package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestControlJSONStructure(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"unknown":{"one":1},"array":[null,true,1.25,"text",{}]}`,
		`{"one":{"same":1},"two":{"same":2}}`,
		`{"number":1e9999}`, // Unknown numbers must not be coerced to float64.
		`{"cols":80,"rows":24}`,
	} {
		var result json.RawMessage
		if err := decodeControlJSON([]byte(data), &result); err != nil || !bytes.Equal(result, []byte(data)) {
			t.Fatalf("valid control JSON rejected: %v", err)
		}
	}
	for _, data := range []string{
		``, `null`, `[]`, `"object"`, `{} {}`, `{"x":1,}`, `{"x":`,
		`{"x":1,"x":2}`, `{"x":1,"X":2}`, `{"x":1,"\u0078":2}`,
		`{"outer":[{"x":1,"X":2}]}`, `{"x":1,"X":{}}`,
		`{"x":"` + string([]byte{0xff}) + `"}`,
		`{"` + strings.Repeat("k", 257) + `":0}`,
		`{"x":"` + strings.Repeat("v", 65536) + `"}`,
	} {
		var result json.RawMessage
		err := decodeControlJSON([]byte(data), &result)
		if err == nil || result != nil || err.Error() != "invalid or ambiguous SSM control JSON" {
			t.Fatal("invalid JSON accepted, decoded, or disclosed in error")
		}
	}
}

func TestControlJSONBounds(t *testing.T) {
	object := func(count int) string {
		fields := make([]string, count)
		for i := range fields {
			fields[i] = fmt.Sprintf(`"field%d":0`, i)
		}
		return "{" + strings.Join(fields, ",") + "}"
	}
	for _, tc := range []struct {
		data string
		good bool
	}{
		{object(64), true}, {object(65), false},
		{`{"x":` + strings.Repeat("[", 15) + `0` + strings.Repeat("]", 15) + `}`, true},
		{`{"x":` + strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16) + `}`, false},
		{`{"` + strings.Repeat("k", 256) + `":0}`, true},
	} {
		var result json.RawMessage
		if err := decodeControlJSON([]byte(tc.data), &result); (err == nil) != tc.good {
			t.Fatal("incorrect control JSON structural limit")
		}
	}
	// Exact byte limit, including insignificant whitespace.
	for _, size := range []int{65536, 65537} {
		data := append([]byte(`{}`), bytes.Repeat([]byte(" "), size-2)...)
		var result json.RawMessage
		if err := decodeControlJSON(data, &result); (err == nil) != (size == 65536) {
			t.Fatal("incorrect control JSON byte limit")
		}
	}
}

func TestAmbiguousProtocolHandshakeFailsClosed(t *testing.T) {
	for _, payload := range []string{
		`{"RequestedClientActions":[{"ActionType":"KMSEncryption"}],"requestedclientactions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}}]}`,
		`{"RequestedClientActions":[{"ActionType":"KMSEncryption","ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream"}}]}`,
		`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Port","sessiontype":"Standard_Stream"}}]}`,
		`{"RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream","Properties":{"type":"secret-marker","type":"ignored"}}}]}`,
	} {
		p := protocol(t)
		event, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, []byte(payload)), time.Now())
		if err == nil || p.Ready() || event.Ready || len(event.Output) != 0 || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("ambiguous security decision accepted or disclosed")
		}
		if _, err := p.Input(Output, []byte("input"), time.Now()); err == nil {
			t.Fatal("failed handshake allowed user input")
		}
		if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, handshake), time.Now()); err == nil {
			t.Fatal("failed protocol recovered after replacement handshake")
		}
	}
	for _, payload := range []string{`null`, `{"CustomerMessage":"secret-marker","customermessage":"ready"}`} {
		p := protocol(t)
		if _, err := p.Process(frame(t, outputStream, HandshakeRequest, 0, handshake), time.Now()); err != nil {
			t.Fatal(err)
		}
		event, err := p.Process(frame(t, outputStream, HandshakeComplete, 1, []byte(payload)), time.Now())
		if err == nil || p.Ready() || event.Ready || event.CustomerMessage != "" || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("ambiguous completion established readiness or disclosed data")
		}
	}
}

func TestAmbiguousAcknowledgementAndCloseFailClosed(t *testing.T) {
	p := ready(t)
	m, err := p.Input(Output, []byte("input"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(fmt.Sprintf(`{"AcknowledgedMessageType":"input_stream_data","AcknowledgedMessageId":"wrong-id","acknowledgedmessageid":%q,"AcknowledgedMessageSequenceNumber":%d,"IsSequentialMessage":true}`, m.ID.String(), m.Sequence))
	if _, err := p.Process(frame(t, acknowledge, 0, 0, data), time.Now()); err == nil || p.Ready() {
		t.Fatal("ambiguous acknowledgement accepted")
	}
	if _, ok := p.outgoing[m.Sequence]; !ok {
		t.Fatal("failed acknowledgement removed pending input")
	}
	for _, data := range []string{
		fmt.Sprintf(`{"SessionId":"unowned","sessionid":%q}`, ownedID),
		fmt.Sprintf(`{"SessionId":%q,"Output":"secret-marker","output":""}`, ownedID),
	} {
		p = ready(t)
		event, err := p.Process(frame(t, channelClosed, 0, 0, []byte(data)), time.Now())
		if err == nil || event.Closed || p.Ready() || p.closed || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("ambiguous close produced normal EOF or disclosed data")
		}
	}
	p = ready(t)
	if _, err := p.Input(Size, []byte(`{"cols":0,"Cols":80,"rows":24}`), time.Now()); err == nil {
		t.Fatal("ambiguous dimensions accepted")
	}
	// A local invalid resize does not fail the remote state machine.
	if _, err := p.Input(Size, []byte(`{"cols":80,"rows":24}`), time.Now()); err != nil {
		t.Fatal("valid dimensions rejected after local validation failure")
	}
}

func FuzzControlJSON(f *testing.F) {
	for _, data := range [][]byte{handshake, []byte(`{}`), []byte(`{"x":1,"X":2}`), []byte(`{"x":[null,{"a":true}]}`)} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var result json.RawMessage
		if err := decodeControlJSON(data, &result); err == nil {
			if !json.Valid(result) || !bytes.Equal(data, result) {
				// RawMessage strips surrounding whitespace, not interior bytes.
				if !json.Valid(result) || !bytes.Equal(bytes.TrimSpace(data), result) {
					t.Fatal("accepted JSON changed during decoding")
				}
			}
		}
	})
}
