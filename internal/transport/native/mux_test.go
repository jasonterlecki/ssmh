package native

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestMuxWireAndFragmentation(t *testing.T) {
	// Independent literal fixture: v1, PSH=2, 3-byte little-endian length,
	// stream ID 0x01020305 little endian, and binary application bytes.
	fixture := []byte{1, 2, 3, 0, 5, 3, 2, 1, 0, '\n', 255}
	f := muxFrame{muxData, 0x01020305, []byte{0, '\n', 255}}
	raw, err := encodeMux(f)
	if err != nil || !bytes.Equal(raw, fixture) {
		t.Fatalf("wire encoding mismatch: %v", err)
	}
	frames := []muxFrame{{muxOpen, 3, nil}, f, {muxNoop, 0, nil}, {muxData, 3, nil}, {muxClose, 3, nil}}
	var stream []byte
	for _, frame := range frames {
		wire, e := encodeMux(frame)
		if e != nil {
			t.Fatal(e)
		}
		stream = append(stream, wire...)
	}
	for split := 0; split <= len(stream); split++ {
		var decoder muxDecoder
		var got []muxFrame
		consume := func(frame muxFrame) error { got = append(got, frame); return nil }
		if e := decoder.feed(stream[:split], consume); e != nil {
			t.Fatal(e)
		}
		if e := decoder.feed(stream[split:], consume); e != nil {
			t.Fatal(e)
		}
		if e := decoder.finish(); e != nil || !reflect.DeepEqual(got, frames) {
			t.Fatalf("split %d: incomplete or mismatched frames: %v", split, e)
		}
	}
	var decoder muxDecoder
	var got []muxFrame
	for _, b := range stream {
		if e := decoder.feed([]byte{b}, func(frame muxFrame) error { got = append(got, frame); return nil }); e != nil {
			t.Fatal(e)
		}
	}
	if e := decoder.finish(); e != nil || !reflect.DeepEqual(got, frames) {
		t.Fatalf("one-byte feed mismatch: %v", e)
	}
}

func TestMuxBoundsAndOwnership(t *testing.T) {
	data := bytes.Repeat([]byte{0xa5}, muxMaxData)
	raw, err := encodeMux(muxFrame{muxData, 3, data})
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 0
	if raw[muxHeaderSize] != 0xa5 {
		t.Fatal("encoder retained input alias")
	}
	var decoder muxDecoder
	if err := decoder.feed(raw[:muxHeaderSize], func(muxFrame) error { t.Fatal("premature delivery"); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(decoder.body) != muxMaxData || decoder.filled != 0 {
		t.Fatal("partial-body bound mismatch")
	}
	var delivered muxFrame
	if err := decoder.feed(raw[muxHeaderSize:], func(f muxFrame) error { delivered = f; return nil }); err != nil {
		t.Fatal(err)
	}
	raw[muxHeaderSize] = 0
	if delivered.data[0] != 0xa5 || decoder.body != nil || decoder.used != 0 {
		t.Fatal("decoder aliased input or retained delivered data")
	}
	next, _ := encodeMux(muxFrame{muxData, 5, []byte("next")})
	if err := decoder.feed(next, func(muxFrame) error { return nil }); err != nil || delivered.data[0] != 0xa5 {
		t.Fatal("subsequent frame overwrote delivered data")
	}
	if _, err := encodeMux(muxFrame{muxData, 3, make([]byte, muxMaxData+1)}); err == nil {
		t.Fatal("accepted oversized body")
	}
	if err := decoder.finish(); err != nil {
		t.Fatal(err)
	}
	if err := decoder.feed(next, func(muxFrame) error { return nil }); err == nil {
		t.Fatal("reused finished decoder")
	}
}

func TestMuxRejectsMalformedAndTruncatedFrames(t *testing.T) {
	cases := map[string][]byte{
		"wrong version":   {2, 2, 0, 0, 3, 0, 0, 0},
		"unknown command": {1, 255, 0, 0, 3, 0, 0, 0},
		"v2 update":       {1, 4, 8, 0, 3, 0, 0, 0},
		"open data":       {1, 0, 1, 0, 3, 0, 0, 0},
		"close data":      {1, 1, 1, 0, 3, 0, 0, 0},
		"noop data":       {1, 3, 1, 0, 0, 0, 0, 0},
		"noop stream":     {1, 3, 0, 0, 3, 0, 0, 0},
		"zero open":       {1, 0, 0, 0, 0, 0, 0, 0},
		"zero close":      {1, 1, 0, 0, 0, 0, 0, 0},
		"zero data":       {1, 2, 0, 0, 0, 0, 0, 0},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			var d muxDecoder
			if err := d.feed(wire, func(muxFrame) error { t.Fatal("delivered malformed frame"); return nil }); err == nil {
				t.Fatal("accepted malformed header")
			}
			if d.body != nil || !d.failed || d.used != 0 {
				t.Fatal("failure retained partial data or allowed reuse")
			}
			if err := d.feed(nil, func(muxFrame) error { return nil }); err == nil {
				t.Fatal("reused failed decoder")
			}
		})
	}
	raw, _ := encodeMux(muxFrame{muxData, 3, []byte("SYNTHETIC-DATA")})
	for n := 1; n < len(raw); n++ {
		var d muxDecoder
		if err := d.feed(raw[:n], func(muxFrame) error { t.Fatal("delivered truncated frame"); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := d.finish(); err == nil || d.body != nil || !d.failed {
			t.Fatalf("truncation %d not refused/released", n)
		}
	}
}

func TestMuxErrorsAndFormattingDoNotExposeData(t *testing.T) {
	marker := "SYNTHETIC-SENSITIVE-PAYLOAD"
	raw, _ := encodeMux(muxFrame{muxData, 3, []byte(marker)})
	var d muxDecoder
	err := d.feed(raw, func(muxFrame) error { return errors.New(marker) })
	if err == nil || strings.Contains(err.Error(), marker) || !d.failed {
		t.Fatal("consumer failure not redacted/final")
	}
	for _, value := range []any{muxFrame{muxData, 3, []byte(marker)}, &muxDecoder{body: []byte(marker)}} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), marker) {
			t.Fatal("formatting exposed data")
		}
	}
	for _, invalid := range []struct {
		data    []byte
		consume func(muxFrame) error
	}{
		{nil, nil}, {make([]byte, MaxPayload+1), func(muxFrame) error { return nil }},
	} {
		var decoder muxDecoder
		if err := decoder.feed(invalid.data, invalid.consume); err == nil || !decoder.failed {
			t.Fatal("accepted invalid feed")
		}
	}
}

func TestMuxValidPrefixThenFailureAndControlFlood(t *testing.T) {
	good, _ := encodeMux(muxFrame{muxOpen, 3, nil})
	bad := []byte{1, 255, 0, 0, 3, 0, 0, 0}
	var decoder muxDecoder
	deliveries := 0
	err := decoder.feed(append(good, bad...), func(muxFrame) error { deliveries++; return nil })
	if err == nil || deliveries != 1 || !decoder.failed {
		t.Fatal("valid-prefix delivery or terminal failure semantics changed")
	}
	noop, _ := encodeMux(muxFrame{muxNoop, 0, nil})
	flood := bytes.Repeat(noop, MaxPayload/muxHeaderSize)
	decoder = muxDecoder{}
	deliveries = 0
	if err := decoder.feed(flood, func(f muxFrame) error {
		if f.command != muxNoop || f.stream != 0 || len(f.data) != 0 {
			t.Fatal("invalid control delivered")
		}
		deliveries++
		return nil
	}); err != nil || deliveries != MaxPayload/muxHeaderSize || decoder.body != nil || decoder.used != 0 {
		t.Fatal("maximum feed was not consumed with bounded retained state")
	}
	for _, invalid := range []muxFrame{
		{255, 3, nil}, {muxOpen, 0, nil}, {muxClose, 0, nil},
		{muxData, 0, nil}, {muxNoop, 3, nil}, {muxClose, 3, []byte("data")},
	} {
		if raw, err := encodeMux(invalid); err == nil || raw != nil {
			t.Fatal("encoded invalid control or stream identity")
		}
	}
}

func FuzzMuxDecoder(f *testing.F) {
	f.Add([]byte{1, 2, 3, 0, 3, 0, 0, 0, 0, 10, 255}, uint8(4))
	f.Add([]byte{1, 0, 0, 0, 3, 0, 0, 0}, uint8(1))
	f.Add([]byte{2, 255}, uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, split uint8) {
		if len(raw) > MaxPayload {
			return
		}
		var d muxDecoder
		consume := func(frame muxFrame) error {
			wire, err := encodeMux(frame)
			if err != nil || len(wire) != muxHeaderSize+len(frame.data) {
				t.Fatal("invalid frame delivered")
			}
			return nil
		}
		cut := min(int(split), len(raw))
		if err := d.feed(raw[:cut], consume); err == nil {
			_ = d.feed(raw[cut:], consume)
		}
		if len(d.body) > muxMaxData || d.used > muxHeaderSize {
			t.Fatal("decoder bounds exceeded")
		}
		_ = d.finish()
	})
}
