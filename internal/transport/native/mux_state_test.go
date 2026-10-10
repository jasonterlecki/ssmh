package native

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func muxWire(t *testing.T, command byte, stream uint32, data []byte) []byte {
	t.Helper()
	wire, err := encodeMux(muxFrame{command, stream, data})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestMuxStateBidirectionalOwnershipAndClose(t *testing.T) {
	m := newMuxState()
	id, open, err := m.open()
	if err != nil || id != 3 || !bytes.Equal(open, []byte{1, 0, 0, 0, 3, 0, 0, 0}) {
		t.Fatalf("incorrect client SYN: %v", err)
	}
	second, _, err := m.open()
	if err != nil || second != 5 {
		t.Fatal("second stream ID mismatch")
	}
	input := []byte{0, 10, 255}
	wire, err := m.send(id, input)
	if err != nil || !bytes.Equal(wire, []byte{1, 2, 3, 0, 3, 0, 0, 0, 0, 10, 255}) {
		t.Fatalf("binary send mismatch: %v", err)
	}
	input[0] = 9
	if wire[8] != 0 {
		t.Fatal("send aliases input")
	}
	var deliveries []muxDelivery
	consume := func(d muxDelivery) error { deliveries = append(deliveries, d); return nil }
	stream := append(muxWire(t, muxData, second, []byte("second")), muxWire(t, muxData, id, []byte("first"))...)
	stream = append(stream, muxWire(t, muxClose, id, nil)...)
	stream = append(stream, muxWire(t, muxClose, id, nil)...)
	for _, b := range stream {
		if err := m.receive([]byte{b}, consume); err != nil {
			t.Fatal(err)
		}
	}
	want := []muxDelivery{{second, []byte("second"), false}, {id, []byte("first"), false}, {id, nil, true}}
	if !reflect.DeepEqual(deliveries, want) {
		t.Fatal("cross-stream delivery or duplicate EOF")
	}
	// Peer FIN closes its sending direction, not our local sending direction.
	if _, err := m.send(id, []byte("still sending")); err != nil {
		t.Fatal(err)
	}
	fin, err := m.closeStream(id)
	if err != nil || !bytes.Equal(fin, []byte{1, 1, 0, 0, 3, 0, 0, 0}) {
		t.Fatal("local FIN mismatch")
	}
	if _, err := m.closeStream(id); err == nil {
		t.Fatal("emitted second local FIN")
	}
	if _, err := m.send(id, []byte("late")); err == nil {
		t.Fatal("sent after local close")
	}
	late := append(muxWire(t, muxData, id, []byte("discard")), muxWire(t, muxClose, id, nil)...)
	if err := m.receive(late, consume); err != nil || len(deliveries) != 3 {
		t.Fatal("late traffic reached a live stream")
	}
	third, _, _ := m.open()
	if third != 7 {
		t.Fatal("reused a closed identifier")
	}
	for _, active := range []uint32{second, third} {
		if _, err := m.closeStream(active); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.finish(); err != nil {
		t.Fatal(err)
	}
	if m.active() || m.streams != nil || m.decoder.body != nil {
		t.Fatal("finish retained session state")
	}
}

func TestMuxStateLimitsAndIdentifierExhaustion(t *testing.T) {
	m := newMuxState()
	for n := 0; n < muxMaxStreams; n++ {
		id, _, err := m.open()
		if err != nil || id != uint32(3+2*n) {
			t.Fatal("open limit or sequence mismatch")
		}
	}
	last := m.last
	if id, wire, err := m.open(); !errors.Is(err, errMuxCapacity) || id != 0 || wire != nil || m.last != last {
		t.Fatal("capacity failure consumed an ID")
	}
	if _, err := m.closeStream(3); err != nil {
		t.Fatal(err)
	}
	id, _, err := m.open()
	if err != nil || id != last+2 || len(m.streams) != muxMaxStreams {
		t.Fatal("closed slot not reusable with fresh ID")
	}
	if _, err := m.send(id, make([]byte, muxSendSize)); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, {}, make([]byte, muxSendSize+1)} {
		if _, err := m.send(id, data); err == nil {
			t.Fatal("accepted invalid outgoing chunk")
		}
	}
	// Seed the monotonic counter at its final valid value; do not wrap to 1/3.
	m = newMuxState()
	m.last = ^uint32(0) - 2
	id, _, err = m.open()
	if err != nil || id != ^uint32(0) {
		t.Fatal("last valid stream ID refused")
	}
	if _, err := m.closeStream(id); err != nil {
		t.Fatal(err)
	}
	if next, wire, err := m.open(); err == nil || next != 0 || wire != nil {
		t.Fatal("identifier wrapped or reused")
	}
}

func TestMuxStatePeerViolationsAreTerminal(t *testing.T) {
	for name, peer := range map[string]muxFrame{
		"server open": {muxOpen, 2, nil}, "reopen own": {muxOpen, 3, nil},
		"unissued one": {muxData, 1, []byte("synthetic")},
		"even id":      {muxData, 2, nil}, "future id": {muxClose, 5, nil},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMuxState()
			_, _, _ = m.open()
			if err := m.receive(muxWire(t, peer.command, peer.stream, peer.data), func(muxDelivery) error { t.Fatal("unsolicited delivery"); return nil }); err == nil {
				t.Fatal("accepted unowned stream")
			}
			if m.active() || m.streams != nil {
				t.Fatal("peer violation did not shut down")
			}
			if _, _, err := m.open(); err == nil {
				t.Fatal("opened after violation")
			}
		})
	}
	m := newMuxState()
	id, _, _ := m.open()
	if err := m.receive(muxWire(t, muxClose, id, nil), func(muxDelivery) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.receive(muxWire(t, muxData, id, []byte("after EOF")), func(muxDelivery) error { t.Fatal("data after EOF delivered"); return nil }); err == nil || m.active() {
		t.Fatal("accepted post-EOF data")
	}
}

func TestMuxStateCompletionCancellationAndRedaction(t *testing.T) {
	for _, partial := range []bool{false, true} {
		m := newMuxState()
		id, _, _ := m.open()
		if partial {
			wire := muxWire(t, muxData, id, []byte("SYNTHETIC"))
			if err := m.receive(wire[:9], func(muxDelivery) error { t.Fatal("partial frame delivered"); return nil }); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.finish(); err == nil || m.active() || m.decoder.body != nil {
			t.Fatal("open/truncated completion accepted")
		}
	}
	m := newMuxState()
	id, _, _ := m.open()
	marker := "SYNTHETIC-SENSITIVE-DATA"
	err := m.receive(muxWire(t, muxData, id, []byte(marker)), func(muxDelivery) error { return errors.New(marker) })
	if err == nil || strings.Contains(err.Error(), marker) || m.active() {
		t.Fatal("consumer error exposed or nonterminal")
	}
	for _, value := range []any{m, muxDelivery{id, []byte(marker), false}} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), marker) {
			t.Fatal("formatting exposed application data")
		}
	}
	m = newMuxState()
	_, _, _ = m.open()
	m.shutdown()
	m.shutdown()
	if _, err := m.send(3, []byte("x")); err == nil {
		t.Fatal("sent after shutdown")
	}
	if _, err := m.closeStream(3); err == nil {
		t.Fatal("closed after shutdown")
	}
	if err := m.receive(nil, func(muxDelivery) error { return nil }); err == nil {
		t.Fatal("received after shutdown")
	}
	var zero muxState
	if _, _, err := zero.open(); err == nil {
		t.Fatal("zero state opened a stream")
	}
	m = newMuxState()
	if err := m.receive(nil, nil); err == nil || m.active() {
		t.Fatal("missing consumer accepted")
	}
}

func TestMuxStateNoopAndEmptyDataDoNotCreateActivity(t *testing.T) {
	m := newMuxState()
	id, _, _ := m.open()
	wire := append(muxWire(t, muxNoop, 0, nil), muxWire(t, muxData, id, nil)...)
	if err := m.receive(wire, func(muxDelivery) error { t.Fatal("noop/empty data delivered"); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(m.streams) != 1 || m.streams[id] {
		t.Fatal("noop changed ownership")
	}
}

func FuzzMuxState(f *testing.F) {
	f.Add([]byte{1, 2, 1, 0, 3, 0, 0, 0, 255})
	f.Add([]byte{1, 1, 0, 0, 3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxPayload {
			return
		}
		m := newMuxState()
		_, _, _ = m.open()
		_ = m.receive(wire, func(d muxDelivery) error {
			if d.stream != 3 || len(d.data) > muxMaxData {
				t.Fatal("unowned/big delivery")
			}
			return nil
		})
		if len(m.streams) > muxMaxStreams || len(m.decoder.body) > muxMaxData {
			t.Fatal("state bounds exceeded")
		}
		m.shutdown()
		if m.active() || m.decoder.body != nil {
			t.Fatal("shutdown retained state")
		}
	})
}
