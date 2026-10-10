package terminal

import "testing"

func TestEscape(t *testing.T) {
	for _, tc := range []struct {
		input, output string
		closed        bool
	}{
		{"~.", "", true}, {"~~.", "~.", false}, {"a~.", "a~.", false},
		{"a\n~.ignored", "a\n", true}, {"~x\r~.", "~x\r", true},
		{"\x00\x03\x04\xff", "\x00\x03\x04\xff", false}, {"~", "~", false},
	} {
		// Every possible two-chunk boundary must yield the same stream.
		for split := 0; split <= len(tc.input); split++ {
			var e Escape
			a, closed := e.Feed([]byte(tc.input[:split]))
			b, end := e.Feed([]byte(tc.input[split:]))
			out := string(a) + string(b) + string(e.Flush())
			if out != tc.output || (closed || end) != tc.closed {
				t.Fatalf("%q at %d: %q %v", tc.input, split, out, closed || end)
			}
		}
	}
}

func FuzzEscape(f *testing.F) {
	f.Add([]byte("abc\n~~x\n~.after"), uint16(3))
	f.Fuzz(func(t *testing.T, input []byte, split uint16) {
		if len(input) > 65536 {
			return
		}
		n := int(split) % (len(input) + 1)
		var one, two Escape
		all, closed := one.Feed(input)
		all = append(all, one.Flush()...)
		a, c1 := two.Feed(input[:n])
		b, c2 := two.Feed(input[n:])
		out := append(append(a, b...), two.Flush()...)
		if string(all) != string(out) || closed != (c1 || c2) {
			t.Fatal("chunk-dependent escape handling")
		}
	})
}
