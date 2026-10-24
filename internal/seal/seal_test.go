package seal

import (
	"bytes"
	"testing"
	"time"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, err := New(bytes.Repeat([]byte{1}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Seal("a", map[string]string{"k": "v"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := s.Open("a", v, &got); err != nil || got["k"] != "v" {
		t.Fatalf("open: %v %v", err, got)
	}
	if err := s.Open("b", v, &got); err == nil {
		t.Fatal("value opened under another cookie name")
	}
	b := []byte(v)
	b[len(b)-3] ^= 1
	if err := s.Open("a", string(b), &got); err == nil {
		t.Fatal("tampered value opened")
	}
	other, _ := New(bytes.Repeat([]byte{2}, 32), nil)
	if err := other.Open("a", v, &got); err == nil {
		t.Fatal("opened with another key")
	}
	now = now.Add(2 * time.Minute)
	if err := s.Open("a", v, &got); err == nil {
		t.Fatal("expired value opened")
	}
}

func TestDeriveKey(t *testing.T) {
	m := bytes.Repeat([]byte{3}, 32)
	if bytes.Equal(DeriveKey(m, "a"), DeriveKey(m, "b")) || len(DeriveKey(m, "a")) != 32 {
		t.Fatal("derived keys not independent")
	}
}
