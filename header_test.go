package nestedaes

import (
	"bytes"
	"fmt"
	"testing"
)

func compareHeader(h1, h2 *Header) error {
	if h1.Size != h2.Size {
		return fmt.Errorf("expected header Size of %d, got %d", h1.Size, h2.Size)
	}

	/*if bytes.Compare(h1.HeaderTag[:], h2.HeaderTag[:]) != 0 {
		return fmt.Errorf("expected header DataTag to be %x, got %x", h1.HeaderTag, h2.HeaderTag)
	}*/

	if bytes.Compare(h2.BaseIV[:], h2.BaseIV[:]) != 0 {
		return fmt.Errorf("expected header BaseIV to be %x, got %x", h1.BaseIV, h2.BaseIV)
	}

	if bytes.Compare(h1.DataTag[:], h2.DataTag[:]) != 0 {
		return fmt.Errorf("expected header DataTag to be %x, got %x", h1.DataTag, h2.DataTag)
	}

	if len(h1.DEKs) != len(h2.DEKs) {
		return fmt.Errorf("expected header to have %d DEKs, got %d", len(h1.DEKs), len(h2.DEKs))
	}

	/* TODO: compare DEKs */

	return nil
}

func TestHeader(t *testing.T) {
	deks := [][]byte{
		[]byte("11111111111111111111111111111111"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte("22222222222222222222222222222222"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		[]byte("33333333333333333333333333333333"), []byte("cccccccccccccccccccccccccccccccc"),
		[]byte("44444444444444444444444444444444"), []byte("dddddddddddddddddddddddddddddddd"),
		[]byte("55555555555555555555555555555555"), []byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
	}

	iv := []byte("abcdefghijklmnop")
	tag := []byte("qrstuvwxyzABCDEF")
	h, err := NewHeader(iv, tag, deks[0])
	if err != nil {
		t.Fatalf("NewHeader failed: %v", err)
	}
	for _, dek := range deks[1:] {
		h.AddDEK(dek)
	}

	if len(deks) != len(h.DEKs) {
		t.Fatalf("expected %d DEKs, got %d", len(deks), len(h.DEKs))
	}

	kek := []byte("66666666666666666666666666666666")
	hData, err := h.Marshal(kek)
	if err != nil {
		t.Fatalf("h.Marshal failed: %v", err)
	}

	if h.Size != uint32(len(hData)) {
		t.Fatalf("expected marshalled header to have size of %d bytes, got %d", h.Size, len(hData))
	}

	h2, err := UnmarshalHeader(kek, hData)
	if err != nil {
		t.Fatalf("h.Unmarshal failed: %v", err)
	}

	if err := compareHeader(h, h2); err != nil {
		t.Fatalf("h.Unmarshal: %v", err)
	}
}
