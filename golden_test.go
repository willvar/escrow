package escrow

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/willvar/dofs"
)

type goldenFixture struct {
	Wrap []struct {
		KEK         string `json:"kek_hex"`
		DEK         string `json:"dek_hex"`
		Wrapped     string `json:"wrapped_hex"`
		Description string `json:"description"`
	} `json:"wrap"`
	Wire []struct {
		Key         string `json:"key_hex"`
		ChunkSize   int    `json:"chunk_size"`
		Plaintext   string `json:"plaintext_hex"`
		Ciphertext  string `json:"ciphertext_hex"`
		Description string `json:"description"`
	} `json:"wire"`
}

func loadGolden(t *testing.T) goldenFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	if len(fixture.Wrap) == 0 || len(fixture.Wire) == 0 {
		t.Fatal("golden fixture is empty")
	}
	return fixture
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return raw
}

func TestUnwrapDEK_GoldenVectors(t *testing.T) {
	fixture := loadGolden(t)
	for _, vector := range fixture.Wrap {
		t.Run(vector.Description, func(t *testing.T) {
			kek := mustDecode(t, vector.KEK)
			defer Zero(kek)
			wrapped := mustDecode(t, vector.Wrapped)
			want := mustDecode(t, vector.DEK)

			dek, err := UnwrapDEK(kek, wrapped)
			if err != nil {
				t.Fatalf("UnwrapDEK: %v", err)
			}
			defer Zero(dek)
			if !bytes.Equal(dek, want) {
				t.Fatal("unwrapped DEK does not match fixture")
			}

			rewrapped, err := WrapDEK(kek, dek)
			if err != nil {
				t.Fatalf("WrapDEK: %v", err)
			}
			roundtrip, err := UnwrapDEK(kek, rewrapped)
			if err != nil {
				t.Fatalf("unwrap rewrapped: %v", err)
			}
			defer Zero(roundtrip)
			if !bytes.Equal(roundtrip, want) {
				t.Fatal("wrap/unwrap roundtrip mismatch")
			}
		})
	}
}

func TestWire_GoldenVectors(t *testing.T) {
	fixture := loadGolden(t)
	for _, vector := range fixture.Wire {
		t.Run(vector.Description, func(t *testing.T) {
			key := mustDecode(t, vector.Key)
			defer Zero(key)
			ciphertext := mustDecode(t, vector.Ciphertext)
			want := mustDecode(t, vector.Plaintext)

			var plaintext bytes.Buffer
			if err := dofs.DecryptStream(key, bytes.NewReader(ciphertext), &plaintext); err != nil {
				t.Fatalf("dofs.DecryptStream: %v", err)
			}
			if !bytes.Equal(plaintext.Bytes(), want) {
				t.Fatal("decrypted plaintext does not match fixture")
			}
		})
	}
}
