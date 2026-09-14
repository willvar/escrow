// Command golden regenerates testdata/golden.json — the shared
// cross-implementation fixture that Go tests and the frontend (vue/) tests
// both consume. Run from the repository root:
//
//	go run ./scripts/golden
//
// The generator is deterministic in its inputs; wrap envelopes and object
// ciphertext use random nonces, so regenerated fixtures differ byte-wise
// from run to run while remaining valid decrypt-direction vectors.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/willvar/dofs"
)

type wrapVector struct {
	KEK         string `json:"kek_hex"`
	DEK         string `json:"dek_hex"`
	Wrapped     string `json:"wrapped_hex"`
	Description string `json:"description"`
}

type wireVector struct {
	Key         string `json:"key_hex"`
	ChunkSize   int    `json:"chunk_size"`
	Plaintext   string `json:"plaintext_hex"`
	Ciphertext  string `json:"ciphertext_hex"`
	Description string `json:"description"`
}

type golden struct {
	Wrap []wrapVector `json:"wrap"`
	Wire []wireVector `json:"wire"`
}

func main() {
	fixture := golden{}

	for _, size := range []int{0, 1, 100, dofs.DefaultChunkSize, dofs.DefaultChunkSize + 1, 3 * dofs.DefaultChunkSize, 3*dofs.DefaultChunkSize + 7} {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(i%251 + 1)
		}
		key, err := dofs.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		defer dofs.Clear(key)

		var ciphertext bytes.Buffer
		if err := dofs.EncryptStream(key, bytes.NewReader(plaintext), &ciphertext); err != nil {
			log.Fatal(err)
		}
		fixture.Wire = append(fixture.Wire, wireVector{
			Key:         hex.EncodeToString(key),
			ChunkSize:   dofs.DefaultChunkSize,
			Plaintext:   hex.EncodeToString(plaintext),
			Ciphertext:  hex.EncodeToString(ciphertext.Bytes()),
			Description: fmt.Sprintf("object of %d plaintext bytes", size),
		})
	}

	for i := 0; i < 4; i++ {
		kek, err := dofs.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		defer dofs.Clear(kek)
		dek, err := dofs.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		defer dofs.Clear(dek)
		wrapped, err := dofs.WrapKey(kek, dek)
		if err != nil {
			log.Fatal(err)
		}
		fixture.Wrap = append(fixture.Wrap, wrapVector{
			KEK:         hex.EncodeToString(kek),
			DEK:         hex.EncodeToString(dek),
			Wrapped:     hex.EncodeToString(wrapped),
			Description: fmt.Sprintf("DEK envelope #%d", i+1),
		})
	}

	out, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	out = append(out, '\n')

	target := filepath.Join("testdata", "golden.json")
	if err := os.WriteFile(target, out, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s (%d wire vectors, %d wrap vectors)\n", target, len(fixture.Wire), len(fixture.Wrap))
}
