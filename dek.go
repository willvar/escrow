package escrow

import (
	"fmt"

	"github.com/willvar/dofs"
)

// DEKSize is the size of a Data Encryption Key in bytes (AES-256).
const DEKSize = dofs.KeySize

// GenerateDEK creates a fresh 32-byte object DEK for the DOFS v1 object
// format. In the ServerMaster profile the browser typically generates the
// DEK and sends it to the server over TLS at upload init; the server wraps
// it under a subject key with WrapDEK before persistence.
func GenerateDEK() ([]byte, error) {
	return dofs.GenerateKey()
}

// WrapDEK wraps a DEK under a subject key (KEK) for persistence.
// Output format: [12-byte nonce | ciphertext + 16-byte tag] = 60 bytes for a
// 32-byte DEK.
func WrapDEK(subjectKey, dek []byte) ([]byte, error) {
	if len(subjectKey) != dofs.KeySize {
		return nil, fmt.Errorf("%w: subject key got %d bytes", ErrInvalidKey, len(subjectKey))
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("%w: DEK got %d bytes", ErrInvalidKey, len(dek))
	}
	wrapped, err := dofs.WrapKey(subjectKey, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}
	return wrapped, nil
}

// UnwrapDEK recovers a DEK from its envelope using the subject key (KEK).
// The caller is responsible for clearing the returned DEK.
func UnwrapDEK(subjectKey, wrapped []byte) ([]byte, error) {
	if len(subjectKey) != dofs.KeySize {
		return nil, fmt.Errorf("%w: subject key got %d bytes", ErrInvalidKey, len(subjectKey))
	}
	if len(wrapped) < dofs.NonceSize+dofs.TagSize+DEKSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrWrappedKeyShort, len(wrapped))
	}
	dek, err := dofs.UnwrapKey(subjectKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}
	if len(dek) != DEKSize {
		dofs.Clear(dek)
		return nil, ErrInvalidEnvelope
	}
	return dek, nil
}

// Zero clears key material in place as soon as it is no longer needed. It is
// a thin alias over dofs.Clear.
func Zero(key []byte) {
	dofs.Clear(key)
}
