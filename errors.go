package escrow

import "errors"

var (
	// ErrInvalidKey is returned when a key material argument is not exactly
	// 32 bytes (the DOFS KeySize for AES-256 keys).
	ErrInvalidKey = errors.New("key must be 32 bytes")

	// ErrInvalidSecret is returned when a deployment secret cannot be decoded
	// into a 32-byte master key.
	ErrInvalidSecret = errors.New("invalid encryption secret")

	// ErrWrappedKeyShort means a wrapped key envelope is too short to carry
	// a 12-byte nonce plus a GCM tag around a 32-byte key.
	ErrWrappedKeyShort = errors.New("wrapped key envelope is too short")

	// ErrClosed is returned when a ServerMaster has been closed and its
	// master key material has been cleared.
	ErrClosed = errors.New("custody is closed")

	// ErrInvalidEnvelope means the plaintext key recovered from an envelope
	// failed length validation after unwrapping.
	ErrInvalidEnvelope = errors.New("unwrapped key has invalid length")
)
