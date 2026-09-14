package escrow

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/willvar/dofs"
)

// ServerKeyFromSecret decodes a hex-encoded deployment secret into the
// 32-byte master key. The secret may be longer than 32 raw bytes; only the
// first 32 bytes are used. This mirrors the semantics domus uses today
// (internal/auth/crypto.go ServerKeyFromSecret) so that existing deployed
// secrets keep working unchanged.
func ServerKeyFromSecret(secret string) ([]byte, error) {
	trimmed := strings.TrimSpace(secret)
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: not hex: %w", ErrInvalidSecret, err)
	}
	if len(raw) < dofs.KeySize {
		return nil, fmt.Errorf("%w: need at least %d bytes, got %d", ErrInvalidSecret, dofs.KeySize, len(raw))
	}
	return raw[:dofs.KeySize], nil
}
