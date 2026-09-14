package escrow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/willvar/dofs"
)

// ServerMaster must satisfy the DOFS substrate key-provider interface so it
// can back a metadata store directly (namespace-key style applications).
var _ dofs.KeyProvider = (*ServerMaster)(nil)

func TestServerMaster_NamespaceKeys(t *testing.T) {
	m, err := NewServerMaster(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	subjectKey, err := m.GenerateSubjectKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(subjectKey)
	wrappedKEK, err := m.WrapSubjectKey(subjectKey)
	if err != nil {
		t.Fatal(err)
	}

	namespace := dofs.Namespace{ID: "test-ns", WrappedKEK: wrappedKEK}
	kek, err := m.UnwrapNamespaceKey(context.Background(), namespace)
	if err != nil {
		t.Fatalf("UnwrapNamespaceKey: %v", err)
	}
	defer Zero(kek)
	if !bytes.Equal(kek, subjectKey) {
		t.Fatal("namespace KEK mismatch")
	}

	m.Close()
	if _, err := m.UnwrapNamespaceKey(context.Background(), namespace); err == nil {
		t.Fatal("expected error after Close")
	}
}

func TestServerKeyFromSecret(t *testing.T) {
	t.Run("valid 32-byte secret", func(t *testing.T) {
		secret := strings.Repeat("ab", 32)
		key, err := ServerKeyFromSecret(secret)
		if err != nil {
			t.Fatalf("ServerKeyFromSecret: %v", err)
		}
		defer Zero(key)
		if len(key) != 32 {
			t.Fatalf("expected 32-byte key, got %d", len(key))
		}
	})

	t.Run("longer secret uses first 32 bytes", func(t *testing.T) {
		secret := strings.Repeat("cd", 40)
		key, err := ServerKeyFromSecret(secret)
		if err != nil {
			t.Fatalf("ServerKeyFromSecret: %v", err)
		}
		defer Zero(key)
		if len(key) != 32 {
			t.Fatalf("expected 32-byte key, got %d", len(key))
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := ServerKeyFromSecret("0123"); err == nil {
			t.Fatal("expected error for short secret")
		}
	})

	t.Run("not hex", func(t *testing.T) {
		if _, err := ServerKeyFromSecret("nothex!"); err == nil {
			t.Fatal("expected error for non-hex secret")
		}
	})
}

func TestServerMaster_Lifecycle(t *testing.T) {
	master, err := ServerKeyFromSecret(strings.Repeat("ef", 32))
	if err != nil {
		t.Fatalf("ServerKeyFromSecret: %v", err)
	}
	m, err := NewServerMaster(master)
	if err != nil {
		t.Fatalf("NewServerMaster: %v", err)
	}

	subjectKey, err := m.GenerateSubjectKey()
	if err != nil {
		t.Fatalf("GenerateSubjectKey: %v", err)
	}
	defer Zero(subjectKey)

	wrapped, err := m.WrapSubjectKey(subjectKey)
	if err != nil {
		t.Fatalf("WrapSubjectKey: %v", err)
	}
	if len(wrapped) != 12+16+32 {
		t.Fatalf("unexpected envelope size: %d", len(wrapped))
	}

	recovered, err := m.UnwrapSubjectKey(wrapped)
	if err != nil {
		t.Fatalf("UnwrapSubjectKey: %v", err)
	}
	defer Zero(recovered)
	if !bytes.Equal(recovered, subjectKey) {
		t.Fatal("recovered subject key mismatch")
	}

	m.Close()

	if _, err := m.UnwrapSubjectKey(wrapped); err == nil {
		t.Fatal("expected error after Close")
	}
	if _, err := m.WrapSubjectKey(subjectKey); err == nil {
		t.Fatal("expected error after Close")
	}
}

func TestServerMaster_WrongMaster(t *testing.T) {
	m1, err := NewServerMaster(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m1.Close()
	m2, err := NewServerMaster(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()

	subjectKey, err := m1.GenerateSubjectKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(subjectKey)
	wrapped, err := m1.WrapSubjectKey(subjectKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m2.UnwrapSubjectKey(wrapped); err == nil {
		t.Fatal("unwrap with wrong master key must fail")
	}
}

func TestServerMaster_InputValidation(t *testing.T) {
	if _, err := NewServerMaster(bytes.Repeat([]byte{0x33}, 31)); err == nil {
		t.Fatal("expected error for short master key")
	}

	m, err := NewServerMaster(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if _, err := m.WrapSubjectKey(bytes.Repeat([]byte{0x55}, 31)); err == nil {
		t.Fatal("expected error for short subject key")
	}
	if _, err := m.UnwrapSubjectKey(bytes.Repeat([]byte{0x66}, 10)); err == nil {
		t.Fatal("expected error for short envelope")
	}
}

func TestDEK_WrapUnwrapRoundtrip(t *testing.T) {
	subjectKey, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(subjectKey)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(dek)

	wrapped, err := WrapDEK(subjectKey, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(wrapped) != 60 {
		t.Fatalf("expected 60-byte envelope, got %d", len(wrapped))
	}

	recovered, err := UnwrapDEK(subjectKey, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer Zero(recovered)
	if !bytes.Equal(recovered, dek) {
		t.Fatal("recovered DEK mismatch")
	}
}

func TestDEK_UnwrapFailures(t *testing.T) {
	subjectKey, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(subjectKey)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(dek)

	wrapped, err := WrapDEK(subjectKey, dek)
	if err != nil {
		t.Fatal(err)
	}

	wrongKEK, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(wrongKEK)

	if _, err := UnwrapDEK(wrongKEK, wrapped); err == nil {
		t.Fatal("unwrap with wrong KEK must fail")
	}

	tampered := append([]byte(nil), wrapped...)
	tampered[13] ^= 0xff
	if _, err := UnwrapDEK(subjectKey, tampered); err == nil {
		t.Fatal("unwrap of tampered envelope must fail")
	}
}
