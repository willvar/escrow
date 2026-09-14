// Package escrow provides product-neutral key custody for DOFS applications.
//
// DOFS defines one wire format: objects are chunked AES-256-GCM ciphertext
// encrypted with a per-object 32-byte DEK, and every DEK lives only as a
// wrapped envelope. The custody axis is about one question: who is able to
// unwrap a DEK.
//
// Escrow is explicitly organized around that axis so that an application
// cannot drift into a custody model by accident:
//
//   - ServerMaster: the deployment holds a 32-byte master key. Subject keys
//     (a user KEK, a namespace KEK, ...) are generated and wrapped under the
//     master key; per-object DEKs are wrapped under a subject key. The
//     server can unwrap anything at any time. This is "encrypted at rest,
//     server-custodial".
//   - ClientHeld: reserved, NOT implemented here. In a true end-to-end
//     profile the DEK envelope is created and opened only by the client and
//     the server stores opaque bytes it cannot open. It will land as a
//     separate, separately documented implementation; it must not grow out
//     of ServerMaster implicitly.
//
// The package delegates all cryptographic primitives to
// github.com/willvar/dofs (WrapKey/UnwrapKey/GenerateKey/Clear) so that the
// wire and envelope formats have exactly one source of truth. Escrow adds
// the vocabulary and the ownership discipline, not new cryptography.
//
// Escrow also ships a frontend implementation (vue/) with the same DOFS v1
// object codec and DEK helpers for browser clients. Go tests and frontend
// tests share one golden fixture file (testdata/golden.json) to keep both
// implementations byte-compatible.
package escrow
