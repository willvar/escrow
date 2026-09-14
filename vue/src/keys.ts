/**
 * keys.ts — DEK generation and key-material hygiene for ServerMaster clients.
 *
 * In the ServerMaster custody profile the browser generates the per-object
 * DEK, encrypts the object body locally (wire.ts), and delivers the raw DEK
 * to the application server over TLS. The server wraps the DEK under a
 * subject key (KEK) with escrow.WrapDEK. The browser never sees the KEK or
 * the master key.
 */

export const DEK_SIZE = 32

/** Generate a fresh random 32-byte DEK. */
export function generateDEK(): Uint8Array<ArrayBuffer> {
  const dek = crypto.getRandomValues(new Uint8Array(DEK_SIZE))
  return dek
}

/** Encode raw key material as lowercase hex. */
export function keyToHex(key: Uint8Array): string {
  let out = ''
  for (const byte of key) {
    if (byte > 0xf) {
      out += byte.toString(16)
    } else {
      out += '0' + byte.toString(16)
    }
  }
  return out
}

/** Decode lowercase or uppercase hex key material. */
export function keyFromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('invalid hex key material')
  }
  const raw = new Uint8Array(hex.length / 2)
  for (let i = 0; i < raw.length; i++) {
    raw[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return raw
}

/** Zero key material in place once it is no longer needed. */
export function zeroize(key: Uint8Array): void {
  key.fill(0)
}
