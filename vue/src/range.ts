import { WIRE_CHUNK_SIZE, WIRE_HEADER_SIZE, WIRE_NONCE_SIZE, WIRE_TAG_SIZE, WIRE_VERSION, uint64BE } from './wire'

/** Size on the wire of one encrypted chunk: nonce + plaintext chunk + GCM tag. */
export function encryptedChunkSize(chunkSize = WIRE_CHUNK_SIZE): number {
  return WIRE_NONCE_SIZE + chunkSize + WIRE_TAG_SIZE
}

export interface EncRange {
  /** Index of the first encrypted chunk containing plaintext offset pStart. */
  startChunk: number
  /** Index of the last encrypted chunk containing plaintext offset pEnd. */
  endChunk: number
  /** Ciphertext byte offset of startChunk (inclusive, after the 5-byte header). */
  encStart: number
  /** Ciphertext byte offset of the end of endChunk (inclusive). */
  encEnd: number
}

/**
 * Map a plaintext byte range [pStart, pEnd] to the encrypted byte range that
 * covers it, including the wire header offset. Chunks authenticate their
 * ordinal, so the caller must decrypt starting at startChunk with that
 * ordinal as AAD.
 */
export function plaintextRangeToEncRange(pStart: number, pEnd: number, chunkSize: number): EncRange {
  if (pStart < 0 || pEnd < pStart || chunkSize <= 0) {
    throw new Error('invalid plaintext range')
  }
  const encChunk = encryptedChunkSize(chunkSize)
  const startChunk = Math.floor(pStart / chunkSize)
  const endChunk = Math.floor(pEnd / chunkSize)
  return {
    startChunk,
    endChunk,
    encStart: WIRE_HEADER_SIZE + startChunk * encChunk,
    encEnd: WIRE_HEADER_SIZE + (endChunk + 1) * encChunk - 1,
  }
}

/**
 * Validate a DOFS v1 wire header ([1B version][4B chunk size big-endian]) and
 * return the chunk size. Throws on unsupported versions or invalid sizes.
 * When expectedChunkSize is given, a mismatch throws.
 */
export function readWireHeader(header: Uint8Array, expectedChunkSize?: number): number {
  if (header.length < WIRE_HEADER_SIZE) {
    throw new Error('wire header is too short')
  }
  if (header[0] !== WIRE_VERSION) {
    throw new Error(`unsupported wire version ${header[0]}`)
  }
  const chunkSize = new DataView(header.buffer, header.byteOffset).getUint32(1, false)
  if (chunkSize <= 0 || chunkSize > 16 * 1024 * 1024) {
    throw new Error(`invalid encrypted chunk size ${chunkSize}`)
  }
  if (expectedChunkSize !== undefined && chunkSize !== expectedChunkSize) {
    throw new Error(`unexpected chunk size: expected ${expectedChunkSize}, got ${chunkSize}`)
  }
  return chunkSize
}

/**
 * Decrypt one encrypted chunk ([12-byte nonce | ciphertext + tag], final
 * chunk may be short) with its ordinal as AAD. The key may be a CryptoKey
 * (service-worker pattern) or raw key bytes.
 */
export async function decryptWireChunk(
  key: CryptoKey | Uint8Array,
  segment: Uint8Array,
  index: number,
): Promise<Uint8Array> {
  const cryptoKey = key instanceof CryptoKey ? key : await importKey(key, 'decrypt')
  if (segment.length < WIRE_NONCE_SIZE + WIRE_TAG_SIZE) {
    throw new Error(`encrypted chunk ${index} is too short`)
  }
  const nonce = segment.subarray(0, WIRE_NONCE_SIZE)
  const ciphertext = segment.subarray(WIRE_NONCE_SIZE)
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce), additionalData: uint64BE(index) },
    cryptoKey,
    toArrayBuffer(ciphertext),
  )
  return new Uint8Array(plaintext)
}

/**
 * Unwrap a DEK envelope using a KEK: input is [12-byte nonce | ciphertext +
 * tag] of a 32-byte DEK, matching escrow.WrapDEK on the Go side. No AAD is
 * bound to the envelope. Returns the raw 32-byte DEK; callers are responsible
 * for zeroizing it when done.
 */
export async function unwrapDEK(kek: CryptoKey | Uint8Array, wrapped: Uint8Array | string): Promise<Uint8Array> {
  if (typeof wrapped === 'string') {
    wrapped = hexToBytes(wrapped)
  }
  if (wrapped.length < WIRE_NONCE_SIZE + WIRE_TAG_SIZE + 32) {
    throw new Error('wrapped DEK envelope is too short')
  }
  const unwrapKey = kek instanceof CryptoKey ? kek : await importKey(kek, 'decrypt')
  const nonce = wrapped.subarray(0, WIRE_NONCE_SIZE)
  const ciphertext = wrapped.subarray(WIRE_NONCE_SIZE)
  const dek = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(nonce) },
    unwrapKey,
    toArrayBuffer(ciphertext),
  )
  return new Uint8Array(dek)
}

export async function importKey(raw: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(raw), { name: 'AES-GCM' }, false, [usage])
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('invalid hex key material')
  }
  const raw = new Uint8Array(hex.length / 2)
  for (let i = 0; i < raw.length; i++) {
    raw[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return raw
}

/**
 * Copy a typed-array view into a standalone ArrayBuffer. A plain
 * Uint8Array.slice() copies, but a Buffer's slice() is subarray() and shares
 * its (potentially pooled) backing store, so the copy must be explicit.
 */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(view.byteLength)
  new Uint8Array(copy).set(view)
  return copy
}
