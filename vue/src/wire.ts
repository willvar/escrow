/**
 * wire.ts — DOFS v1 object codec for browser clients.
 *
 * Wire format (identical to github.com/willvar/dofs EncryptStream and to the
 * server-side Go implementations):
 *
 *   [1 byte version: 0x01]
 *   [4 bytes chunk_size big-endian]
 *   [chunk 0: 12-byte nonce | ciphertext + 16-byte tag]
 *   [chunk 1: …]
 *
 * Each chunk authenticates its zero-based ordinal as 8-byte big-endian AAD,
 * preventing reorder and truncation attacks.
 */

export const WIRE_VERSION = 0x01
export const WIRE_CHUNK_SIZE = 65536
export const WIRE_NONCE_SIZE = 12
export const WIRE_TAG_SIZE = 16
export const WIRE_HEADER_SIZE = 5

/** Encrypted size of a plaintext of the given length in the DOFS v1 format. */
export function encryptedSize(plaintextLength: number, chunkSize = WIRE_CHUNK_SIZE): number {
  if (plaintextLength <= 0) {
    return WIRE_HEADER_SIZE
  }
  const chunks = Math.ceil(plaintextLength / chunkSize)
  return WIRE_HEADER_SIZE + plaintextLength + chunks * (WIRE_NONCE_SIZE + WIRE_TAG_SIZE)
}

/** 8-byte big-endian chunk ordinal used as AES-GCM AAD. */
export function uint64BE(value: number | bigint): Uint8Array<ArrayBuffer> {
  const aad = new Uint8Array(8)
  new DataView(aad.buffer).setBigUint64(0, BigInt(value), false)
  return aad
}

/** Encrypt bytes into the DOFS v1 wire format. */
export async function encryptBlob(dek: Uint8Array, data: Uint8Array | ArrayBuffer): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(dek), { name: 'AES-GCM' }, false, ['encrypt'])
  const plain = data instanceof Uint8Array ? data : new Uint8Array(data)

  const numChunks = Math.ceil(plain.length / WIRE_CHUNK_SIZE)
  const output = new Uint8Array(encryptedSize(plain.length))
  output[0] = WIRE_VERSION
  new DataView(output.buffer).setUint32(1, WIRE_CHUNK_SIZE, false)

  let offset = WIRE_HEADER_SIZE
  for (let i = 0; i < numChunks; i++) {
    const chunk = plain.subarray(i * WIRE_CHUNK_SIZE, Math.min((i + 1) * WIRE_CHUNK_SIZE, plain.length))
    const nonce = crypto.getRandomValues(new Uint8Array(WIRE_NONCE_SIZE))
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: uint64BE(i) },
        key,
        toArrayBuffer(chunk),
      ),
    )
    output.set(nonce, offset)
    offset += WIRE_NONCE_SIZE
    output.set(ciphertext, offset)
    offset += ciphertext.length
  }
  return output
}

/** Decrypt a DOFS v1 wire-format blob back to plaintext. */
export async function decryptBlob(dek: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length < WIRE_HEADER_SIZE) {
    throw new Error('blob is shorter than the wire header')
  }
  const view = new DataView(toArrayBuffer(blob))
  if (blob[0] !== WIRE_VERSION) {
    throw new Error(`unsupported wire version ${blob[0]}`)
  }
  const chunkSize = view.getUint32(1, false)
  if (chunkSize <= 0 || chunkSize > 16 * 1024 * 1024) {
    throw new Error(`invalid encrypted chunk size ${chunkSize}`)
  }
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(dek), { name: 'AES-GCM' }, false, ['decrypt'])

  const chunks: Uint8Array[] = []
  let offset = WIRE_HEADER_SIZE
  let i = 0
  while (offset < blob.length) {
    const encChunkMax = WIRE_NONCE_SIZE + chunkSize + WIRE_TAG_SIZE
    const end = Math.min(offset + encChunkMax, blob.length)
    const encryptedChunk = blob.subarray(offset, end)
    if (encryptedChunk.length < WIRE_NONCE_SIZE + WIRE_TAG_SIZE) {
      throw new Error(`truncated encrypted chunk ${i}`)
    }
    const nonce = encryptedChunk.subarray(0, WIRE_NONCE_SIZE)
    const ciphertext = encryptedChunk.subarray(WIRE_NONCE_SIZE)
    const plainChunk = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: uint64BE(i),
      },
      key,
      toArrayBuffer(ciphertext),
    )
    chunks.push(new Uint8Array(plainChunk))
    offset += encryptedChunk.length
    i++
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const plaintext = new Uint8Array(total)
  let pos = 0
  for (const chunk of chunks) {
    plaintext.set(chunk, pos)
    pos += chunk.length
  }
  return plaintext
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
