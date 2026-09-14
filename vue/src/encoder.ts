import { WIRE_CHUNK_SIZE, WIRE_HEADER_SIZE, WIRE_NONCE_SIZE, WIRE_VERSION, uint64BE } from './wire'

/**
 * WireEncoder — streaming DOFS v1 encoder for upload workers.
 *
 * Owns the chunk ordinal so callers only feed plaintext chunks (any size up
 * to WIRE_CHUNK_SIZE; the final chunk may be short) and receive
 * [12-byte nonce | ciphertext + tag] segments to place into their own
 * multipart buffers. The 5-byte wire header is produced separately via
 * header() exactly once.
 */
export class WireEncoder {
  #key: CryptoKey
  #index = 0

  private constructor(key: CryptoKey) {
    this.#key = key
  }

  static async create(dek: Uint8Array): Promise<WireEncoder> {
    const key = await crypto.subtle.importKey('raw', toArrayBuffer(dek), { name: 'AES-GCM' }, false, ['encrypt'])
    return new WireEncoder(key)
  }

  /** The DOFS v1 header: [1 byte version][4 bytes chunk size big-endian]. */
  static header(): Uint8Array<ArrayBuffer> {
    const header = new Uint8Array(WIRE_HEADER_SIZE)
    header[0] = WIRE_VERSION
    new DataView(header.buffer).setUint32(1, WIRE_CHUNK_SIZE, false)
    return header
  }

  /** Number of chunks already encrypted; also the AAD ordinal of the next chunk. */
  get chunkIndex(): number {
    return this.#index
  }

  /**
   * Encrypt one plaintext chunk and return [nonce | ciphertext + tag].
   * The chunk is authenticated with its ordinal to prevent reorder and
   * truncation attacks.
   */
  async encryptChunk(chunk: Uint8Array): Promise<Uint8Array> {
    const nonce = crypto.getRandomValues(new Uint8Array(WIRE_NONCE_SIZE))
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: uint64BE(this.#index) },
        this.#key,
        toArrayBuffer(chunk),
      ),
    )
    this.#index += 1

    const segment = new Uint8Array(nonce.length + ciphertext.length)
    segment.set(nonce, 0)
    segment.set(ciphertext, nonce.length)
    return segment
  }
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
