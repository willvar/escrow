import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { generateDEK, zeroize } from './keys'
import { WireEncoder } from './encoder'
import { decryptBlob, WIRE_CHUNK_SIZE } from './wire'
import { decryptWireChunk, plaintextRangeToEncRange, readWireHeader, unwrapDEK } from './range'

interface WrapVector {
  kek_hex: string
  dek_hex: string
  wrapped_hex: string
  description: string
}

interface WireVector {
  key_hex: string
  chunk_size: number
  plaintext_hex: string
  ciphertext_hex: string
  description: string
}

interface Golden {
  wrap: WrapVector[]
  wire: WireVector[]
}

// Single source of truth shared with the Go tests: repo-root testdata/golden.json.
const golden: Golden = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../testdata/golden.json', import.meta.url)), 'utf8'),
)

describe('range: golden vectors', () => {
  it('decrypts every wire vector chunk-by-chunk with explicit ordinals', async () => {
    for (const vector of golden.wire) {
      const key = keyFromHex(vector.key_hex)
      const blob = Buffer.from(vector.ciphertext_hex, 'hex')
      const chunkSize = readWireHeader(blob.subarray(0, 5), vector.chunk_size)
      expect(chunkSize).toBe(vector.chunk_size)

      const dec = await import('./wire')
      const encChunkSize = 12 + chunkSize + 16
      const chunks: Uint8Array[] = []
      let offset = 5
      let index = 0
      while (offset < blob.length) {
        const segment = blob.subarray(offset, Math.min(offset + encChunkSize, blob.length))
        chunks.push(await decryptWireChunk(key, new Uint8Array(segment), index))
        offset += segment.length
        index++
      }
      const assembled = chunks.reduce((acc, c) => acc.concat(Array.from(c)), [] as number[])
      expect(assembled).toEqual(Array.from(Buffer.from(vector.plaintext_hex, 'hex')))
      void dec
    }
  })

  it('unwraps every DEK envelope vector', async () => {
    for (const vector of golden.wrap) {
      const kek = keyFromHex(vector.kek_hex)
      const dek = await unwrapDEK(kek, Buffer.from(vector.wrapped_hex, 'hex'))
      expect(Buffer.from(dek).toString('hex')).toBe(vector.dek_hex)
      expect(dek.length).toBe(32)
    }
  })
})

describe('range: decryptWireChunk', () => {
  it('rejects a wrong ordinal', async () => {
    const dek = generateDEK()
    const encoder = await WireEncoder.create(dek)
    const segment = await encoder.encryptChunk(new Uint8Array(100))
    await expect(decryptWireChunk(dek, segment, 99)).rejects.toThrow()
    zeroize(dek)
  })

  it('rejects a tampered segment', async () => {
    const dek = generateDEK()
    const encoder = await WireEncoder.create(dek)
    const segment = await encoder.encryptChunk(new Uint8Array(100))
    segment[20]! ^= 0xff
    await expect(decryptWireChunk(dek, segment, 0)).rejects.toThrow()
  })

  it('rejects a truncated segment', async () => {
    const dek = generateDEK()
    await expect(decryptWireChunk(dek, new Uint8Array(10), 0)).rejects.toThrow(/too short/)
  })
})

describe('range: geometry', () => {
  it('maps plaintext ranges to encrypted ranges', () => {
    const chunkSize = 65536
    const encChunk = 12 + chunkSize + 16
    // First chunk, whole file
    expect(plaintextRangeToEncRange(0, chunkSize - 1, chunkSize)).toEqual({
      startChunk: 0,
      endChunk: 0,
      encStart: 5,
      encEnd: 5 + encChunk - 1,
    })
    // Middle of second chunk
    expect(plaintextRangeToEncRange(chunkSize + 10, chunkSize + 20, chunkSize)).toEqual({
      startChunk: 1,
      endChunk: 1,
      encStart: 5 + encChunk,
      encEnd: 5 + 2 * encChunk - 1,
    })
    // Range spanning chunk boundary
    expect(plaintextRangeToEncRange(chunkSize - 5, chunkSize + 5, chunkSize)).toEqual({
      startChunk: 0,
      endChunk: 1,
      encStart: 5,
      encEnd: 5 + 2 * encChunk - 1,
    })
  })

  it('rejects invalid ranges', () => {
    expect(() => plaintextRangeToEncRange(10, 5, 65536)).toThrow()
    expect(() => plaintextRangeToEncRange(-1, 5, 65536)).toThrow()
    expect(() => plaintextRangeToEncRange(0, 5, 0)).toThrow()
  })
})

describe('range: header', () => {
  it('validates a canonical header', () => {
    const header = WireEncoder.header()
    expect(readWireHeader(header)).toBe(WIRE_CHUNK_SIZE)
  })

  it('rejects bad headers', () => {
    const header = WireEncoder.header()
    header[0] = 0x02
    expect(() => readWireHeader(header)).toThrow(/version/)
    const oversized = WireEncoder.header()
    oversized[1] = 0x02
    expect(() => readWireHeader(oversized)).toThrow(/chunk size/)
    expect(() => readWireHeader(new Uint8Array(3))).toThrow(/short/)
    expect(() => readWireHeader(WireEncoder.header(), 4096)).toThrow(/unexpected/)
  })
})

function keyFromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'))
}
