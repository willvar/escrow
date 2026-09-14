import { describe, expect, it } from 'vitest'
import { generateDEK, zeroize } from './keys'
import { decryptBlob, WIRE_CHUNK_SIZE, WIRE_HEADER_SIZE, WIRE_VERSION } from './wire'
import { WireEncoder } from './encoder'

describe('WireEncoder', () => {
  it('produces the canonical DOFS v1 header', () => {
    const header = WireEncoder.header()
    expect(header[0]).toBe(WIRE_VERSION)
    expect(new DataView(header.buffer).getUint32(1, false)).toBe(WIRE_CHUNK_SIZE)
  })

  it('streams chunks with consecutive ordinals that decrypt as one blob', async () => {
    const dek = generateDEK()
    const encoder = await WireEncoder.create(dek)

    const chunks = [
      crypto.getRandomValues(new Uint8Array(WIRE_CHUNK_SIZE)),
      crypto.getRandomValues(new Uint8Array(WIRE_CHUNK_SIZE)),
      crypto.getRandomValues(new Uint8Array(7)),
    ]
    const blob = new Uint8Array(5 + 3 * (12 + 16) + chunksTotal(chunks))
    blob.set(WireEncoder.header(), 0)
    let offset = WIRE_HEADER_SIZE
    for (const chunk of chunks) {
      const segment = await encoder.encryptChunk(chunk)
      expect(segment.length).toBe(12 + 16 + chunk.length)
      blob.set(segment, offset)
      offset += segment.length
    }
    expect(encoder.chunkIndex).toBe(3)

    const plaintext = await decryptBlob(dek, blob)
    expect(Array.from(plaintext)).toEqual(Array.from(chunks[0]!).concat(Array.from(chunks[1]!), Array.from(chunks[2]!)))
    zeroize(dek)
  })

  it('rejects a segment reordered by callers', async () => {
    const dek = generateDEK()
    const encoder = await WireEncoder.create(dek)
    const first = await encoder.encryptChunk(new Uint8Array(100))
    const second = await encoder.encryptChunk(new Uint8Array(100))

    const blob = new Uint8Array(WIRE_HEADER_SIZE + first.length + second.length)
    blob.set(WireEncoder.header(), 0)
    blob.set(second, WIRE_HEADER_SIZE)
    blob.set(first, WIRE_HEADER_SIZE + second.length)
    await expect(decryptBlob(dek, blob)).rejects.toThrow()
  })
})

function chunksTotal(chunks: Uint8Array[]): number {
  return chunks.reduce((sum, chunk) => sum + chunk.length, 0)
}
