import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { generateDEK, keyFromHex, zeroize } from './keys'
import { decryptBlob, encryptBlob, encryptedSize, uint64BE, WIRE_VERSION } from './wire'

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

describe('wire: golden vectors', () => {
  it('decrypts every DOFS v1 object vector', async () => {
    for (const vector of golden.wire) {
      const key = keyFromHex(vector.key_hex)
      const ciphertext = Buffer.from(vector.ciphertext_hex, 'hex')
      const plaintext = await decryptBlob(key, new Uint8Array(ciphertext))
      const want = Buffer.from(vector.plaintext_hex, 'hex')
      expect(Buffer.from(plaintext).toString('hex')).toBe(want.toString('hex'))
    }
  })
})

describe('wire: round trips', () => {
  const sizes = [0, 1, 65, 65535, 65536, 65537, 200_000]

  for (const size of sizes) {
    it(`encrypts/decrypts ${size} plaintext bytes`, async () => {
      const dek = generateDEK()
      const plain = new Uint8Array(size)
      for (let i = 0; i < size; i++) plain[i] = (i * 31 + 7) % 251

      const blob = await encryptBlob(dek, plain)
      expect(blob.length).toBe(encryptedSize(size))
      expect(blob[0]).toBe(WIRE_VERSION)

      const recovered = await decryptBlob(dek, blob)
      expect(recovered).toEqual(plain)

      zeroize(dek)
    })
  }

  it('rejects a tampered chunk', async () => {
    const dek = generateDEK()
    const blob = await encryptBlob(dek, new Uint8Array(1000))
    blob[30]! ^= 0xff
    await expect(decryptBlob(dek, blob)).rejects.toThrow()
  })

  it('rejects a wrong key', async () => {
    const blob = await encryptBlob(generateDEK(), new Uint8Array(1000))
    await expect(decryptBlob(generateDEK(), blob)).rejects.toThrow()
  })

  it('rejects bad headers', async () => {
    const dek = generateDEK()
    const blob = await encryptBlob(dek, new Uint8Array(100))
    blob[0] = 0x02
    await expect(decryptBlob(dek, blob)).rejects.toThrow(/version/)
    blob[0] = WIRE_VERSION
    blob[1] = 0xff
    await expect(decryptBlob(dek, blob)).rejects.toThrow(/chunk size/)
  })
})

describe('wire: helpers', () => {
  it('uint64BE matches 8-byte big-endian ordinals', () => {
    expect(Array.from(uint64BE(0))).toEqual([0, 0, 0, 0, 0, 0, 0, 0])
    expect(Array.from(uint64BE(1))).toEqual([0, 0, 0, 0, 0, 0, 0, 1])
    expect(Array.from(uint64BE(0x0102030405060708n))).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
  })

  it('encryptedSize matches the DOFS v1 formula', () => {
    expect(encryptedSize(0)).toBe(5)
    expect(encryptedSize(1)).toBe(5 + 1 + 28)
    expect(encryptedSize(65536)).toBe(5 + 65536 + 28)
    expect(encryptedSize(65537)).toBe(5 + 65537 + 2 * 28)
  })
})
