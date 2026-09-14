import { describe, expect, it } from 'vitest'
import { generateDEK, keyFromHex, keyToHex, zeroize } from './keys'

describe('keys', () => {
  it('generates 32-byte DEKs', () => {
    const dek = generateDEK()
    expect(dek.length).toBe(32)
    const second = generateDEK()
    expect(Array.from(dek)).not.toEqual(Array.from(second))
  })

  it('round-trips hex encoding', () => {
    const dek = generateDEK()
    expect(keyFromHex(keyToHex(dek))).toEqual(dek)
  })

  it('accepts uppercase hex', () => {
    const hex = keyToHex(generateDEK()).toUpperCase()
    expect(keyFromHex(hex)).toHaveLength(32)
  })

  it('rejects malformed hex', () => {
    expect(() => keyFromHex('abc')).toThrow()
    expect(() => keyFromHex('zz')).toThrow()
  })

  it('zeroizes in place', () => {
    const dek = generateDEK()
    zeroize(dek)
    expect(Array.from(dek).every((byte) => byte === 0)).toBe(true)
  })
})
