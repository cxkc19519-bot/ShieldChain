import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(resolve(process.cwd(), 'src/styles/tokens.css'), 'utf8')

function readHexToken(name: string): string {
  const value = css.match(new RegExp(`${name}:\\s*(#[\\da-f]{6})`, 'i'))?.[1]
  if (!value) {
    throw new Error(`Missing hexadecimal CSS token ${name}`)
  }
  return value
}

function relativeLuminance(hex: string): number {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)
    ?.map((value) => Number.parseInt(value, 16) / 255)
    .map((value) => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4))

  if (!channels || channels.length !== 3) {
    throw new Error(`Invalid hexadecimal color ${hex}`)
  }

  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
}

function contrastRatio(first: string, second: string): number {
  const firstLuminance = relativeLuminance(first)
  const secondLuminance = relativeLuminance(second)
  const lighter = Math.max(firstLuminance, secondLuminance)
  const darker = Math.min(firstLuminance, secondLuminance)
  return (lighter + 0.05) / (darker + 0.05)
}

describe('application styles', () => {
  it('defines semantic pale-blue and status tokens', () => {
    expect(css).toMatch(/--color-surface:\s*#[\da-f]{6}/i)
    expect(css).toMatch(/--color-accent:\s*#[\da-f]{6}/i)
    expect(css).toMatch(/--color-warning:\s*#[\da-f]{6}/i)
    expect(css).toMatch(/--color-danger:\s*#[\da-f]{6}/i)
    expect(css).toContain('--color-status-healthy:')
    expect(css).toContain('--color-status-unavailable:')
  })

  it('provides visible keyboard focus and stacks the shell at 680px', () => {
    expect(css).toContain(':focus-visible')
    expect(css).toMatch(/@media\s*\(max-width:\s*680px\)/)
    expect(css).toMatch(/@media[\s\S]*\.app-shell[\s\S]*grid-template-columns:\s*1fr/)
  })

  it('uses a theme accent focus outline with at least 3:1 surface contrast', () => {
    const focusRule = css.match(/a:focus-visible,\s*button:focus-visible\s*{([^}]*)}/)?.[1]
    const accent = readHexToken('--color-accent')

    expect(focusRule).toContain('outline: 3px solid var(--color-accent)')
    expect(contrastRatio(accent, readHexToken('--color-surface'))).toBeGreaterThanOrEqual(3)
    expect(contrastRatio(accent, readHexToken('--color-canvas'))).toBeGreaterThanOrEqual(3)
  })

  it('keeps active navigation text at or above 4.5:1 contrast', () => {
    const activeRule = css.match(/\.sidebar a:hover,\s*\.sidebar a\.active\s*{([^}]*)}/)?.[1]
    const accent = readHexToken('--color-accent')

    expect(activeRule).toContain('color: var(--color-accent)')
    expect(contrastRatio(accent, readHexToken('--color-accent-soft'))).toBeGreaterThanOrEqual(4.5)
  })
})
