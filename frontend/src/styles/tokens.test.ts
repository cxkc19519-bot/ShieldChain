import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(resolve(process.cwd(), 'src/styles/tokens.css'), 'utf8')

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
})
