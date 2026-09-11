import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const forbidden = ['raw_prompt', 'chain_of_thought', 'token_digest', 'tenant_id', 'principal_id', 'access_token']

function componentFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return componentFiles(path)
    return entry.name.endsWith('.tsx') && !entry.name.endsWith('.test.tsx') ? [path] : []
  })
}

describe('security rendering boundary', () => {
  it('keeps server-only sensitive field names out of render components', () => {
    const violations = componentFiles(resolve(process.cwd(), 'src'))
      .flatMap((file) => forbidden.filter((field) => readFileSync(file, 'utf8').includes(field)).map((field) => `${file}:${field}`))

    expect(violations).toEqual([])
  })
})
