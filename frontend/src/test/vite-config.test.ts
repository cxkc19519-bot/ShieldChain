// @vitest-environment node

import { describe, expect, it } from 'vitest'

import config from '../../vite.config'

describe('Vite development integration', () => {
  it('proxies API paths to FastAPI without rewriting them', () => {
    expect(config).toHaveProperty('server.proxy./api.target', 'http://127.0.0.1:8000')
    expect(config).not.toHaveProperty('server.proxy./api.rewrite')
  })
})
