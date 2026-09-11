import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { HelpPage } from './HelpPage'

describe('HelpPage', () => {
  it('introduces the project and every agent', () => {
    render(<MemoryRouter><HelpPage /></MemoryRouter>)

    expect(screen.getByRole('heading', { name: 'ShieldChain 使用说明' })).toBeInTheDocument()
    expect(screen.getByText('项目说明')).toBeInTheDocument()
    for (const name of [
      '总控智能体', '告警分诊智能体', '威胁研判智能体', '知识检索智能体',
      '响应规划智能体', '验证智能体', '报告智能体', '漏洞研判智能体',
    ]) {
      expect(screen.getByRole('heading', { name })).toBeInTheDocument()
    }
    expect(screen.getByRole('link', { name: '进入运营总览' })).toHaveAttribute('href', '/dashboard')
    expect(screen.getByRole('link', { name: '查看运营报告' })).toHaveAttribute('href', '/operations-report')
    expect(screen.queryByRole('heading', { name: '推荐演示顺序' })).not.toBeInTheDocument()
    expect(screen.queryByText(/当前前端处于离线仿真模式/)).not.toBeInTheDocument()
  })
})
