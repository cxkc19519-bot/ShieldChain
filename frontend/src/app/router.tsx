import { createBrowserRouter, type RouteObject } from 'react-router-dom'

import { AgentsPage } from '../features/agents/AgentsPage'
import { DashboardPage } from '../features/dashboard/DashboardPage'
import { InvestigationPage } from '../features/investigation/InvestigationPage'
import { ToolsPage } from '../features/tools/ToolsPage'
import { ReportsPage } from '../features/reports/ReportsPage'
import { KnowledgePage } from '../features/knowledge/KnowledgePage'
import { App } from './App'
import { RunContextProvider } from './RunContext'

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: <RunContextProvider><App /></RunContextProvider>,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'events', element: <InvestigationPage /> },
      { path: 'agents', element: <AgentsPage /> },
      { path: 'knowledge', element: <KnowledgePage /> },
      { path: 'response', element: <ToolsPage /> },
      { path: 'reports', element: <ReportsPage /> },
    ],
  },
]

export const router = createBrowserRouter(appRoutes)
