import { createBrowserRouter, type RouteObject } from 'react-router-dom'

import { HomePage } from '../features/home/HomePage'
import { HelpPage } from '../features/help/HelpPage'
import { AboutPage } from '../features/about/AboutPage'
import { StatusPage } from '../features/about/StatusPage'
import { ChangelogPage } from '../features/about/ChangelogPage'
import { DashboardPage } from '../features/dashboard/DashboardPage'
import { AgentsPage } from '../features/agents/AgentsPage'
import { ToolsPage } from '../features/tools/ToolsPage'
import { OperationsReportPage } from '../features/operations/OperationsReportPage'
import { ReportsPage } from '../features/reports/ReportsPage'
import { KnowledgePage } from '../features/knowledge/KnowledgePage'
import { AssistantPage } from '../features/assistant/AssistantPage'
import { QwenChatPage } from '../features/qwen/QwenChatPage'
import { AlertsPage } from '../features/alerts/AlertsPage'
import { App } from './App'
import { RouteErrorPage } from './RouteErrorPage'
import { RunContextProvider } from './RunContext'

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: <RunContextProvider><App /></RunContextProvider>,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'dashboard', element: <DashboardPage /> },
      { path: 'help', element: <HelpPage /> },
      { path: 'about', element: <AboutPage /> },
      { path: 'status', element: <StatusPage /> },
      { path: 'changelog', element: <ChangelogPage /> },
      { path: 'operations-report', element: <OperationsReportPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      { path: 'agents', element: <AgentsPage /> },
      { path: 'knowledge', element: <KnowledgePage /> },
      { path: 'assistant', element: <AssistantPage /> },
      { path: 'qwen-chat', element: <QwenChatPage /> },
      { path: 'response', element: <ToolsPage /> },
      { path: 'reports', element: <ReportsPage /> },
    ],
  },
]

export const router = createBrowserRouter(appRoutes)
