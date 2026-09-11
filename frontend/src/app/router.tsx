import { createBrowserRouter, type RouteObject } from 'react-router-dom'

import { HomePage } from '../features/home/HomePage'
import { HelpPage } from '../features/help/HelpPage'
import { AboutPage } from '../features/about/AboutPage'
import { ChangelogPage } from '../features/about/ChangelogPage'
import { DashboardPage } from '../features/dashboard/DashboardPage'
import { OperationsReportPage } from '../features/operations/OperationsReportPage'
import { KnowledgePage } from '../features/knowledge/KnowledgePage'
import { AssistantPage } from '../features/assistant/AssistantPage'
import { AlertsPage } from '../features/alerts/AlertsPage'
import { VulnerabilitiesPage } from '../features/vulnerabilities/VulnerabilitiesPage'
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
      { path: 'changelog', element: <ChangelogPage /> },
      { path: 'operations-report', element: <OperationsReportPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      { path: 'vulnerabilities', element: <VulnerabilitiesPage /> },
      { path: 'knowledge', element: <KnowledgePage /> },
      { path: 'assistant', element: <AssistantPage /> },
      { path: 'response', element: <OperationsReportPage /> },
    ],
  },
]

export const router = createBrowserRouter(appRoutes)
