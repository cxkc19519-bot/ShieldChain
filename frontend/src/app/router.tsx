import { createBrowserRouter, type RouteObject } from 'react-router-dom'

import { DashboardPage } from '../features/dashboard/DashboardPage'
import { InvestigationPage } from '../features/investigation/InvestigationPage'
import { KnowledgePage } from '../features/knowledge/KnowledgePage'
import { App } from './App'
import { FuturePage } from './FuturePage'

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'events', element: <InvestigationPage /> },
      { path: 'agents', element: <FuturePage /> },
      { path: 'knowledge', element: <KnowledgePage /> },
      { path: 'response', element: <FuturePage /> },
      { path: 'reports', element: <FuturePage /> },
    ],
  },
]

export const router = createBrowserRouter(appRoutes)
