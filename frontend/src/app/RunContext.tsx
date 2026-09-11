import { createContext, type PropsWithChildren, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const INCIDENT_KEY = 'shieldchain.incident_id'
const RUN_KEY = 'shieldchain.run_id'

export interface RunSelection {
  incidentId: string | null
  runId: string | null
}

interface RunContextValue extends RunSelection {
  setSelection: (selection: Partial<RunSelection>) => void
  clearSelection: () => void
}

const emptySelection: RunSelection = { incidentId: null, runId: null }
const RunContext = createContext<RunContextValue>({
  ...emptySelection,
  setSelection: () => undefined,
  clearSelection: () => undefined,
})

function valid(value: string | null): string | null {
  const normalized = value?.trim() ?? ''
  return UUID.test(normalized) ? normalized : null
}

function stored(key: string): string | null {
  try {
    return valid(window.sessionStorage.getItem(key))
  } catch {
    return null
  }
}

function fromLocation(search: string): RunSelection {
  const params = new URLSearchParams(search)
  const hasUrlContext = params.has('incident_id') || params.has('run_id')
  if (hasUrlContext) {
    return { incidentId: valid(params.get('incident_id')), runId: valid(params.get('run_id')) }
  }
  return { incidentId: stored(INCIDENT_KEY), runId: stored(RUN_KEY) }
}

function persist(selection: RunSelection) {
  try {
    if (selection.incidentId) window.sessionStorage.setItem(INCIDENT_KEY, selection.incidentId)
    else window.sessionStorage.removeItem(INCIDENT_KEY)
    if (selection.runId) window.sessionStorage.setItem(RUN_KEY, selection.runId)
    else window.sessionStorage.removeItem(RUN_KEY)
  } catch {
    // URL state remains authoritative when session storage is unavailable.
  }
}

export function RunContextProvider({ children }: PropsWithChildren) {
  const location = useLocation()
  const navigate = useNavigate()
  const [selection, setState] = useState<RunSelection>(() => fromLocation(location.search))

  const replaceUrl = useCallback((next: RunSelection) => {
    const params = new URLSearchParams(location.search)
    if (next.incidentId) params.set('incident_id', next.incidentId)
    else params.delete('incident_id')
    if (next.runId) params.set('run_id', next.runId)
    else params.delete('run_id')
    const search = params.toString()
    navigate({ pathname: location.pathname, search: search ? `?${search}` : '' }, { replace: true })
  }, [location.pathname, location.search, navigate])

  const setSelection = useCallback((next: Partial<RunSelection>) => {
    const updated = {
      incidentId: next.incidentId === undefined ? selection.incidentId : valid(next.incidentId),
      runId: next.runId === undefined ? selection.runId : valid(next.runId),
    }
    persist(updated)
    setState(updated)
    replaceUrl(updated)
  }, [replaceUrl, selection.incidentId, selection.runId])

  const clearSelection = useCallback(() => {
    persist(emptySelection)
    setState(emptySelection)
    replaceUrl(emptySelection)
  }, [replaceUrl])

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const next = fromLocation(location.search)
    persist(next)
    setState((current) => {
      if (current.incidentId === next.incidentId && current.runId === next.runId) return current
      return next
    })
    const missingUrlContext = !params.has('incident_id') && !params.has('run_id')
    const invalidUrlContext = (params.has('incident_id') && valid(params.get('incident_id')) === null)
      || (params.has('run_id') && valid(params.get('run_id')) === null)
    if ((missingUrlContext && (next.incidentId || next.runId)) || invalidUrlContext) replaceUrl(next)
  }, [location.search, replaceUrl])

  const value = useMemo(() => ({ ...selection, setSelection, clearSelection }), [clearSelection, selection, setSelection])
  return <RunContext.Provider value={value}>{children}</RunContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useRunContext(): RunContextValue {
  return useContext(RunContext)
}
