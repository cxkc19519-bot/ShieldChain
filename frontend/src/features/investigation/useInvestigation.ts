import { useCallback, useEffect, useRef, useState } from 'react'

import { getAudit, getIncident, getInvestigation, resetPhishingScenario, startInvestigation } from './api'
import type {
  AuditResponse,
  IncidentResponse,
  InvestigationMode,
  InvestigationResponse,
  InvestigationStatus,
  ResetSimulationResponse,
} from './types'

const TERMINAL = new Set<InvestigationStatus>(['closed', 'failed', 'needs_review', 'interrupted'])

function message(error: unknown): string {
  return error instanceof Error ? error.message : '璇锋眰澶辫触'
}

export interface InvestigationState {
  scenario: ResetSimulationResponse | null
  run: InvestigationResponse | null
  incident: IncidentResponse | null
  audit: AuditResponse | null
  error: string | null
  pending: boolean
  active: boolean
  start: (mode: InvestigationMode) => Promise<void>
  reset: () => Promise<void>
}

export function useInvestigation(): InvestigationState {
  const [scenario, setScenario] = useState<ResetSimulationResponse | null>(null)
  const [run, setRun] = useState<InvestigationResponse | null>(null)
  const [incident, setIncident] = useState<IncidentResponse | null>(null)
  const [audit, setAudit] = useState<AuditResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const actionController = useRef<AbortController | null>(null)

  const cancelAction = useCallback(() => {
    actionController.current?.abort()
    actionController.current = null
  }, [])

  const reset = useCallback(async () => {
    cancelAction()
    setRun(null)
    setIncident(null)
    setAudit(null)
    setError(null)
    setPending(true)
    const controller = new AbortController()
    actionController.current = controller
    try {
      const next = await resetPhishingScenario(controller.signal)
      if (!controller.signal.aborted) setScenario(next)
    } catch (failure) {
      if (!controller.signal.aborted) setError(message(failure))
    } finally {
      if (actionController.current === controller) actionController.current = null
      if (!controller.signal.aborted) setPending(false)
    }
  }, [cancelAction])

  const start = useCallback(async (mode: InvestigationMode) => {
    cancelAction()
    setError(null)
    setPending(true)
    const controller = new AbortController()
    actionController.current = controller
    try {
      let loaded = scenario
      if (!loaded) {
        loaded = await resetPhishingScenario(controller.signal)
        if (controller.signal.aborted) return
        setScenario(loaded)
      }
      const next = await startInvestigation(loaded.simulation.id, mode, controller.signal)
      if (!controller.signal.aborted) setRun(next)
    } catch (failure) {
      if (!controller.signal.aborted) setError(message(failure))
    } finally {
      if (actionController.current === controller) actionController.current = null
      if (!controller.signal.aborted) setPending(false)
    }
  }, [cancelAction, scenario])

  const runId = run?.run_id
  const runStatus = run?.status
  const runIsTerminal = runStatus !== undefined && TERMINAL.has(runStatus)
  useEffect(() => {
    if (!runId || runIsTerminal) return
    let timer: number | undefined
    let stopped = false
    let requestController: AbortController | null = null

    const schedule = () => {
      timer = window.setTimeout(() => void attempt(), 500)
    }
    const attempt = async () => {
      requestController = new AbortController()
      try {
        const next = await getInvestigation(runId, requestController.signal)
        if (stopped) return
        setRun(next)
        setError(null)
        if (!TERMINAL.has(next.status)) schedule()
      } catch (failure) {
        if (stopped || requestController.signal.aborted) return
        setError(message(failure))
        schedule()
      }
    }

    schedule()
    return () => {
      stopped = true
      if (timer !== undefined) window.clearTimeout(timer)
      requestController?.abort()
    }
  }, [runId, runIsTerminal])

  const terminalIncidentId = runIsTerminal ? run?.incident_id : undefined
  useEffect(() => {
    if (!terminalIncidentId) return
    const controller = new AbortController()
    void Promise.all([getIncident(terminalIncidentId, controller.signal), getAudit(terminalIncidentId, controller.signal)]).then(
      ([nextIncident, nextAudit]) => {
        setIncident(nextIncident)
        setAudit(nextAudit)
      },
      (failure: unknown) => {
        if (!controller.signal.aborted) setError(message(failure))
      },
    )
    return () => controller.abort()
  }, [terminalIncidentId])

  useEffect(() => () => cancelAction(), [cancelAction])

  return {
    scenario,
    run,
    incident,
    audit,
    error,
    pending,
    active: pending || (run !== null && !TERMINAL.has(run.status)),
    start,
    reset,
  }
}
