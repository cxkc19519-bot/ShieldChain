import { useEffect, useRef } from 'react'

export function useRouteFocus(pathname: string) {
  const target = useRef<HTMLElement>(null)
  const previousPath = useRef(pathname)

  useEffect(() => {
    if (previousPath.current !== pathname) target.current?.focus()
    previousPath.current = pathname
  }, [pathname])

  return target
}
