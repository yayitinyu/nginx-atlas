import { useEffect, useRef } from 'react'

interface TurnstileAPI {
  render: (container: HTMLElement, options: {
    sitekey: string
    theme: 'light' | 'dark'
    action: string
    callback: (token: string) => void
    'error-callback': () => void
    'expired-callback': () => void
  }) => string
  remove: (widgetID: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileAPI
  }
}

const scriptID = 'nginx-atlas-turnstile'
let scriptPromise: Promise<TurnstileAPI> | undefined

function loadTurnstile(): Promise<TurnstileAPI> {
  if (window.turnstile) return Promise.resolve(window.turnstile)
  if (scriptPromise) return scriptPromise
  const pending = new Promise<TurnstileAPI>((resolve, reject) => {
    const ready = () => window.turnstile ? resolve(window.turnstile) : reject(new Error('Turnstile unavailable'))
    const existing = document.getElementById(scriptID) as HTMLScriptElement | null
    if (existing) {
      existing.addEventListener('load', ready, { once: true })
      existing.addEventListener('error', () => { existing.remove(); reject(new Error('Turnstile failed to load')) }, { once: true })
      return
    }
    const script = document.createElement('script')
    script.id = scriptID
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    script.async = true
    script.defer = true
    script.addEventListener('load', ready, { once: true })
    script.addEventListener('error', () => { script.remove(); reject(new Error('Turnstile failed to load')) }, { once: true })
    document.head.appendChild(script)
  })
  const guarded = pending.catch((error) => {
    scriptPromise = undefined
    throw error
  })
  scriptPromise = guarded
  return guarded
}

export function TurnstileWidget({ siteKey, theme, onToken, onError }: {
  siteKey: string
  theme: 'light' | 'dark'
  onToken: (token: string) => void
  onError: () => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let active = true
    let widgetID = ''
    onToken('')
    void loadTurnstile().then((turnstile) => {
      if (!active || !containerRef.current) return
      widgetID = turnstile.render(containerRef.current, {
        sitekey: siteKey,
        theme,
        action: 'turnstile-spin-v1',
        callback: onToken,
        'error-callback': () => { onToken(''); onError() },
        'expired-callback': () => onToken(''),
      })
    }).catch(() => { onToken(''); onError() })
    return () => {
      active = false
      if (widgetID && window.turnstile) window.turnstile.remove(widgetID)
    }
  }, [siteKey, theme, onToken, onError])

  return <div className="turnstile-slot" data-action="turnstile-spin-v1" ref={containerRef} />
}
