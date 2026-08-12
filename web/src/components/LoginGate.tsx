import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { usePreferences, type LanguageMode, type ThemeMode } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, Logo } from './Primitives'
import { SelectField } from './SelectField'
import { api } from '../api'
import type { LoginConfig } from '../types'
import { TurnstileWidget } from './TurnstileWidget'

const defaultLoginConfig: LoginConfig = { turnstile_enabled: false, turnstile_site_key: '' }

export function LoginGate({ onLogin }: { onLogin: (password: string, turnstileToken: string) => Promise<void> }) {
  const { t, effectiveTheme, effectiveLanguage, setTheme, setLanguage } = usePreferences()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [config, setConfig] = useState<LoginConfig>(defaultLoginConfig)
  const [configLoading, setConfigLoading] = useState(true)
  const [configFailed, setConfigFailed] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState('')
  const [challengeAttempt, setChallengeAttempt] = useState(0)
  const handleChallengeError = useCallback(() => setError(t('login.challengeUnavailable')), [t])

  useEffect(() => {
    document.body.classList.add('login-active')
    return () => document.body.classList.remove('login-active')
  }, [])

  useEffect(() => {
    let active = true
    void api.loginConfig()
      .then((value) => { if (active) { setConfig(value); setConfigFailed(false) } })
      .catch(() => { if (active) { setConfig(defaultLoginConfig); setConfigFailed(true); setError(t('login.configUnavailable')) } })
      .finally(() => { if (active) setConfigLoading(false) })
    return () => { active = false }
  }, [t])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (password.length < 12) {
      setError(t('login.tooShort'))
      return
    }
    setBusy(true)
    setError('')
    try {
      await onLogin(password, turnstileToken)
    } catch {
      setError(t('login.invalid'))
      setTurnstileToken('')
      setChallengeAttempt((value) => value + 1)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-screen-compact">
      <div className="login-preferences-top">
        <SelectField ariaLabel={t('app.language')} value={effectiveLanguage} onChange={(value) => setLanguage(value as LanguageMode)} icon="language" className="login-preference-select" options={[
          { value: 'zh', label: t('common.chinese') }, { value: 'en', label: t('common.english') },
        ]} />
        <SelectField ariaLabel={t('app.theme')} value={effectiveTheme} onChange={(value) => setTheme(value as ThemeMode)} icon={effectiveTheme === 'light' ? 'sun' : 'moon'} className="login-preference-select" options={[
          { value: 'light', label: t('common.light') }, { value: 'dark', label: t('common.dark') },
        ]} />
      </div>
      <form className="login-card-centered" onSubmit={submit}>
        <div className="login-logo-wrap"><Logo /></div>
        <h2>{t('login.cardTitle')}</h2>
        <div className={`login-input-large ${error ? 'field-error' : ''}`}>
          <Icon name="key" size={20} />
          <input
            id="admin-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={t('login.passwordPlaceholder')}
            autoFocus
          />
        </div>
        {config.turnstile_enabled && config.turnstile_site_key && <TurnstileWidget key={challengeAttempt} siteKey={config.turnstile_site_key} theme={effectiveTheme} onToken={setTurnstileToken} onError={handleChallengeError} />}
        {error && <span className="form-error" role="alert">{error}</span>}
        <ActionButton wide plain disabled={busy || configLoading || configFailed || (config.turnstile_enabled && !turnstileToken)}>{busy ? t('login.submitting') : t('login.submit')}</ActionButton>
      </form>
    </main>
  )
}
