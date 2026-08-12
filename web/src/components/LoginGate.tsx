import { useEffect, useState, type FormEvent } from 'react'
import { usePreferences, type LanguageMode, type ThemeMode } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, Logo } from './Primitives'
import { SelectField } from './SelectField'

export function LoginGate({ onLogin }: { onLogin: (password: string) => Promise<void> }) {
  const { t, effectiveTheme, effectiveLanguage, setTheme, setLanguage } = usePreferences()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    document.body.classList.add('login-active')
    return () => document.body.classList.remove('login-active')
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (password.length < 12) {
      setError(t('login.tooShort'))
      return
    }
    setBusy(true)
    setError('')
    try {
      await onLogin(password)
    } catch {
      setError(t('login.invalid'))
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
        {error && <span className="form-error" role="alert">{error}</span>}
        <ActionButton wide plain disabled={busy}>{busy ? t('login.submitting') : t('login.submit')}</ActionButton>
      </form>
    </main>
  )
}
