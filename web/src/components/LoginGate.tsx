import { useState, type FormEvent } from 'react'
import { usePreferences, type LanguageMode, type ThemeMode } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, Logo } from './Primitives'
import { SelectField } from './SelectField'

export function LoginGate({ onLogin }: { onLogin: (password: string) => Promise<void> }) {
  const { t, theme, language, setTheme, setLanguage } = usePreferences()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

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
    <main className="login-screen">
      <div className="login-preferences">
        <SelectField ariaLabel={t('app.language')} value={language} onChange={(value) => setLanguage(value as LanguageMode)} icon="language" options={[
          { value: 'system', label: t('common.system') }, { value: 'zh', label: t('common.chinese') }, { value: 'en', label: t('common.english') },
        ]} />
        <SelectField ariaLabel={t('app.theme')} value={theme} onChange={(value) => setTheme(value as ThemeMode)} icon={theme === 'light' ? 'sun' : theme === 'dark' ? 'moon' : 'system'} options={[
          { value: 'system', label: t('common.system') }, { value: 'light', label: t('common.light') }, { value: 'dark', label: t('common.dark') },
        ]} />
      </div>
      <section className="login-copy">
        <Logo />
        <span className="login-eyebrow">{t('login.eyebrow')}</span>
        <h1>{t('login.title').split('\n').map((line) => <span key={line}>{line}</span>)}</h1>
        <p>{t('login.description')}</p>
      </section>
      <div className="login-shell">
        <form className="login-card" onSubmit={submit}>
          <span className="login-key"><Icon name="lock" size={25} weight="light" /></span>
          <h2>{t('login.cardTitle')}</h2>
          <p>{t('login.cardDescription')}</p>
          <label htmlFor="admin-password">{t('login.password')}</label>
          <div className={`login-input ${error ? 'field-error' : ''}`}>
            <Icon name="key" size={18} />
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
          <ActionButton wide disabled={busy}>{busy ? t('login.submitting') : t('login.submit')}</ActionButton>
          <small className="login-security"><Icon name="shield" size={15} />{t('login.secure')}</small>
        </form>
      </div>
    </main>
  )
}
