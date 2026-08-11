import type { CSSProperties } from 'react'
import { usePreferences, type LanguageMode, type ThemeMode } from '../preferences'
import { Icon, type IconName } from './Icon'
import { Logo } from './Primitives'
import { SelectField } from './SelectField'

export type PageKey = 'overview' | 'domains' | 'certificates' | 'nodes' | 'accounts' | 'audit' | 'settings'

const items: Array<{ key: PageKey; labelKey: string; mobileLabelKey?: string; icon: IconName }> = [
  { key: 'overview', labelKey: 'nav.overview', icon: 'overview', mobileLabelKey: 'nav.overview' },
  { key: 'domains', labelKey: 'nav.domains', icon: 'globe', mobileLabelKey: 'nav.domainsShort' },
  { key: 'certificates', labelKey: 'nav.certificates', icon: 'shield', mobileLabelKey: 'nav.certificates' },
  { key: 'nodes', labelKey: 'nav.nodes', icon: 'server', mobileLabelKey: 'nav.nodes' },
  { key: 'accounts', labelKey: 'nav.accounts', icon: 'dns' },
  { key: 'audit', labelKey: 'nav.audit', icon: 'log' },
  { key: 'settings', labelKey: 'nav.settings', icon: 'settings', mobileLabelKey: 'nav.settings' },
]

export function NavigationRail({ page, onChange, onLogout }: { page: PageKey; onChange: (page: PageKey) => void; onLogout: () => void }) {
  const { t } = usePreferences()
  return (
    <aside className="navigation-rail">
      <Logo />
      <nav aria-label={t('nav.main')}>
        {items.map((item) => (
          <button key={item.key} className={page === item.key ? 'nav-item nav-active' : 'nav-item'} onClick={() => onChange(item.key)}>
            <Icon name={item.icon} size={21} />
            <span>{t(item.labelKey)}</span>
          </button>
        ))}
      </nav>
      <div className="rail-profile">
        <span className="rail-health" title={t('app.allHealthy')}><span className="pulse-dot" /></span>
        <button className="profile-action profile-logout" onClick={onLogout} aria-label={t('app.logout')} title={t('app.logout')}>
          <Icon name="logout" size={19} />
          <span>{t('app.logout')}</span>
        </button>
      </div>
    </aside>
  )
}

export function MobileHeader({ onMenu }: { onMenu: () => void }) {
  const { t } = usePreferences()
  return (
    <header className="mobile-header">
      <Logo />
      <button className="mobile-menu-button" onClick={onMenu} aria-label={t('nav.open')}><Icon name="menu" size={24} /></button>
    </header>
  )
}

export function MobileNavigation({ page, onChange }: { page: PageKey; onChange: (page: PageKey) => void }) {
  const { t } = usePreferences()
  return (
    <nav className="mobile-navigation" aria-label={t('nav.mobile')}>
      {items.filter((item) => item.mobileLabelKey).map((item) => (
        <button key={item.key} className={page === item.key ? 'mobile-nav-active' : ''} onClick={() => onChange(item.key)}>
          <Icon name={item.key === 'overview' ? 'home' : item.icon} size={22} />
          <span>{t(item.mobileLabelKey!)}</span>
        </button>
      ))}
    </nav>
  )
}

export function MobileMenu({ open, page, onChange, onClose, onLogout }: {
  open: boolean
  page: PageKey
  onChange: (page: PageKey) => void
  onClose: () => void
  onLogout: () => void
}) {
  const { t, theme, language, setTheme, setLanguage } = usePreferences()
  if (!open) return null
  return (
    <div className="mobile-menu-layer mobile-menu-open" onMouseDown={(event) => event.currentTarget === event.target && onClose()}>
      <aside className="mobile-menu-compact">
        <div className="mobile-menu-top">
          <strong>{t('settings.quickPreferences')}</strong>
          <button onClick={onClose} aria-label={t('nav.close')}><Icon name="close" size={20} /></button>
        </div>
        <div className="mobile-menu-body">
          <SelectField ariaLabel={t('app.language')} value={language} onChange={(value) => setLanguage(value as LanguageMode)} icon="language" options={[{ value: 'system', label: t('common.system') }, { value: 'zh', label: t('common.chinese') }, { value: 'en', label: t('common.english') }]} />
          <SelectField ariaLabel={t('app.theme')} value={theme} onChange={(value) => setTheme(value as ThemeMode)} icon={theme === 'light' ? 'sun' : theme === 'dark' ? 'moon' : 'system'} options={[{ value: 'system', label: t('common.system') }, { value: 'light', label: t('common.light') }, { value: 'dark', label: t('common.dark') }]} />
          <button className="compact-menu-item" onClick={() => { onChange('audit'); onClose() }}>
            <Icon name="log" size={18} /><span>{t('nav.audit')}</span>
          </button>
          <button className="compact-menu-item logout-item" onClick={onLogout}>
            <Icon name="logout" size={18} /><span>{t('app.logout')}</span>
          </button>
        </div>
      </aside>
    </div>
  )
}
