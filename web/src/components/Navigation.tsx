import { Icon, type IconName } from './Icon'
import { Logo } from './Primitives'

export type PageKey = 'overview' | 'domains' | 'certificates' | 'nodes' | 'accounts' | 'audit' | 'settings'

const items: Array<{ key: PageKey; label: string; mobileLabel?: string; icon: IconName }> = [
  { key: 'overview', label: '概览', icon: 'overview', mobileLabel: '概览' },
  { key: 'domains', label: '域名与路由', icon: 'globe', mobileLabel: '域名' },
  { key: 'certificates', label: '证书', icon: 'shield', mobileLabel: '证书' },
  { key: 'nodes', label: '节点', icon: 'server', mobileLabel: '节点' },
  { key: 'accounts', label: 'DNS / ACME', icon: 'dns' },
  { key: 'audit', label: '审计日志', icon: 'log' },
  { key: 'settings', label: '设置', icon: 'settings', mobileLabel: '设置' },
]

export function NavigationRail({ page, onChange, onLogout }: { page: PageKey; onChange: (page: PageKey) => void; onLogout: () => void }) {
  return (
    <aside className="navigation-rail">
      <Logo />
      <nav aria-label="主导航">
        {items.map((item) => (
          <button key={item.key} className={page === item.key ? 'nav-item nav-active' : 'nav-item'} onClick={() => onChange(item.key)}>
            <Icon name={item.icon} size={21} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="rail-profile">
        <span className="avatar">A</span>
        <span className="profile-copy"><strong>admin</strong><small>超级管理员</small></span>
        <button className="profile-action" onClick={onLogout} aria-label="退出登录" title="退出登录"><Icon name="logout" size={19} /></button>
      </div>
    </aside>
  )
}

export function MobileHeader({ onMenu }: { onMenu: () => void }) {
  return (
    <header className="mobile-header">
      <Logo />
      <button className="mobile-menu-button" onClick={onMenu} aria-label="打开导航"><Icon name="menu" size={24} /></button>
    </header>
  )
}

export function MobileNavigation({ page, onChange }: { page: PageKey; onChange: (page: PageKey) => void }) {
  return (
    <nav className="mobile-navigation" aria-label="移动主导航">
      {items.filter((item) => item.mobileLabel).map((item) => (
        <button key={item.key} className={page === item.key ? 'mobile-nav-active' : ''} onClick={() => onChange(item.key)}>
          <Icon name={item.key === 'overview' ? 'home' : item.icon} size={22} />
          <span>{item.mobileLabel}</span>
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
  return (
    <div className={`mobile-menu-layer ${open ? 'mobile-menu-open' : ''}`} aria-hidden={!open}>
      <div className="mobile-menu-top"><Logo /><button onClick={onClose} aria-label="关闭导航"><Icon name="close" size={25} /></button></div>
      <nav>
        {items.map((item, index) => (
          <button
            key={item.key}
            className={page === item.key ? 'active' : ''}
            style={{ '--menu-index': index } as React.CSSProperties}
            onClick={() => { onChange(item.key); onClose() }}
          >
            <Icon name={item.icon} size={23} /><span>{item.label}</span><Icon name="arrow" size={21} />
          </button>
        ))}
      </nav>
      <button className="mobile-logout" onClick={onLogout}><Icon name="logout" size={20} />退出登录</button>
    </div>
  )
}
