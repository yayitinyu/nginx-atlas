import { useId, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react'
import { Icon, type IconName } from './Icon'
import { usePreferences } from '../preferences'

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand" aria-label="Nginx Atlas">
      <span className="brand-mark" aria-hidden="true" />
      {!compact && <span className="brand-word">ATLAS</span>}
    </div>
  )
}

export function Bezel({ children, className = '', ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`bezel ${className}`} {...props}>
      <div className="bezel-core">{children}</div>
    </div>
  )
}

type ActionButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: IconName
  tone?: 'primary' | 'quiet' | 'danger'
  wide?: boolean
}

export function ActionButton({ children, icon = 'arrow', tone = 'primary', wide, className = '', ...props }: ActionButtonProps) {
  return (
    <button className={`action-button action-${tone} ${wide ? 'action-wide' : ''} ${className}`} {...props}>
      <span>{children}</span>
      <span className="action-icon"><Icon name={icon} size={18} /></span>
    </button>
  )
}

export function IconButton({ name, label, className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { name: IconName; label: string }) {
  return (
    <button className={`icon-button ${className}`} aria-label={label} title={label} {...props}>
      <Icon name={name} size={19} />
    </button>
  )
}

export function StatusDot({ tone = 'muted' }: { tone?: 'good' | 'warning' | 'danger' | 'info' | 'muted' }) {
  return <span className={`status-dot status-${tone}`} aria-hidden="true" />
}

export function StatusIcon({ tone }: { tone: 'success' | 'warning' | 'info' | 'error' }) {
  const icon = tone === 'success' ? 'check' : tone === 'warning' || tone === 'error' ? 'warning' : 'info'
  return <span className={`status-icon status-icon-${tone}`}><Icon name={icon} size={17} /></span>
}

export function SectionHeading({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="section-heading">
      <h2>{title}</h2>
      {action}
    </div>
  )
}

export function EmptyState({ icon, title, description, action }: { icon: IconName; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon name={icon} size={27} /></span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  )
}

export function LoadingState({ label }: { label?: string }) {
  const { t } = usePreferences()
  return (
    <div className="loading-state" role="status">
      <span className="loading-orbit" />
      <span>{label ?? t('common.loading')}</span>
    </div>
  )
}

export interface ToastMessage {
  id: number
  tone: 'success' | 'error' | 'info'
  message: string
}

export function ToastRegion({ messages, dismiss }: { messages: ToastMessage[]; dismiss: (id: number) => void }) {
  const { t } = usePreferences()
  return (
    <div className="toast-region" aria-live="polite" aria-atomic="false">
      {messages.map((message) => (
        <div className={`toast toast-${message.tone}`} key={message.id}>
          <StatusIcon tone={message.tone === 'error' ? 'error' : message.tone} />
          <span>{message.message}</span>
          <IconButton name="close" label={t('common.close')} onClick={() => dismiss(message.id)} />
        </div>
      ))}
    </div>
  )
}

export function ConfirmDialog({ title, description, confirmLabel, open, onCancel, onConfirm, busy = false, tone = 'danger', icon = 'trash', busyLabel }: {
  title: string
  description: string
  confirmLabel: string
  open: boolean
  onCancel: () => void
  onConfirm: () => void
  busy?: boolean
  tone?: 'primary' | 'danger'
  icon?: IconName
  busyLabel?: string
}) {
  const { t } = usePreferences()
  const titleID = useId()
  if (!open) return null
  return (
    <div className="modal-layer" role="presentation" onMouseDown={(event) => event.currentTarget === event.target && !busy && onCancel()}>
      <div className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby={titleID}>
        <span className={`confirm-symbol confirm-symbol-${tone}`}><Icon name={tone === 'danger' ? 'warning' : icon} size={24} /></span>
        <h2 id={titleID}>{title}</h2>
        <p>{description}</p>
        <div className="confirm-actions">
          <button className="text-button" onClick={onCancel} disabled={busy}>{t('common.cancel')}</button>
          <ActionButton tone={tone} icon={icon} onClick={onConfirm} disabled={busy}>{busy ? busyLabel ?? t('common.saving') : confirmLabel}</ActionButton>
        </div>
      </div>
    </div>
  )
}

export function AdminAvatar({ compact = false }: { compact?: boolean }) {
  const { t } = usePreferences()
  return (
    <span className={compact ? 'admin-avatar admin-avatar-compact' : 'admin-avatar'} aria-label={t('app.admin')}>
      <span>A</span>
    </span>
  )
}
