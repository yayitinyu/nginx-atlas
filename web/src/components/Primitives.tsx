import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react'
import { Icon, type IconName } from './Icon'

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand" aria-label="Nginx Atlas">
      <svg className="brand-mark" viewBox="0 0 44 48" aria-hidden="true">
        <path d="M22 2 41 13v22L22 46 3 35V13L22 2Z" />
        <path d="M13 33V15l18 18V15" />
      </svg>
      {!compact && <span>Nginx Atlas</span>}
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

export function LoadingState({ label = '正在读取基础设施状态' }: { label?: string }) {
  return (
    <div className="loading-state" role="status">
      <span className="loading-orbit" />
      <span>{label}</span>
    </div>
  )
}

export interface ToastMessage {
  id: number
  tone: 'success' | 'error' | 'info'
  message: string
}

export function ToastRegion({ messages, dismiss }: { messages: ToastMessage[]; dismiss: (id: number) => void }) {
  return (
    <div className="toast-region" aria-live="polite" aria-atomic="false">
      {messages.map((message) => (
        <div className={`toast toast-${message.tone}`} key={message.id}>
          <StatusIcon tone={message.tone === 'error' ? 'error' : message.tone} />
          <span>{message.message}</span>
          <IconButton name="close" label="关闭提示" onClick={() => dismiss(message.id)} />
        </div>
      ))}
    </div>
  )
}

export function ConfirmDialog({ title, description, confirmLabel, open, onCancel, onConfirm, busy = false }: {
  title: string
  description: string
  confirmLabel: string
  open: boolean
  onCancel: () => void
  onConfirm: () => void
  busy?: boolean
}) {
  if (!open) return null
  return (
    <div className="modal-layer" role="presentation" onMouseDown={(event) => event.currentTarget === event.target && onCancel()}>
      <div className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <span className="confirm-symbol"><Icon name="warning" size={24} /></span>
        <h2 id="confirm-title">{title}</h2>
        <p>{description}</p>
        <div className="confirm-actions">
          <button className="text-button" onClick={onCancel} disabled={busy}>取消</button>
          <ActionButton tone="danger" icon="trash" onClick={onConfirm} disabled={busy}>{busy ? '处理中' : confirmLabel}</ActionButton>
        </div>
      </div>
    </div>
  )
}
