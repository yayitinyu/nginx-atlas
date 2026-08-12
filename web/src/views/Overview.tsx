import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api'
import type { AuditEvent, DashboardData, DomainRecord, ManagementCommands, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from '../components/Icon'
import { Bezel, EmptyState, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'

interface Props {
  data: DashboardData
  onNavigate: (page: 'domains' | 'certificates' | 'nodes' | 'pending' | 'audit') => void
}

export function Overview({ data, onNavigate }: Props) {
  const { t } = usePreferences()
  const [commands, setCommands] = useState<ManagementCommands>()
  const [installCommand, setInstallCommand] = useState('')
  const [loadingCommand, setLoadingCommand] = useState(false)
  const [copied, setCopied] = useState('')
  const onlineNodes = data.nodes.filter((node) => node.status === 'online' && node.nginx_healthy).length
  const activeDomains = data.domains.filter((domain) => domain.enabled && domain.job_status !== 'failed').length
  const healthyCertificates = data.certificates.filter((certificate) => certificate.status === 'valid').length
  const riskDomains = useMemo(() => data.domains
    .filter((domain) => domain.certificate_status === 'expiring' || domain.certificate_status === 'expired')
    .sort((a, b) => new Date(a.certificate_expiry ?? 0).getTime() - new Date(b.certificate_expiry ?? 0).getTime()), [data.domains])

  useEffect(() => { void api.managementCommands().then(setCommands).catch(() => undefined) }, [])

  async function ensureInstallCommand() {
    if (installCommand || loadingCommand) return
    setLoadingCommand(true)
    try { setInstallCommand((await api.createEnrollment()).command) } finally { setLoadingCommand(false) }
  }

  function copy(value: string, key: string) {
    void navigator.clipboard.writeText(value)
    setCopied(key)
    window.setTimeout(() => setCopied((current) => current === key ? '' : current), 1800)
  }

  return (
    <div className="overview-page page-enter overview-focused">
      <section className="overview-hero compact-hero">
        <div><span className="page-kicker">{t('page.kickerStatus')}</span><h1>{t('overview.title')}</h1></div>
      </section>

      <section className="overview-stat-grid" aria-label={t('overview.title')}>
        <StatCard icon="server" label={t('overview.nodesOnline')} value={`${onlineNodes}/${data.nodes.length}`} tone={onlineNodes === data.nodes.length && data.nodes.length > 0 ? 'good' : 'warning'} onClick={() => onNavigate('nodes')} />
        <StatCard icon="globe" label={t('overview.activeRoutes')} value={activeDomains} tone="info" onClick={() => onNavigate('domains')} />
        <StatCard icon="shield" label={t('common.valid')} value={`${healthyCertificates}/${data.certificates.length}`} tone={healthyCertificates === data.certificates.length ? 'good' : 'warning'} onClick={() => onNavigate('certificates')} />
        <StatCard icon="warning" label={t('overview.pending')} value={data.pending_job_count} tone={data.pending_job_count > 0 ? 'warning' : 'muted'} onClick={() => onNavigate('pending')} />
      </section>

      <div className="overview-focus-grid">
        <ActivityFeed events={data.audit} domains={data.domains} nodes={data.nodes} onOpen={() => onNavigate('audit')} />
        <div className="overview-side-stack">
          {riskDomains.length > 0 && (
            <Bezel className="expiry-alert-panel">
              <SectionHeading title={t('overview.expiringDomains')} action={<span className="risk-count">{riskDomains.length}</span>} />
              <div className="expiry-domain-list">
                {riskDomains.slice(0, 5).map((domain) => (
                  <button type="button" key={domain.id} onClick={() => onNavigate('domains')}>
                    <StatusIcon tone={domain.certificate_status === 'expired' ? 'error' : 'warning'} />
                    <span><strong>{domain.name}</strong><small>{certificateLabel(domain, t).label}</small></span>
                    <Icon name="chevron" size={16} />
                  </button>
                ))}
              </div>
            </Bezel>
          )}

          <Bezel className="command-center-panel">
            <SectionHeading title={t('overview.commands')} />
            <div className="command-accordion">
              <CommandDetails icon="plus" title={t('overview.installNode')} onOpen={() => void ensureInstallCommand()} command={installCommand} loading={loadingCommand} copied={copied === 'install'} onCopy={() => copy(installCommand, 'install')} />
              <CommandDetails icon="server" title={t('overview.uninstallNode')} command={commands?.uninstall_node ?? ''} copied={copied === 'node'} onCopy={() => copy(commands?.uninstall_node ?? '', 'node')} />
              <CommandDetails icon="warning" title={t('overview.uninstallController')} command={commands?.uninstall_controller ?? ''} warning={t('overview.uninstallControllerWarning')} copied={copied === 'controller'} onCopy={() => copy(commands?.uninstall_controller ?? '', 'controller')} />
            </div>
          </Bezel>
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon, label, value, tone, onClick }: { icon: 'server' | 'globe' | 'shield' | 'warning'; label: string; value: string | number; tone: 'good' | 'warning' | 'info' | 'muted'; onClick: () => void }) {
  return <button type="button" className={`overview-stat stat-${tone}`} onClick={onClick}><span><Icon name={icon} size={20} /></span><strong>{value}</strong><small>{label}</small></button>
}

function CommandDetails({ icon, title, command, loading, warning, copied, onOpen, onCopy }: { icon: 'plus' | 'server' | 'warning'; title: string; command: string; loading?: boolean; warning?: string; copied: boolean; onOpen?: () => void; onCopy: () => void }) {
  const { t } = usePreferences()
  return (
    <details onToggle={(event) => event.currentTarget.open && onOpen?.()}>
      <summary><span><Icon name={icon} size={17} />{title}</span><Icon name="chevron" size={16} /></summary>
      <div className="overview-command-body">
        {warning && <p className="command-warning"><Icon name="warning" size={16} />{warning}</p>}
        {loading ? <span className="loading-inline"><i className="loading-orbit" />{t('common.loading')}</span> : command ? <><pre>{command}</pre><button type="button" onClick={onCopy}><Icon name={copied ? 'check' : 'copy'} size={16} />{copied ? t('dialog.copied') : t('dialog.copyCommand')}</button></> : <span className="loading-inline">{t('common.loading')}</span>}
      </div>
    </details>
  )
}

export function DomainTable({ domains, onOpen, showActions, padEmpty }: { domains: DomainRecord[]; onOpen?: (domain: DomainRecord) => void; showActions?: (domain: DomainRecord) => ReactNode; padEmpty?: boolean }) {
  const { t } = usePreferences()
  return (
    <div className={`domain-table ${showActions ? 'domain-table-actions' : ''}`} role="table" aria-label={t('nav.domains')}>
      <div className="domain-table-head" role="row"><span>{t('domain.columnDomain')}</span><span>{t('domain.columnRoute')}</span><span>{t('domain.columnCert')}</span><span>{t('domain.columnNode')}</span><span>{t('domain.columnState')}</span><span /></div>
      {domains.map((domain) => {
        const certificate = certificateLabel(domain, t)
        const runtime = domain.job_status === 'queued' ? t('domain.runtimeQueued') : domain.job_status === 'running' ? t('domain.runtimeRunning') : domain.job_status === 'failed' ? t('domain.runtimeFailed') : domain.enabled ? t('domain.runtimeActive') : t('domain.runtimePending')
        return <div className="domain-row" role="row" key={domain.id}>
          <button type="button" className="domain-name" role="cell" onClick={() => onOpen?.(domain)}>{domain.name}{domain.observed_only && <small>{t('domain.localConfig')}</small>}{domain.taken_over && <small>{t('domain.takenOverBadge')}</small>}</button>
          <span className="route-target" role="cell">{domain.upstream_host && domain.upstream_port ? `${domain.upstream_host}:${domain.upstream_port}` : '—'}</span>
          <span className={`certificate-cell certificate-${domain.certificate_status}`} role="cell"><StatusDot tone={certificate.tone} />{certificate.label}</span>
          <span className="node-cell" role="cell"><Icon name="server" size={15} />{domain.node_name || t('domain.unconnected')}</span>
          <span className="runtime-cell" role="cell"><StatusDot tone={domain.enabled && domain.job_status !== 'failed' ? 'good' : domain.job_status === 'failed' ? 'danger' : 'warning'} />{runtime}</span>
          <span className="row-action" role="cell">{showActions?.(domain)}</span>
        </div>
      })}
      {padEmpty && Array.from({ length: Math.max(0, 4 - domains.length) }).map((_, index) => <div className="domain-row placeholder-row" role="row" key={`empty-${index}`} />)}
    </div>
  )
}

function ActivityFeed({ events, domains, nodes, onOpen }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[]; onOpen: () => void }) {
  const { t, locale, effectiveLanguage } = usePreferences()
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return (
    <Bezel className="activity-panel overview-activity-panel">
      <SectionHeading title={t('overview.activity')} action={<button type="button" className="plain-link" onClick={onOpen}>{t('overview.viewAll')}</button>} />
      {events.length === 0 ? (
        <EmptyState icon="log" title={t('overview.noActivity')} description={t('overview.noActivityDescription')} />
      ) : (
        <div className="activity-list">
          {events.slice(0, 8).map((event, index) => {
            const context = domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? '']
            return (
              <button type="button" className="activity-row" key={event.id || `${event.action}-${index}`} onClick={onOpen}>
                <StatusIcon tone={event.level === 'error' ? 'error' : event.level} />
                <span>
                  <strong>{effectiveLanguage === 'zh' ? event.message : event.action.replaceAll('.', ' · ')}</strong>
                  {context && <small>{context}</small>}
                </span>
                <time>{relativeTime(event.created_at, locale)}</time>
              </button>
            )
          })}
        </div>
      )}
    </Bezel>
  )
}

function certificateLabel(domain: DomainRecord, t: (key: string, variables?: Record<string, string | number>) => string): { label: string; tone: 'good' | 'warning' | 'danger' | 'muted' } {
  if (!domain.certificate_expiry) return { label: domain.certificate_mode ? t('domain.certPending') : t('domain.httpOnlyShort'), tone: 'muted' }
  const days = Math.ceil((new Date(domain.certificate_expiry).getTime() - Date.now()) / 86_400_000)
  if (days <= 0) return { label: t('common.expired'), tone: 'danger' }
  if (days <= 30) return { label: t('certificate.remaining', { count: days }), tone: 'warning' }
  return { label: t('common.valid'), tone: 'good' }
}

export function relativeTime(value: string, locale = 'zh-CN'): string {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  if (Math.abs(seconds) < 60) return formatter.format(seconds, 'second')
  if (Math.abs(seconds) < 3600) return formatter.format(Math.round(seconds / 60), 'minute')
  if (Math.abs(seconds) < 86400) return formatter.format(Math.round(seconds / 3600), 'hour')
  return formatter.format(Math.round(seconds / 86400), 'day')
}
