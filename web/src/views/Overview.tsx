import { useMemo, useState, type ReactNode } from 'react'
import type { AuditEvent, DashboardData, DomainRecord, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from '../components/Icon'
import { Bezel, EmptyState, IconButton, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'

interface Props {
  data: DashboardData
  onNavigate: (page: 'domains' | 'certificates' | 'nodes' | 'audit') => void
}

export function Overview({ data, onNavigate }: Props) {
  const { t } = usePreferences()
  const [query, setQuery] = useState('')
  const domains = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return data.domains.filter((domain) => !normalized || domain.name.includes(normalized) || domain.node_name.toLowerCase().includes(normalized))
  }, [data.domains, query])
  const onlineNodes = data.nodes.filter((node) => node.status === 'online' && node.nginx_healthy).length
  const expiring = data.certificates.filter((certificate) => certificate.status !== 'valid').length

  return (
    <div className="overview-page page-enter">
      <section className="overview-hero">
        <div><span className="page-kicker">ATLAS / STATUS</span><h1>{t('overview.title')}</h1><p>{t('overview.description')}</p></div>
      </section>
      <section className="mobile-status-strip" aria-label={t('overview.description')}>
        <div><StatusDot tone={onlineNodes === data.nodes.length && data.nodes.length ? 'good' : 'warning'} /><span>{t('overview.nodesOnline')}</span><strong>{onlineNodes} / {data.nodes.length}</strong><small>{onlineNodes === data.nodes.length ? t('overview.allNormal') : t('overview.checkNeeded')}</small></div>
        <div><StatusDot tone={expiring > 0 ? 'warning' : 'good'} /><span>{t('overview.certRisk')}</span><strong>{expiring}</strong><small>{expiring > 0 ? t('overview.within30') : t('overview.noRisk')}</small></div>
      </section>
      <div className="overview-grid">
        <div className="overview-primary">
          <Bezel className="domain-panel">
            <div className="panel-toolbar"><h2>{t('overview.routes')}</h2><div className="toolbar-actions"><label className="search-field"><Icon name="search" size={17} /><span className="sr-only">{t('overview.searchDomain')}</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('overview.searchDomain')} /></label><IconButton name="filter" label={t('common.search')} /></div></div>
            {domains.length > 0 ? <DomainTable domains={domains.slice(0, 6)} onOpen={() => onNavigate('domains')} /> : <EmptyState icon="globe" title={t('overview.noDomain')} description={query ? t('overview.adjustSearch') : t('overview.noDomainDescription')} />}
            {data.domains.length > 0 && <div className="panel-footer"><span>{t('overview.total', { count: data.domains.length })}</span><button className="text-link" onClick={() => onNavigate('domains')}>{t('overview.viewAll')} <Icon name="arrow" size={17} /></button></div>}
          </Bezel>
          <CertificateTimeline data={data} onOpen={() => onNavigate('certificates')} />
        </div>
        <aside className="overview-rail"><NodeHealth nodes={data.nodes} onOpen={() => onNavigate('nodes')} /><ActivityFeed events={data.audit} domains={data.domains} nodes={data.nodes} onOpen={() => onNavigate('audit')} /></aside>
      </div>
    </div>
  )
}

export function DomainTable({ domains, onOpen, showActions }: { domains: DomainRecord[]; onOpen?: (domain: DomainRecord) => void; showActions?: (domain: DomainRecord) => ReactNode }) {
  const { t } = usePreferences()
  return (
    <div className="domain-table" role="table" aria-label={t('nav.domains')}>
      <div className="domain-table-head" role="row"><span role="columnheader">{t('domain.columnDomain')}</span><span role="columnheader">{t('domain.columnRoute')}</span><span role="columnheader">{t('domain.columnCert')}</span><span role="columnheader">{t('domain.columnNode')}</span><span role="columnheader">{t('domain.columnState')}</span><span aria-hidden="true" /></div>
      {domains.map((domain) => {
        const certificate = certificateLabel(domain, t)
        const route = domain.upstream_host && domain.upstream_port ? `${domain.upstream_host}:${domain.upstream_port}` : '—'
        const runtime = domain.job_status === 'queued' ? t('domain.runtimeQueued') : domain.job_status === 'running' ? t('domain.runtimeRunning') : domain.job_status === 'failed' ? t('domain.runtimeFailed') : domain.enabled ? t('domain.runtimeActive') : t('domain.runtimePending')
        return <div className="domain-row" role="row" key={domain.id}><button className="domain-name" role="cell" onClick={() => onOpen?.(domain)}>{domain.name}{domain.observed_only && <small>{t('domain.localConfig')}</small>}</button><span className="route-target" role="cell">{route}<Icon name="link" size={14} /></span><span className={`certificate-cell certificate-${domain.certificate_status}`} role="cell"><StatusDot tone={certificate.tone} />{certificate.label}</span><span className="node-cell" role="cell"><Icon name="server" size={15} />{domain.node_name || t('domain.unconnected')}</span><span className="runtime-cell" role="cell"><StatusDot tone={domain.enabled && domain.job_status !== 'failed' ? 'good' : domain.job_status === 'failed' ? 'danger' : 'warning'} />{runtime}</span><span className="row-action" role="cell">{showActions?.(domain) ?? <IconButton name="more" label={domain.name} onClick={() => onOpen?.(domain)} />}</span></div>
      })}
    </div>
  )
}

function CertificateTimeline({ data, onOpen }: { data: DashboardData; onOpen: () => void }) {
  const { t } = usePreferences()
  const certificates = data.certificates.slice(0, 4)
  return <Bezel className="timeline-panel"><SectionHeading title={t('overview.timeline')} action={<span className="section-context">{t('overview.next90')}</span>} />{certificates.length === 0 ? <EmptyState icon="shield" title={t('overview.noCertificates')} description={t('overview.noCertificatesDescription')} /> : <div className="timeline-list">{certificates.map((certificate) => { const width = Math.max(6, Math.min(100, (certificate.days_remaining / 90) * 100)); return <div className="timeline-row" key={certificate.id}><div><Icon name="shield" size={17} /><span><strong>{certificate.domain}</strong><small>{certificateSource(certificate.source, t)}</small></span></div><div className="timeline-track"><span className={`timeline-fill timeline-${certificate.status}`} style={{ transform: `scaleX(${width / 100})` }} /></div><span className={`timeline-days timeline-${certificate.status}`}>{certificate.days_remaining > 0 ? t('common.days', { count: certificate.days_remaining }) : t('common.expired')}</span></div>})}</div>}<div className="panel-footer timeline-footer"><span className="timeline-legend"><StatusDot tone="good" />{t('common.valid')} <StatusDot tone="warning" />{t('common.expiring')} <StatusDot tone="danger" />{t('common.expired')}</span><button className="text-link" onClick={onOpen}>{t('overview.viewCertificates')} <Icon name="arrow" size={17} /></button></div></Bezel>
}

function NodeHealth({ nodes, onOpen }: { nodes: NodeRecord[]; onOpen: () => void }) {
  const { t } = usePreferences()
  return <Bezel className="node-health-panel"><SectionHeading title={t('overview.nodeHealth')} action={<button className="square-link" onClick={onOpen} aria-label={t('overview.viewNodes')}><Icon name="arrow" size={17} /></button>} />{nodes.length === 0 ? <EmptyState icon="server" title={t('overview.noNodes')} description={t('overview.noNodesDescription')} /> : <div className="node-health-list">{nodes.slice(0, 5).map((node) => <button className="node-health-row" key={node.id} onClick={onOpen}><StatusDot tone={node.status === 'online' && node.nginx_healthy ? 'good' : node.status === 'offline' ? 'danger' : 'warning'} /><span><strong>{node.name}</strong><small>{node.ip_addresses?.[0] ?? node.hostname ?? t('overview.waitingReport')}</small><small>{node.nginx_version || t('overview.nginxUndetected')}</small></span><span className={node.status === 'online' ? 'node-online' : 'node-offline'}>{node.status === 'online' ? t('common.online') : t('common.offline')}<strong>{node.nginx_healthy ? '100%' : '—'}</strong></span></button>)}</div>}{nodes.length > 0 && <button className="rail-link" onClick={onOpen}>{t('overview.viewNodes')} <Icon name="arrow" size={17} /></button>}</Bezel>
}

function ActivityFeed({ events, domains, nodes, onOpen }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[]; onOpen: () => void }) {
  const { t, locale, effectiveLanguage } = usePreferences()
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return <Bezel className="activity-panel"><SectionHeading title={t('overview.activity')} action={<button className="plain-link" onClick={onOpen}>{t('overview.viewAll')}</button>} />{events.length === 0 ? <EmptyState icon="log" title={t('overview.noActivity')} description={t('overview.noActivityDescription')} /> : <div className="activity-list">{events.slice(0, 6).map((event, index) => <button className="activity-row" key={event.id || `${event.action}-${index}`} onClick={onOpen}><StatusIcon tone={event.level === 'error' ? 'error' : event.level} /><span><strong>{effectiveLanguage === 'zh' ? event.message : event.action.replaceAll('.', ' · ')}</strong><small>{domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? ''] || event.action}</small></span><time>{relativeTime(event.created_at, locale)}</time></button>)}</div>}</Bezel>
}

function certificateSource(source: string, t: (key: string, variables?: Record<string, string | number>) => string): string {
  return t(source === 'acme' ? 'certificate.sourceACME' : source === 'upload' ? 'certificate.sourceUpload' : 'certificate.sourceLocal')
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
