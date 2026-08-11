import { useMemo, useState } from 'react'
import type { ACMEAccount, AuditEvent, CertificateRecord, DNSAccount, DomainRecord, NginxSiteMeta, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from '../components/Icon'
import { ActionButton, Bezel, EmptyState, IconButton, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'
import { SelectField } from '../components/SelectField'
import { DomainTable, relativeTime } from './Overview'

interface DiscoveredSite { node: NodeRecord; site: NginxSiteMeta }

export function DomainsPage({ domains, nodes, onAdd, onEdit, onDelete, onAdopt }: {
  domains: DomainRecord[]
  nodes: NodeRecord[]
  onAdd: () => void
  onEdit: (domain: DomainRecord) => void
  onDelete: (domain: DomainRecord) => void
  onAdopt: (node: NodeRecord, site: NginxSiteMeta, takeover: boolean) => void
}) {
  const { t } = usePreferences()
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState<'managed' | 'discovered'>('managed')
  const normalized = query.trim().toLowerCase()
  const filtered = useMemo(() => domains.filter((domain) => !normalized || domain.name.includes(normalized) || domain.node_name.toLowerCase().includes(normalized) || `${domain.upstream_host}:${domain.upstream_port}`.includes(normalized)), [domains, normalized])
  const discovered = useMemo<DiscoveredSite[]>(() => {
    const managedNames = new Set(domains.map((domain) => domain.name))
    return nodes.flatMap((node) => (node.nginx_sites ?? []).map((site) => ({ node, site }))).filter(({ node, site }) => !managedNames.has(site.domain) && (!normalized || site.domain.includes(normalized) || node.name.toLowerCase().includes(normalized) || `${site.upstream_host}:${site.upstream_port}`.includes(normalized)))
  }, [domains, nodes, normalized])
  return <div className="content-page page-enter"><PageHeader title={t('domain.title')} description={t('domain.description')} action={<ActionButton icon="plus" onClick={onAdd}>{t('domain.add')}</ActionButton>} /><Bezel className="operation-panel"><div className="panel-toolbar"><div className="toolbar-tabs"><button className={tab === 'managed' ? 'active' : ''} onClick={() => setTab('managed')}>{t('domain.managedTab')} <small>{domains.length}</small></button><button className={tab === 'discovered' ? 'active' : ''} onClick={() => setTab('discovered')}>{t('domain.discoveredTab')} <small>{discovered.length}</small></button></div><label className="search-field"><Icon name="search" size={17} /><span className="sr-only">{t('common.search')}</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('domain.searchPlaceholder')} /></label></div>{tab === 'managed' ? (filtered.length ? <DomainTable domains={filtered} onOpen={onEdit} showActions={(domain) => <div className="domain-row-actions"><IconButton name="edit" label={`${t('common.edit')} ${domain.name}`} onClick={() => onEdit(domain)} /><IconButton name="trash" label={`${t('common.delete')} ${domain.name}`} onClick={() => onDelete(domain)} /></div>} /> : <EmptyState icon="globe" title={t('domain.empty')} description={t('domain.emptyDescription')} action={<button className="inline-action" onClick={onAdd}><Icon name="plus" size={17} />{t('domain.add')}</button>} />) : <DiscoveredSites sites={discovered} onAdopt={onAdopt} />}<div className="panel-footer"><span>{tab === 'managed' ? t('domain.showing', { shown: filtered.length, total: domains.length }) : t('overview.total', { count: discovered.length })}</span><span className="footer-note"><Icon name="terminal" size={15} />{tab === 'managed' ? t('domain.transactionNote') : 'nginx -T'}</span></div></Bezel></div>
}

function DiscoveredSites({ sites, onAdopt }: { sites: DiscoveredSite[]; onAdopt: (node: NodeRecord, site: NginxSiteMeta, takeover: boolean) => void }) {
  const { t } = usePreferences()
  if (!sites.length) return <EmptyState icon="cloud-download" title={t('domain.noDiscovered')} description={t('domain.noDiscoveredDescription')} />
  return <div className="discovered-sites"><div className="discovered-intro"><Icon name="eye" size={22} /><span><strong>{t('domain.discoveredTitle')}</strong><small>{t('domain.discoveredDescription')}</small></span></div>{sites.map(({ node, site }) => {
    const canTakeOver = Boolean(site.config_path && site.upstream_host && site.upstream_port && !site.managed_by_atlas)
    return <article className="discovered-row" key={`${node.id}-${site.config_path}-${site.domain}`}><span className="discovered-state"><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /></span><span className="discovered-domain"><strong>{site.domain}</strong><small>{site.config_path || 'nginx -T'}</small></span><span className="discovered-route"><small>{t('domain.columnRoute')}</small><strong>{site.upstream_host && site.upstream_port ? `${site.upstream_host}:${site.upstream_port}` : '—'}</strong></span><span className="discovered-route"><small>{t('domain.columnNode')}</small><strong>{node.name}</strong></span><span className="site-badges"><i>{site.tls ? t('domain.tls') : t('domain.http')}</i>{site.managed_by_atlas && <i>{t('domain.managedConfig')}</i>}</span><span className="discovered-actions"><button className="inline-action quiet-action" onClick={() => onAdopt(node, site, false)}><Icon name="eye" size={16} />{t('domain.observe')}</button><button className="inline-action" disabled={!canTakeOver} title={!canTakeOver ? t('domain.takeoverUnavailable') : t('domain.takeover')} onClick={() => onAdopt(node, site, true)}><Icon name="download" size={16} />{t('domain.takeover')}</button></span></article>
  })}</div>
}

export function CertificatesPage({ certificates, nodes, onAdd, onRenew, onToggleAutoRenew, onSync, onEdit, busy }: {
  certificates: CertificateRecord[]
  nodes: NodeRecord[]
  onAdd: () => void
  onRenew: (certificate: CertificateRecord) => void
  onToggleAutoRenew: (certificate: CertificateRecord, enabled: boolean) => void
  onSync: (certificate: CertificateRecord) => void
  onEdit: (certificate: CertificateRecord) => void
  busy: string
}) {
  const { t, locale } = usePreferences()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<'all' | 'valid' | 'risk'>('all')
  const normalized = query.trim().toLowerCase()
  const filtered = certificates.filter((certificate) => (!normalized || certificate.domain.includes(normalized) || certificate.issuer.toLowerCase().includes(normalized) || certificate.fingerprint_sha256.toLowerCase().includes(normalized)) && (status === 'all' || status === 'valid' && certificate.status === 'valid' || status === 'risk' && certificate.status !== 'valid'))
  const expiring = certificates.filter((certificate) => certificate.status !== 'valid').length
  const autoRenew = certificates.filter((certificate) => certificate.auto_renew).length
  const copies = certificates.reduce((total, certificate) => total + certificate.deployed_node_ids.length, 0)
  return <div className="content-page page-enter"><PageHeader title={t('certificate.title')} description={t('certificate.description')} action={<ActionButton icon="plus" onClick={onAdd}>{t('certificate.add')}</ActionButton>} /><div className="certificate-summary"><SummaryMetric icon="shield" label={t('certificate.total')} value={certificates.length} /><SummaryMetric icon="warning" label={t('certificate.expiringCount')} value={expiring} warning={expiring > 0} /><SummaryMetric icon="refresh" label={t('certificate.autoRenewCount')} value={autoRenew} /><SummaryMetric icon="server" label={t('certificate.nodeCopies')} value={copies} /></div><Bezel className="operation-panel certificate-list-panel"><div className="panel-toolbar certificate-toolbar"><label className="search-field certificate-search"><Icon name="search" size={17} /><span className="sr-only">{t('common.search')}</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('certificate.searchPlaceholder')} /></label><SelectField ariaLabel={t('certificate.allStatuses')} value={status} onChange={(value) => setStatus(value as typeof status)} icon="filter" options={[{ value: 'all', label: t('certificate.allStatuses') }, { value: 'valid', label: t('certificate.validOnly') }, { value: 'risk', label: t('certificate.expiringOnly') }]} /></div><div className="certificate-list-head"><span>{t('domain.columnDomain')}</span><span>{t('certificate.source')}</span><span>{t('certificate.expiry')}</span><span>{t('certificate.autoRenew')}</span><span>{t('certificate.distribution')}</span><span /></div>{filtered.length === 0 ? <EmptyState icon="shield" title={t('certificate.empty')} description={t('certificate.emptyDescription')} action={<button className="inline-action" onClick={onAdd}><Icon name="plus" size={17} />{t('certificate.add')}</button>} /> : filtered.map((certificate) => {
    const automationReady = Boolean(certificate.issuer_node_id && certificate.acme_account_id && certificate.dns_account_id && nodes.some((node) => node.id === certificate.issuer_node_id && node.status !== 'revoked'))
    const toggling = busy === `auto-renew-${certificate.id}`
    const renewing = busy === `renew-${certificate.id}`
    const switchLabel = t(certificate.auto_renew ? 'certificate.disableAutoRenew' : 'certificate.enableAutoRenew', { domain: certificate.domain })
    return <div className="certificate-list-row" key={certificate.id}><span className="cert-identity"><StatusIcon tone={certificate.status === 'valid' ? 'success' : certificate.status === 'expiring' ? 'warning' : 'error'} /><span><strong>{certificate.domain}</strong><small title={certificate.fingerprint_sha256}>{certificate.issuer || '—'} · {t('certificate.namesCount', { count: certificate.dns_names.length })}</small></span></span><span className="source-label">{certificateSource(certificate.source, t)}</span><span className={`expiry-label expiry-${certificate.status}`}><strong>{certificate.days_remaining > 0 ? t('certificate.remaining', { count: certificate.days_remaining }) : t('common.expired')}</strong><small>{formatDate(certificate.not_after, locale)}</small></span><span className="renewal-state"><button type="button" role="switch" aria-checked={certificate.auto_renew} aria-label={switchLabel} title={!certificate.auto_renew && !automationReady ? t('certificate.automationUnavailable') : switchLabel} className={certificate.auto_renew ? 'certificate-renew-switch switch-on' : 'certificate-renew-switch'} disabled={toggling || (!certificate.auto_renew && !automationReady)} onClick={() => onToggleAutoRenew(certificate, !certificate.auto_renew)}><i /></button><span>{toggling ? t('common.saving') : certificate.auto_renew ? t('certificate.enabled') : t('certificate.disabled')}</span></span><span className="deployed-count"><strong>{certificate.deployed_node_ids.length}</strong> / {nodes.length}</span><span className="certificate-actions"><button onClick={() => onEdit(certificate)}><Icon name="edit" size={16} />{t('common.edit')}</button><button disabled={renewing || !automationReady} onClick={() => onRenew(certificate)}><Icon name="refresh" size={16} />{t('certificate.renew')}</button><button disabled={Boolean(busy)} onClick={() => onSync(certificate)}><Icon name="upload" size={16} />{t('certificate.sync')}</button></span></div>
  })}</Bezel></div>
}

function SummaryMetric({ icon, label, value, warning = false }: { icon: 'shield' | 'warning' | 'refresh' | 'server'; label: string; value: number; warning?: boolean }) {
  return <div className={warning ? 'summary-metric summary-warning' : 'summary-metric'}><span><Icon name={icon} size={19} /></span><strong>{value}</strong><small>{label}</small></div>
}

export function NodesPage({ nodes, onAdd, onRevoke, onManage }: { nodes: NodeRecord[]; onAdd: () => void; onRevoke: (node: NodeRecord) => void; onManage: (node: NodeRecord) => void }) {
  const { t, locale } = usePreferences()
  return <div className="content-page page-enter"><PageHeader title={t('nodes.title')} description={t('nodes.description')} action={<ActionButton icon="plus" onClick={onAdd}>{t('nodes.add')}</ActionButton>} /><div className="nodes-canvas">{nodes.length === 0 ? <Bezel><EmptyState icon="server" title={t('nodes.empty')} description={t('nodes.emptyDescription')} action={<button className="inline-action" onClick={onAdd}><Icon name="terminal" size={17} />{t('nodes.command')}</button>} /></Bezel> : nodes.map((node) => <Bezel className="node-detail" key={node.id}><div className="node-detail-top"><span className="node-machine"><Icon name="server" size={22} /></span><span><span className="node-name-line"><strong>{node.name}</strong>{node.controller_installed && <span className="controller-badge"><Icon name="home" size={13} />{t('nodes.controller')}</span>}</span><small>{node.hostname || t('nodes.hostnamePending')}</small></span><span className={`node-state node-state-${node.status}`}><StatusDot tone={node.status === 'online' && node.nginx_healthy ? 'good' : node.status === 'offline' ? 'danger' : 'warning'} />{t(`common.${node.status}`)}</span></div><div className="node-specs"><span><small>{t('nodes.addresses')}</small><strong>{node.ip_addresses?.join(' · ') || '—'}</strong></span><span><small>{t('nodes.nginx')}</small><strong>{node.nginx_version || t('overview.nginxUndetected')}</strong></span><span><small>{t('nodes.platform')}</small><strong>{node.os_name || [node.os, node.arch].filter(Boolean).join(' / ') || '—'}</strong></span><span><small>{t('nodes.certDirectory')}</small><strong>{t('nodes.certFound', { count: node.certificates?.length ?? 0 })} · {t('nodes.siteFound', { count: node.nginx_sites?.length ?? 0 })}</strong></span></div><div className="node-detail-footer"><span><Icon name="clock" size={15} />{t('nodes.lastSeen', { time: node.last_seen_at ? relativeTime(node.last_seen_at, locale) : t('nodes.never') })}</span><span className="node-card-actions"><button className="inline-action" onClick={() => onManage(node)}><Icon name="settings" size={16} />{t('nodes.manage')}</button>{node.status !== 'revoked' && <button className="danger-link" onClick={() => onRevoke(node)}><Icon name="trash" size={15} />{t('nodes.revoke')}</button>}</span></div></Bezel>)}</div></div>
}

export function AccountsPage({ dnsAccounts, acmeAccounts, onAddDNS, onAddACME, onEditDNS, onEditACME }: {
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDNS: () => void
  onAddACME: () => void
  onEditDNS: (account: DNSAccount) => void
  onEditACME: (account: ACMEAccount) => void
}) {
  const { t } = usePreferences()
  return <div className="content-page page-enter"><PageHeader title={t('accounts.title')} description={t('accounts.description')} /><div className="account-split"><Bezel className="account-panel"><SectionHeading title={t('accounts.dnsTitle')} action={<IconButton name="plus" label={t('accounts.addDNS')} onClick={onAddDNS} />} />{dnsAccounts.length === 0 ? <EmptyState icon="dns" title={t('accounts.emptyDNS')} description={t('accounts.emptyDNSDescription')} action={<button className="inline-action" onClick={onAddDNS}><Icon name="plus" size={17} />{t('accounts.addDNS')}</button>} /> : <div className="account-list">{dnsAccounts.map((account) => <button className="account-row" key={account.id} onClick={() => onEditDNS(account)}><span className="account-icon"><Icon name="dns" size={20} /></span><span><strong>{account.name}</strong><small>{account.provider}</small></span><span className="credential-keys">{t('accounts.credentials', { count: account.credential_keys.length })}</span><Icon name="edit" size={17} /></button>)}</div>}</Bezel><Bezel className="account-panel"><SectionHeading title={t('accounts.acmeTitle')} action={<IconButton name="plus" label={t('accounts.addACME')} onClick={onAddACME} />} />{acmeAccounts.length === 0 ? <EmptyState icon="key" title={t('accounts.emptyACME')} description={t('accounts.emptyACMEDescription')} action={<button className="inline-action" onClick={onAddACME}><Icon name="plus" size={17} />{t('accounts.addACME')}</button>} /> : <div className="account-list">{acmeAccounts.map((account) => <button className="account-row" key={account.id} onClick={() => onEditACME(account)}><span className="account-icon"><Icon name="key" size={20} /></span><span><strong>{account.name}</strong><small>{account.email}</small></span><span className="credential-keys">{account.has_eab ? t('accounts.eab') : t('accounts.standard')}</span><Icon name="edit" size={17} /></button>)}</div>}</Bezel></div></div>
}

export function AuditPage({ events, domains, nodes }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[] }) {
  const { t, locale, effectiveLanguage } = usePreferences()
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return <div className="content-page page-enter"><PageHeader title={t('audit.title')} description={t('audit.description')} /><Bezel className="operation-panel audit-panel"><div className="audit-head"><span>{t('audit.event')}</span><span>{t('audit.target')}</span><span>{t('audit.time')}</span><span>{t('audit.level')}</span></div>{events.length === 0 ? <EmptyState icon="log" title={t('audit.empty')} description={t('audit.emptyDescription')} /> : events.map((event, index) => <div className="audit-row" key={event.id || `${event.action}-${index}`}><span><StatusIcon tone={event.level === 'error' ? 'error' : event.level} /><span><strong>{effectiveLanguage === 'zh' ? event.message : event.action.replaceAll('.', ' · ')}</strong><small>{event.action}</small></span></span><span>{domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? ''] || t('audit.controller')}</span><time>{formatDateTime(event.created_at, locale)}</time><span className={`audit-level audit-${event.level}`}>{t(`audit.${event.level}`)}</span></div>)}</Bezel></div>
}

export function SettingsPage({ onPassword, onLogout }: { onPassword: () => void; onLogout: () => void }) {
  const { t } = usePreferences()
  return <div className="content-page page-enter"><PageHeader title={t('settings.title')} description={t('settings.description')} /><div className="settings-list"><SettingRow icon="shield" title={t('settings.security')} description={t('settings.securityDescription')} value={t('accounts.encrypted')} /><SettingRow icon="server" title={t('settings.transport')} description={t('settings.transportDescription')} value="HTTPS" /><SettingRow icon="terminal" title={t('settings.transaction')} description={t('settings.transactionDescription')} value={t('settings.atomic')} /><button className="settings-action-row" onClick={onPassword}><span className="settings-icon"><Icon name="lock" size={22} /></span><span><strong>{t('settings.password')}</strong><small>{t('settings.passwordDescription')}</small></span><span className="settings-value">{t('settings.changePassword')} <Icon name="arrow" size={16} /></span></button></div><button className="logout-row" onClick={onLogout}><Icon name="logout" size={19} />{t('settings.logout')}</button></div>
}

function SettingRow({ icon, title, description, value }: { icon: 'shield' | 'server' | 'terminal'; title: string; description: string; value: string }) {
  return <Bezel className="settings-row"><span className="settings-icon"><Icon name={icon} size={22} /></span><span><strong>{title}</strong><small>{description}</small></span><span className="settings-value">{value}</span></Bezel>
}

function PageHeader({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) {
  return <header className="page-header"><div><span className="page-kicker">ATLAS / CONTROL</span><h1>{title}</h1><p>{description}</p></div>{action}</header>
}

function certificateSource(source: string, t: (key: string, variables?: Record<string, string | number>) => string): string {
  return t(source === 'acme' ? 'certificate.sourceACME' : source === 'upload' ? 'certificate.sourceUpload' : 'certificate.sourceLocal')
}

function formatDate(value: string, locale: string): string { return new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(value)) }
function formatDateTime(value: string, locale: string): string { return new Intl.DateTimeFormat(locale, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value)) }
