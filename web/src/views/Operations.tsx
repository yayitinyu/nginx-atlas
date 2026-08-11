import { useMemo, useState } from 'react'
import type { ACMEAccount, AuditEvent, CertificateRecord, DNSAccount, DomainRecord, NginxSiteMeta, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from '../components/Icon'
import { ActionButton, Bezel, EmptyState, IconButton, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'
import { SelectField } from '../components/SelectField'
import { DomainTable, relativeTime } from './Overview'

interface DiscoveredSite { node: NodeRecord; site: NginxSiteMeta }

export function DomainsPage({ domains, nodes, onAdd, onEdit, onDelete }: {
  domains: DomainRecord[]
  nodes: NodeRecord[]
  onAdd: () => void
  onEdit: (domain: DomainRecord) => void
  onDelete: (domain: DomainRecord) => void
}) {
  const { t } = usePreferences()
  const [query, setQuery] = useState('')
  const normalized = query.trim().toLowerCase()
  const filtered = useMemo(() => domains.filter((domain) =>
    !normalized
    || domain.name.includes(normalized)
    || domain.node_name.toLowerCase().includes(normalized)
    || `${domain.upstream_host}:${domain.upstream_port}`.includes(normalized),
  ), [domains, normalized])

  return (
    <div className="content-page page-enter">
      <PageHeader
        title={t('domain.title')}
        description={t('domain.description')}
        action={<ActionButton leadingIcon="plus" plain onClick={onAdd}>{t('domain.add')}</ActionButton>}
      />
      <Bezel className="operation-panel">
        <div className="panel-toolbar">
          <label className="search-field">
            <Icon name="search" size={17} />
            <span className="sr-only">{t('common.search')}</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('domain.searchPlaceholder')} />
          </label>
        </div>
        {filtered.length ? (
          <DomainTable
            domains={filtered}
            onOpen={onEdit}
            showActions={(domain) => (
              <div className="domain-row-actions">
                <IconButton name="edit" label={`${t('common.edit')} ${domain.name}`} onClick={() => onEdit(domain)} />
                <IconButton name="trash" label={`${t('common.delete')} ${domain.name}`} onClick={() => onDelete(domain)} />
              </div>
            )}
          />
        ) : (
          <EmptyState
            icon="globe"
            title={t('domain.empty')}
            description={t('domain.emptyDescription')}
            action={<button type="button" className="inline-action" onClick={onAdd}><Icon name="plus" size={16} />{t('domain.add')}</button>}
          />
        )}
        <div className="panel-footer">
          <span>{t('domain.showing', { shown: filtered.length, total: domains.length })}</span>
          <span className="footer-note">{t('domain.transactionNote')}</span>
        </div>
      </Bezel>
    </div>
  )
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
  const filtered = certificates.filter((certificate) =>
    (!normalized || certificate.domain.includes(normalized) || certificate.issuer.toLowerCase().includes(normalized) || certificate.fingerprint_sha256.toLowerCase().includes(normalized))
    && (status === 'all' || (status === 'valid' && certificate.status === 'valid') || (status === 'risk' && certificate.status !== 'valid')),
  )
  const expiring = certificates.filter((certificate) => certificate.status !== 'valid').length
  const autoRenew = certificates.filter((certificate) => certificate.auto_renew).length
  const copies = certificates.reduce((total, certificate) => total + certificate.deployed_node_ids.length, 0)

  return (
    <div className="content-page page-enter">
      <PageHeader
        title={t('certificate.title')}
        description={t('certificate.description')}
        action={<ActionButton leadingIcon="plus" plain onClick={onAdd}>{t('certificate.add')}</ActionButton>}
      />
      <div className="certificate-summary">
        <SummaryMetric icon="shield" label={t('certificate.total')} value={certificates.length} />
        <SummaryMetric icon="warning" label={t('certificate.expiringCount')} value={expiring} warning={expiring > 0} />
        <SummaryMetric icon="refresh" label={t('certificate.autoRenewCount')} value={autoRenew} />
        <SummaryMetric icon="server" label={t('certificate.nodeCopies')} value={copies} />
      </div>
      <Bezel className="operation-panel certificate-list-panel">
        <div className="panel-toolbar certificate-toolbar">
          <label className="search-field certificate-search">
            <Icon name="search" size={17} />
            <span className="sr-only">{t('common.search')}</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('certificate.searchPlaceholder')} />
          </label>
          <SelectField
            ariaLabel={t('certificate.allStatuses')}
            value={status}
            onChange={(value) => setStatus(value as typeof status)}
            icon="filter"
            options={[
              { value: 'all', label: t('certificate.allStatuses') },
              { value: 'valid', label: t('certificate.validOnly') },
              { value: 'risk', label: t('certificate.expiringOnly') },
            ]}
          />
        </div>
        <div className="certificate-list-head">
          <span>{t('domain.columnDomain')}</span>
          <span>{t('certificate.source')}</span>
          <span>{t('certificate.expiry')}</span>
          <span>{t('certificate.autoRenew')}</span>
          <span>{t('certificate.distribution')}</span>
          <span />
        </div>
        {filtered.length === 0 ? (
          <EmptyState
            icon="shield"
            title={t('certificate.empty')}
            description={t('certificate.emptyDescription')}
            action={<button type="button" className="inline-action" onClick={onAdd}><Icon name="plus" size={16} />{t('certificate.add')}</button>}
          />
        ) : filtered.map((certificate) => {
          const automationReady = Boolean(
            certificate.issuer_node_id
            && certificate.acme_account_id
            && certificate.dns_account_id
            && nodes.some((node) => node.id === certificate.issuer_node_id && node.status !== 'revoked'),
          )
          const toggling = busy === `auto-renew-${certificate.id}`
          const renewing = busy === `renew-${certificate.id}`
          const switchLabel = t(certificate.auto_renew ? 'certificate.disableAutoRenew' : 'certificate.enableAutoRenew', { domain: certificate.domain })
          return (
            <div className="certificate-list-row" key={certificate.id}>
              <span className="cert-identity">
                <StatusIcon tone={certificate.status === 'valid' ? 'success' : certificate.status === 'expiring' ? 'warning' : 'error'} />
                <span>
                  <strong>{certificate.domain}</strong>
                  <small title={certificate.fingerprint_sha256}>{certificateSource(certificate.source, t)} · {t('certificate.namesCount', { count: certificate.dns_names.length })}</small>
                </span>
              </span>
              <span className="source-label">{certificateSource(certificate.source, t)}</span>
              <span className={`expiry-label expiry-${certificate.status}`}>
                <strong>{certificate.days_remaining > 0 ? t('certificate.remaining', { count: certificate.days_remaining }) : t('common.expired')}</strong>
                <small>{formatDate(certificate.not_after, locale)}</small>
              </span>
              <span className="renewal-state">
                <button
                  type="button"
                  role="switch"
                  aria-checked={certificate.auto_renew}
                  aria-label={switchLabel}
                  title={!certificate.auto_renew && !automationReady ? t('certificate.automationUnavailable') : switchLabel}
                  className={certificate.auto_renew ? 'certificate-renew-switch switch-on' : 'certificate-renew-switch'}
                  disabled={toggling || (!certificate.auto_renew && !automationReady)}
                  onClick={() => onToggleAutoRenew(certificate, !certificate.auto_renew)}
                >
                  <i />
                </button>
                <span>{toggling ? t('common.saving') : certificate.auto_renew ? t('certificate.enabled') : t('certificate.disabled')}</span>
              </span>
              <span className="deployed-count"><strong>{certificate.deployed_node_ids.length}</strong>/{nodes.length}</span>
              <span className="certificate-actions">
                <button type="button" onClick={() => onEdit(certificate)} title={t('common.edit')}>
                  <Icon name="edit" size={15} /><span>{t('common.edit')}</span>
                </button>
                <button type="button" disabled={renewing || !automationReady} onClick={() => onRenew(certificate)} title={t('certificate.renew')}>
                  <Icon name="refresh" size={15} /><span>{t('certificate.renew')}</span>
                </button>
                <button type="button" disabled={Boolean(busy)} onClick={() => onSync(certificate)} title={t('certificate.sync')}>
                  <Icon name="upload" size={15} /><span>{t('certificate.sync')}</span>
                </button>
              </span>
            </div>
          )
        })}
      </Bezel>
    </div>
  )
}

function SummaryMetric({ icon, label, value, warning = false }: { icon: 'shield' | 'warning' | 'refresh' | 'server'; label: string; value: number; warning?: boolean }) {
  return (
    <div className={warning ? 'summary-metric summary-warning' : 'summary-metric'}>
      <span><Icon name={icon} size={18} /></span>
      <strong>{value}</strong>
      <small>{label}</small>
    </div>
  )
}

export function NodesPage({ nodes, onAdd, onRevoke, onManage }: { nodes: NodeRecord[]; onAdd: () => void; onRevoke: (node: NodeRecord) => void; onManage: (node: NodeRecord) => void }) {
  const { t, locale } = usePreferences()
  return (
    <div className="content-page page-enter">
      <PageHeader
        title={t('nodes.title')}
        description={t('nodes.description')}
        action={<ActionButton leadingIcon="plus" plain onClick={onAdd}>{t('nodes.add')}</ActionButton>}
      />
      <div className="nodes-canvas">
        {nodes.length === 0 ? (
          <Bezel>
            <EmptyState
              icon="server"
              title={t('nodes.empty')}
              description={t('nodes.emptyDescription')}
              action={<button type="button" className="inline-action" onClick={onAdd}><Icon name="plus" size={16} />{t('nodes.add')}</button>}
            />
          </Bezel>
        ) : nodes.map((node) => (
          <Bezel className="node-detail" key={node.id}>
            <div className="node-detail-top">
              <span className="node-machine"><Icon name="server" size={22} /></span>
              <span>
                <span className="node-name-line">
                  <strong>{node.name}</strong>
                  {node.controller_installed && <span className="controller-badge"><Icon name="home" size={13} />{t('nodes.controller')}</span>}
                </span>
                <small>{node.hostname || t('nodes.hostnamePending')}</small>
              </span>
              <span className={`node-state node-state-${node.status}`}>
                <StatusDot tone={node.status === 'online' && node.nginx_healthy ? 'good' : node.status === 'offline' ? 'danger' : 'warning'} />
                {t(`common.${node.status}`)}
              </span>
            </div>
            <div className="node-specs">
              <span><small>{t('nodes.addresses')}</small><strong>{node.ip_addresses?.join(' · ') || '—'}</strong></span>
              <span><small>{t('nodes.nginx')}</small><strong>{node.nginx_version || t('overview.nginxUndetected')}</strong></span>
              <span><small>{t('nodes.platform')}</small><strong>{node.os_name || [node.os, node.arch].filter(Boolean).join(' / ') || '—'}</strong></span>
              <span><small>{t('nodes.certDirectory')}</small><strong>{t('nodes.certFound', { count: node.certificates?.length ?? 0 })} · {t('nodes.siteFound', { count: node.nginx_sites?.length ?? 0 })}</strong></span>
            </div>
            <div className="node-detail-footer">
              <span><Icon name="clock" size={15} />{t('nodes.lastSeen', { time: node.last_seen_at ? relativeTime(node.last_seen_at, locale) : t('nodes.never') })}</span>
              <span className="node-card-actions">
                <button type="button" className="chip-action" onClick={() => onManage(node)}>
                  <Icon name="settings" size={15} />{t('nodes.manage')}
                </button>
                {node.status !== 'revoked' && (
                  <button type="button" className="chip-action danger-chip" onClick={() => onRevoke(node)}>
                    <Icon name="trash" size={15} />{t('nodes.revoke')}
                  </button>
                )}
              </span>
            </div>
          </Bezel>
        ))}
      </div>
    </div>
  )
}

export function AuditPage({ events, domains, nodes }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[] }) {
  const { t, locale, effectiveLanguage } = usePreferences()
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return (
    <div className="content-page page-enter">
      <PageHeader title={t('audit.title')} description={t('audit.description')} />
      <Bezel className="operation-panel audit-panel">
        <div className="audit-head">
          <span>{t('audit.event')}</span>
          <span>{t('audit.target')}</span>
          <span>{t('audit.time')}</span>
          <span>{t('audit.level')}</span>
        </div>
        {events.length === 0 ? (
          <EmptyState icon="log" title={t('audit.empty')} description={t('audit.emptyDescription')} />
        ) : events.map((event, index) => (
          <div className="audit-row" key={event.id || `${event.action}-${index}`}>
            <span>
              <StatusIcon tone={event.level === 'error' ? 'error' : event.level} />
              <span>
                <strong>{effectiveLanguage === 'zh' ? event.message : event.action.replaceAll('.', ' · ')}</strong>
                <small>{event.action}</small>
              </span>
            </span>
            <span>{domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? ''] || t('audit.controller')}</span>
            <time>{formatDateTime(event.created_at, locale)}</time>
            <span className={`audit-level audit-${event.level}`}>{t(`audit.${event.level}`)}</span>
          </div>
        ))}
      </Bezel>
    </div>
  )
}

export function SettingsPage({
  dnsAccounts, acmeAccounts, onAddDNS, onAddACME, onEditDNS, onEditACME, onPassword, onLogout
}: {
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDNS: () => void
  onAddACME: () => void
  onEditDNS: (account: DNSAccount) => void
  onEditACME: (account: ACMEAccount) => void
  onPassword: () => void
  onLogout: () => void
}) {
  const { t } = usePreferences()
  return (
    <div className="content-page page-enter">
      <PageHeader title={t('settings.title')} description={t('settings.description')} />
      <div className="account-split">
        <Bezel className="account-panel">
          <SectionHeading title={t('accounts.dnsTitle')} action={<IconButton name="plus" label={t('accounts.addDNS')} onClick={onAddDNS} />} />
          {dnsAccounts.length === 0 ? (
            <EmptyState icon="dns" title={t('accounts.emptyDNS')} description={t('accounts.emptyDNSDescription')} action={<button type="button" className="inline-action" onClick={onAddDNS}><Icon name="plus" size={16} />{t('accounts.addDNS')}</button>} />
          ) : (
            <div className="account-list">
              {dnsAccounts.map((account) => (
                <button type="button" className="account-row" key={account.id} onClick={() => onEditDNS(account)}>
                  <span className="account-icon"><Icon name="dns" size={20} /></span>
                  <span><strong>{account.name}</strong><small>{account.provider}</small></span>
                  <span className="credential-keys">{t('accounts.credentials', { count: account.credential_keys.length })}</span>
                  <Icon name="chevron" size={16} />
                </button>
              ))}
            </div>
          )}
        </Bezel>
        <Bezel className="account-panel">
          <SectionHeading title={t('accounts.acmeTitle')} action={<IconButton name="plus" label={t('accounts.addACME')} onClick={onAddACME} />} />
          {acmeAccounts.length === 0 ? (
            <EmptyState icon="key" title={t('accounts.emptyACME')} description={t('accounts.emptyACMEDescription')} action={<button type="button" className="inline-action" onClick={onAddACME}><Icon name="plus" size={16} />{t('accounts.addACME')}</button>} />
          ) : (
            <div className="account-list">
              {acmeAccounts.map((account) => (
                <button type="button" className="account-row" key={account.id} onClick={() => onEditACME(account)}>
                  <span className="account-icon"><Icon name="key" size={20} /></span>
                  <span><strong>{account.name}</strong><small>{account.email}</small></span>
                  <span className="credential-keys">{account.has_eab ? t('accounts.eab') : t('accounts.standard')}</span>
                  <Icon name="chevron" size={16} />
                </button>
              ))}
            </div>
          )}
        </Bezel>
      </div>
      <div className="settings-list">
        <SettingRow icon="shield" title={t('settings.security')} description={t('settings.securityDescription')} value={t('accounts.encrypted')} />
        <SettingRow icon="server" title={t('settings.transport')} description={t('settings.transportDescription')} value="HTTPS" />
        <SettingRow icon="terminal" title={t('settings.transaction')} description={t('settings.transactionDescription')} value={t('settings.atomic')} />
        <button type="button" className="settings-action-row" onClick={onPassword}>
          <span className="settings-icon"><Icon name="lock" size={20} /></span>
          <span><strong>{t('settings.password')}</strong>{t('settings.passwordDescription') && <small>{t('settings.passwordDescription')}</small>}</span>
          <span className="settings-value">{t('settings.changePassword')} <Icon name="chevron" size={15} /></span>
        </button>
      </div>
      <button type="button" className="logout-row" onClick={onLogout}><Icon name="logout" size={18} />{t('settings.logout')}</button>
    </div>
  )
}

function SettingRow({ icon, title, description, value }: { icon: 'shield' | 'server' | 'terminal'; title: string; description: string; value: string }) {
  return (
    <Bezel className="settings-row">
      <span className="settings-icon"><Icon name={icon} size={20} /></span>
      <span><strong>{title}</strong>{description && <small>{description}</small>}</span>
      <span className="settings-value">{value}</span>
    </Bezel>
  )
}

function PageHeader({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) {
  const { t } = usePreferences()
  return (
    <header className="page-header">
      <div>
        <span className="page-kicker">{t('page.kickerControl')}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-header-action">{action}</div>}
    </header>
  )
}

function certificateSource(source: string, t: (key: string, variables?: Record<string, string | number>) => string): string {
  return t(source === 'acme' ? 'certificate.sourceACME' : source === 'upload' ? 'certificate.sourceUpload' : 'certificate.sourceLocal')
}

function formatDate(value: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(value))
}

function formatDateTime(value: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}
