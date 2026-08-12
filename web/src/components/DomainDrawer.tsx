import { useEffect, useMemo, useState, type FormEvent } from 'react'
import type { ACMEAccount, CertificateRecord, CreateDomainInput, DNSAccount, DomainRecord, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, IconButton } from './Primitives'
import { SelectField } from './SelectField'

export interface DomainSubmission {
  input: CreateDomainInput
}

interface Props {
  open: boolean
  nodes: NodeRecord[]
  certificates: CertificateRecord[]
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  busy: boolean
  editingDomain?: DomainRecord
  onClose: () => void
  onSubmit: (submission: DomainSubmission) => Promise<void>
  onUpdate?: (id: string, submission: DomainSubmission) => Promise<void>
}

type CertificateChoice = 'existing' | 'acme'
const currentNodeCertificate = '__current_node_certificate__'

export function DomainDrawer({ open, nodes, certificates, dnsAccounts, acmeAccounts, busy, editingDomain, onClose, onSubmit, onUpdate }: Props) {
  const { t } = usePreferences()
  const availableNodes = useMemo(() => nodes.filter((node) => node.status !== 'revoked'), [nodes])
  const cloudflareAccounts = useMemo(() => dnsAccounts.filter((account) => account.provider.toLowerCase() === 'cloudflare'), [dnsAccounts])
  const [domain, setDomain] = useState('')
  const [nodeID, setNodeID] = useState('')
  const [upstreamHost, setUpstreamHost] = useState('127.0.0.1')
  const [port, setPort] = useState('')
  const [choice, setChoice] = useState<CertificateChoice>('existing')
  const [certificateID, setCertificateID] = useState('')
  const [dnsAccountID, setDNSAccountID] = useState('')
  const [acmeAccountID, setACMEAccountID] = useState('')
  const [autoRenew, setAutoRenew] = useState(true)
  const [cloudflareEnabled, setCloudflareEnabled] = useState(false)
  const [cloudflareAccountID, setCloudflareAccountID] = useState('')
  const [cloudflareProxied, setCloudflareProxied] = useState(true)
  const [recordContent, setRecordContent] = useState('')
  const [nginxWebsocket, setNginxWebsocket] = useState(false)
  const [nginxHttp2, setNginxHttp2] = useState(true)
  const [nginxGzip, setNginxGzip] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    if (editingDomain) {
      setDomain(editingDomain.name)
      setNodeID(editingDomain.node_id)
      setUpstreamHost(editingDomain.upstream_host || '127.0.0.1')
      setPort(editingDomain.upstream_port ? String(editingDomain.upstream_port) : '')
      setChoice(editingDomain.certificate_mode === 'acme' ? 'acme' : 'existing')
      setCertificateID(editingDomain.certificate_mode === 'local' ? currentNodeCertificate : (editingDomain.certificate_id ?? ''))
      setDNSAccountID(editingDomain.dns_account_id ?? (dnsAccounts[0]?.id ?? ''))
      setACMEAccountID(editingDomain.acme_account_id ?? (acmeAccounts[0]?.id ?? ''))
      setAutoRenew(editingDomain.auto_renew ?? true)
      setCloudflareEnabled(editingDomain.cloudflare_enabled ?? false)
      setCloudflareAccountID(editingDomain.cloudflare_dns_account_id ?? (cloudflareAccounts[0]?.id ?? ''))
      setCloudflareProxied(editingDomain.cloudflare_proxied ?? true)
      setRecordContent(editingDomain.cloudflare_record_content ?? '')
      setNginxWebsocket(editingDomain.nginx_websocket ?? false)
      setNginxHttp2(editingDomain.nginx_http2 ?? true)
      setNginxGzip(editingDomain.nginx_gzip ?? true)
    } else {
      const firstNode = availableNodes[0]
      setDomain('')
      setNodeID(firstNode?.id ?? '')
      setUpstreamHost('127.0.0.1')
      setPort('')
      setChoice('existing')
      setCertificateID('')
      setDNSAccountID(dnsAccounts[0]?.id ?? '')
      setACMEAccountID(acmeAccounts[0]?.id ?? '')
      setAutoRenew(true)
      setCloudflareEnabled(false)
      setCloudflareAccountID(cloudflareAccounts[0]?.id ?? '')
      setCloudflareProxied(true)
      setRecordContent(preferredAddress(firstNode))
      setNginxWebsocket(false)
      setNginxHttp2(true)
      setNginxGzip(true)
    }
    setError('')
  }, [open, editingDomain])

  useEffect(() => {
    if (!open) return
    if (!availableNodes.some((node) => node.id === nodeID)) {
      const firstNode = availableNodes[0]
      setNodeID(firstNode?.id ?? '')
      setRecordContent(preferredAddress(firstNode))
    }
    if (!dnsAccounts.some((account) => account.id === dnsAccountID)) {
      setDNSAccountID(dnsAccounts[0]?.id ?? '')
    }
    if (!acmeAccounts.some((account) => account.id === acmeAccountID)) {
      setACMEAccountID(acmeAccounts[0]?.id ?? '')
    }
    if (!cloudflareAccounts.some((account) => account.id === cloudflareAccountID)) {
      setCloudflareAccountID(cloudflareAccounts[0]?.id ?? '')
    }
  }, [open, availableNodes, nodeID, dnsAccounts, dnsAccountID, acmeAccounts, acmeAccountID, cloudflareAccounts, cloudflareAccountID])

  const normalizedDomain = domain.trim().toLowerCase()
  const eligibleCertificates = useMemo(() => certificates.filter((certificate) =>
    normalizedDomain && (certificate.domain === normalizedDomain || certificate.dns_names.some((name) => coversDomain(name, normalizedDomain))),
  ), [certificates, normalizedDomain])
  const selectedNode = availableNodes.find((node) => node.id === nodeID)
  const keepsCurrentNodeCertificate = Boolean(
    editingDomain?.certificate_mode === 'local'
    && editingDomain.node_id === nodeID
    && certificateID === currentNodeCertificate,
  )
  const certificateOptions = [
    ...(editingDomain?.certificate_mode === 'local' && editingDomain.node_id === nodeID ? [{
      value: currentNodeCertificate,
      label: t('domain.currentNodeCertificate'),
      description: editingDomain.name,
    }] : []),
    ...eligibleCertificates.map((certificate) => ({
      value: certificate.id,
      label: certificate.domain,
      description: t('domain.controllerCertificate', { domain: certificate.domain, days: certificate.days_remaining }),
    })),
  ]

  useEffect(() => {
    if (choice !== 'existing') return
    const currentLocal = certificateID === currentNodeCertificate && editingDomain?.certificate_mode === 'local' && editingDomain.node_id === nodeID
    if (certificateID && !currentLocal && !eligibleCertificates.some((certificate) => certificate.id === certificateID)) {
      setCertificateID(eligibleCertificates[0]?.id ?? '')
    } else if (!certificateID && eligibleCertificates.length > 0) {
      setCertificateID(eligibleCertificates[0]?.id ?? '')
    }
  }, [choice, certificateID, eligibleCertificates, editingDomain, nodeID])

  function selectNode(value: string) {
    setNodeID(value)
    const node = availableNodes.find((item) => item.id === value)
    setRecordContent(preferredAddress(node))
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const parsedPort = Number(port)
    if (!normalizedDomain.includes('.') || !nodeID || !upstreamHost.trim() || !Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setError(t('domain.validation'))
      return
    }
    if (choice === 'existing' && !certificateID) {
      setError(t('domain.validationCertificate'))
      return
    }
    if (choice === 'acme' && (!dnsAccountID || !acmeAccountID)) {
      setError(t('domain.validationAccounts'))
      return
    }
    if (cloudflareEnabled && !cloudflareAccountID) {
      setError(t('domain.validationCloudflare'))
      return
    }
    const submissionInput: CreateDomainInput = {
      domain: normalizedDomain,
      node_id: nodeID,
      upstream_host: upstreamHost.trim().toLowerCase(),
      upstream_port: parsedPort,
      certificate_mode: choice === 'acme' ? 'acme' : keepsCurrentNodeCertificate ? 'local' : 'upload',
      certificate_id: choice === 'existing' && !keepsCurrentNodeCertificate ? certificateID : undefined,
      acme_account_id: choice === 'acme' ? acmeAccountID : undefined,
      dns_account_id: choice === 'acme' ? dnsAccountID : undefined,
      auto_renew: choice === 'acme' && autoRenew,
      renew_before_days: 30,
      sync_node_ids: [],
      cloudflare_enabled: cloudflareEnabled,
      cloudflare_dns_account_id: cloudflareEnabled ? cloudflareAccountID : undefined,
      cloudflare_proxied: cloudflareEnabled && cloudflareProxied,
      cloudflare_record_content: cloudflareEnabled ? recordContent.trim() : undefined,
      nginx_websocket: nginxWebsocket,
      nginx_http2: nginxHttp2,
      nginx_gzip: nginxGzip,
    }
    if (editingDomain && onUpdate) {
      await onUpdate(editingDomain.id, { input: submissionInput })
    } else {
      await onSubmit({ input: submissionInput })
    }
  }

  if (!open) return null

  return (
    <div className="drawer-layer drawer-open" onMouseDown={(event) => event.currentTarget === event.target && !busy && onClose()}>
      <form className="domain-drawer" onSubmit={submit} aria-label={editingDomain ? t('domain.editTitle') : t('domain.add')}>
        <header className="drawer-header"><div><span className="dialog-kicker">{t('domain.drawerKicker')}</span><h2>{editingDomain ? t('domain.editTitle') : t('domain.add')}</h2><p>{t('domain.drawerSubtitle')}</p></div><IconButton name="close" label={t('common.close')} type="button" onClick={onClose} disabled={busy} /></header>
        <div className="drawer-body">
          <section className="form-section">
            <div className="form-section-heading"><span>01</span><div><strong>{t('domain.stepRoute')}</strong><small>{t('domain.routeHint')}</small></div></div>
            <div className="form-row"><label htmlFor="domain-name">{t('certificate.domain')}</label><div className="field-control"><Icon name="globe" size={18} /><input id="domain-name" value={domain} disabled={Boolean(editingDomain)} onChange={(event) => setDomain(event.target.value)} placeholder="api.example.com" autoComplete="off" /><span className="field-state">{normalizedDomain.includes('.') && <Icon name="check" size={18} />}</span></div></div>
            <div className="form-row"><label>{t('domain.targetNode')}</label><SelectField ariaLabel={t('domain.targetNode')} value={nodeID} onChange={selectNode} placeholder={t('common.select')} icon="server" options={availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.os_name || (node.status === 'online' ? t('common.online') : t('common.offline')) }))} /></div>
            <div className="form-row form-row-split"><label htmlFor="upstream-host">{t('domain.upstreamHost')}</label><div className="split-fields"><div className="field-control"><input id="upstream-host" value={upstreamHost} onChange={(event) => setUpstreamHost(event.target.value)} placeholder="127.0.0.1" /></div><div className="port-field"><span>{t('domain.projectPort')}</span><div className="field-control"><input aria-label={t('domain.projectPort')} inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))} placeholder="8080" /></div></div></div></div>
          </section>

          <section className="form-section">
            <div className="form-section-heading"><span>02</span><div><strong>{t('domain.stepCertificate')}</strong><small>{t('domain.certificateHint')}</small></div></div>
            <div className="segmented-control certificate-choice">
              <button type="button" className={choice === 'existing' ? 'selected' : ''} onClick={() => setChoice('existing')}>
                <Icon name="shield" size={17} /><span>{t('domain.existingCertificate')}</span>
              </button>
              <button type="button" className={choice === 'acme' ? 'selected' : ''} onClick={() => setChoice('acme')}>
                <Icon name="certificate" size={17} /><span>{t('domain.letsencryptShort')}</span>
              </button>
            </div>
            {choice === 'existing' ? <label className="source-select"><span>{t('domain.certificateLocation')}</span>{certificateOptions.length ? <SelectField ariaLabel={t('domain.certificateLocation')} value={certificateID} onChange={setCertificateID} placeholder={t('common.select')} icon="shield" options={certificateOptions} /> : <span className="certificate-empty-choice" role="status"><Icon name="shield" size={18} />{t('domain.noMatchingCertificate')}</span>}</label> : <div className="acme-compact-panel"><label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: 30 })}</small></span></label></div>}
          </section>

          <section className="form-section cloudflare-section">
            <div className="cloudflare-heading"><span className="cloudflare-symbol"><Icon name="dns" size={21} /></span><span><strong>{t('domain.cloudflareTitle')}</strong><small>{t('domain.cloudflareHint')}</small></span><button type="button" role="switch" aria-label={t('domain.cloudflareTitle')} aria-checked={cloudflareEnabled} className={cloudflareEnabled ? 'switch-on' : ''} onClick={() => setCloudflareEnabled((value) => !value)}><i /></button></div>
            {cloudflareEnabled && <div className="cloudflare-options"><label><span>{t('domain.recordContent')}</span><div className="field-control"><Icon name="link" size={17} /><input value={recordContent} onChange={(event) => setRecordContent(event.target.value)} placeholder={preferredAddress(selectedNode) || t('domain.recordAuto')} /></div></label><div className="proxy-mode"><span>{t('domain.proxyMode')}</span><div className="segmented-control"><button type="button" className={cloudflareProxied ? 'selected proxy-orange' : ''} onClick={() => setCloudflareProxied(true)}><Icon name="cloud" size={17} />{t('domain.orangeCloud')}</button><button type="button" className={!cloudflareProxied ? 'selected' : ''} onClick={() => setCloudflareProxied(false)}><Icon name="cloud-off" size={17} />{t('domain.grayCloud')}</button></div></div></div>}
          </section>

          <section className="form-section nginx-section">
            <div className="form-section-heading"><span>03</span><div><strong>{t('domain.nginxSettings')}</strong><small>{t('domain.nginxSettingsHint')}</small></div></div>
            <div className="nginx-options">
              <label className="switch-row"><button type="button" role="switch" aria-checked={nginxWebsocket} className={nginxWebsocket ? 'switch-on' : ''} onClick={() => setNginxWebsocket((value) => !value)}><i /></button><span><strong>{t('domain.nginxWebsocket')}</strong><small>{t('domain.nginxWebsocketHint')}</small></span></label>
              <label className="switch-row"><button type="button" role="switch" aria-checked={nginxHttp2} className={nginxHttp2 ? 'switch-on' : ''} onClick={() => setNginxHttp2((value) => !value)}><i /></button><span><strong>{t('domain.nginxHttp2')}</strong><small>{t('domain.nginxHttp2Hint')}</small></span></label>
              <label className="switch-row"><button type="button" role="switch" aria-checked={nginxGzip} className={nginxGzip ? 'switch-on' : ''} onClick={() => setNginxGzip((value) => !value)}><i /></button><span><strong>{t('domain.nginxGzip')}</strong><small>{t('domain.nginxGzipHint')}</small></span></label>
            </div>
          </section>

          {selectedNode?.status !== 'online' && nodeID && <div className="form-warning"><Icon name="warning" size={18} />{t('domain.offlineWarning')}</div>}
          {error && <div className="form-error drawer-error" role="alert"><Icon name="warning" size={17} />{error}</div>}
        </div>
        <footer className="drawer-footer">
          <button className="cancel-button" type="button" onClick={onClose} disabled={busy}>{t('common.cancel')}</button>
          <ActionButton type="submit" wide plain disabled={busy || availableNodes.length === 0}>
            {busy ? t('common.queueing') : editingDomain ? t('domain.updateSubmit') : t('domain.submit')}
          </ActionButton>
        </footer>
      </form>
    </div>
  )
}

function coversDomain(name: string, domain: string): boolean {
  const normalized = name.toLowerCase()
  if (normalized === domain) return true
  if (!normalized.startsWith('*.')) return false
  const suffix = normalized.slice(1)
  return domain.endsWith(suffix) && domain.slice(0, -suffix.length).indexOf('.') === -1
}

function preferredAddress(node?: NodeRecord): string {
  if (!node) return ''
  return node.ip_addresses?.find((address) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) ?? node.ip_addresses?.[0] ?? ''
}
