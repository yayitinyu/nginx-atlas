import { useEffect, useMemo, useState, type FormEvent } from 'react'
import type { ACMEAccount, CertificateRecord, CreateDomainInput, DNSAccount, NodeRecord } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, IconButton, StatusDot } from './Primitives'
import { SelectField } from './SelectField'

export interface DomainSubmission {
  input: CreateDomainInput
  fullchain?: File
  privkey?: File
}

interface Props {
  open: boolean
  nodes: NodeRecord[]
  certificates: CertificateRecord[]
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  busy: boolean
  onClose: () => void
  onSubmit: (submission: DomainSubmission) => Promise<void>
}

type Source = 'existing' | 'upload' | 'acme'

export function DomainDrawer({ open, nodes, certificates, dnsAccounts, acmeAccounts, busy, onClose, onSubmit }: Props) {
  const { t } = usePreferences()
  const availableNodes = useMemo(() => nodes.filter((node) => node.status !== 'revoked'), [nodes])
  const [domain, setDomain] = useState('')
  const [nodeID, setNodeID] = useState('')
  const [upstreamHost, setUpstreamHost] = useState('127.0.0.1')
  const [port, setPort] = useState('')
  const [source, setSource] = useState<Source>('existing')
  const [existingCertificate, setExistingCertificate] = useState('local')
  const [fullchain, setFullchain] = useState<File>()
  const [privkey, setPrivkey] = useState<File>()
  const [dnsAccountID, setDNSAccountID] = useState('')
  const [acmeAccountID, setACMEAccountID] = useState('')
  const [autoRenew, setAutoRenew] = useState(true)
  const [syncNodeIDs, setSyncNodeIDs] = useState<string[]>([])
  const [httpOnly, setHTTPOnly] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setDomain(''); setNodeID(availableNodes[0]?.id ?? ''); setUpstreamHost('127.0.0.1'); setPort('')
    setSource('existing'); setExistingCertificate('local'); setFullchain(undefined); setPrivkey(undefined)
    setDNSAccountID(dnsAccounts[0]?.id ?? ''); setACMEAccountID(acmeAccounts[0]?.id ?? '')
    setAutoRenew(true); setSyncNodeIDs([]); setHTTPOnly(false); setError('')
  // Polling refreshes the resource arrays in the background. Resetting on
  // those identity changes would erase partially completed domain forms.
  }, [open])

  const normalizedDomain = domain.trim().toLowerCase()
  const eligibleCertificates = useMemo(() => certificates.filter((certificate) => !normalizedDomain || certificate.domain === normalizedDomain || certificate.dns_names.includes(normalizedDomain)), [certificates, normalizedDomain])
  const selectedNode = availableNodes.find((node) => node.id === nodeID)
  const otherNodes = availableNodes.filter((node) => node.id !== nodeID)
  const previewDomain = normalizedDomain || 'api.example.com'
  const previewPort = Number(port) || 8080

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const parsedPort = Number(port)
    if (!normalizedDomain.includes('.') || !nodeID || !upstreamHost.trim() || !Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) { setError(t('domain.validation')); return }
    if (!httpOnly && source === 'upload' && (!fullchain || !privkey)) { setError(t('domain.validationFiles')); return }
    if (!httpOnly && (source === 'acme' || autoRenew) && (!dnsAccountID || !acmeAccountID)) { setError(t('domain.validationAccounts')); return }

    let certificateMode: CreateDomainInput['certificate_mode'] = 'none'
    let certificateID: string | undefined
    if (!httpOnly) {
      if (source === 'acme') certificateMode = 'acme'
      else if (source === 'upload') certificateMode = 'upload'
      else if (existingCertificate === 'local') certificateMode = 'local'
      else { certificateMode = 'upload'; certificateID = existingCertificate }
    }
    await onSubmit({
      input: {
        domain: normalizedDomain, node_id: nodeID, upstream_host: upstreamHost.trim().toLowerCase(), upstream_port: parsedPort,
        certificate_mode: certificateMode, certificate_id: certificateID,
        acme_account_id: !httpOnly && (autoRenew || source === 'acme') ? acmeAccountID : undefined,
        dns_account_id: !httpOnly && (autoRenew || source === 'acme') ? dnsAccountID : undefined,
        auto_renew: !httpOnly && autoRenew, renew_before_days: 30, sync_node_ids: syncNodeIDs,
      },
      fullchain, privkey,
    })
  }

  if (!open) return null

  return (
    <div className="drawer-layer drawer-open" onMouseDown={(event) => event.currentTarget === event.target && !busy && onClose()}>
      <form className="domain-drawer" onSubmit={submit} aria-label={t('domain.add')}>
        <header className="drawer-header"><div><h2>{t('domain.add')}</h2><p>{t('domain.drawerSubtitle')}</p></div><IconButton name="close" label={t('common.close')} type="button" onClick={onClose} disabled={busy} /></header>
        <div className="drawer-steps" aria-label={t('domain.stepDeploy')}><span className="step-active"><i>1</i>{t('domain.stepRoute')}</span><b /><span className={domain && nodeID ? 'step-ready' : ''}><i>2</i>{t('domain.stepCertificate')}</span><b /><span className={domain && nodeID && port ? 'step-ready' : ''}><i>3</i>{t('domain.stepDeploy')}</span></div>
        <div className="drawer-body">
          <div className="form-row"><label htmlFor="domain-name">{t('certificate.domain')}</label><div className="field-control"><Icon name="globe" size={17} /><input id="domain-name" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="api.example.com" autoComplete="off" /><span className="field-state">{normalizedDomain.includes('.') && <Icon name="check" size={17} />}</span></div></div>
          <div className="form-row"><label>{t('domain.targetNode')}</label><SelectField ariaLabel={t('domain.targetNode')} value={nodeID} onChange={(value) => { setNodeID(value); setSyncNodeIDs((items) => items.filter((id) => id !== value)) }} placeholder={t('common.select')} icon="server" options={availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.status === 'online' ? t('common.online') : t('common.offline') }))} /></div>
          <div className="form-row form-row-split"><label htmlFor="upstream-host">{t('domain.upstreamHost')}</label><div className="split-fields"><div className="field-control"><input id="upstream-host" value={upstreamHost} onChange={(event) => setUpstreamHost(event.target.value)} placeholder="127.0.0.1" /></div><div className="port-field"><span>{t('domain.projectPort')}</span><div className="field-control"><input aria-label={t('domain.projectPort')} inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))} placeholder="8080" /></div></div></div></div>

          <fieldset className="certificate-source" disabled={httpOnly}>
            <legend>{t('domain.certificateSource')}</legend>
            <div className="segmented-control">{(['existing', 'upload', 'acme'] as const).map((item) => <button type="button" className={source === item ? 'selected' : ''} onClick={() => setSource(item)} key={item}><Icon name={item === 'existing' ? 'shield' : item === 'upload' ? 'upload' : 'key'} size={17} />{t(item === 'existing' ? 'domain.existingCertificate' : item === 'upload' ? 'domain.uploadCertificate' : 'domain.letsencrypt')}{source === item && <Icon name="check" size={15} />}</button>)}</div>
            <div className="certificate-source-body">
              {source === 'existing' && <label className="source-select"><span>{t('domain.certificateLocation')}</span><SelectField ariaLabel={t('domain.certificateLocation')} value={existingCertificate} onChange={setExistingCertificate} icon="shield" options={[{ value: 'local', label: t('domain.localCertificate', { domain: normalizedDomain || 'example.com' }) }, ...eligibleCertificates.map((certificate) => ({ value: certificate.id, label: t('domain.controllerCertificate', { domain: certificate.domain, days: certificate.days_remaining }) }))]} /></label>}
              {source === 'upload' && <div className="certificate-upload-grid"><FileField label={t('certificate.fullchain')} file={fullchain} onChange={setFullchain} accept=".pem,.crt" /><FileField label={t('certificate.privkey')} file={privkey} onChange={setPrivkey} accept=".pem,.key" /></div>}
              {(source === 'acme' || autoRenew) && <div className="account-fields"><label><span>{t('certificate.dnsAccount')}</span><SelectField ariaLabel={t('certificate.dnsAccount')} value={dnsAccountID} onChange={setDNSAccountID} placeholder={t('common.select')} icon="dns" options={dnsAccounts.map((account) => ({ value: account.id, label: account.name, description: account.provider }))} /></label><label><span>{t('certificate.acmeAccount')}</span><SelectField ariaLabel={t('certificate.acmeAccount')} value={acmeAccountID} onChange={setACMEAccountID} placeholder={t('common.select')} icon="key" options={acmeAccounts.map((account) => ({ value: account.id, label: account.name, description: account.email }))} /></label></div>}
              <label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: 30 })}</small></span></label>
            </div>
          </fieldset>

          <div className="form-row sync-row"><label>{t('domain.syncOthers')}</label><div className="sync-node-select">{otherNodes.length === 0 ? <span className="empty-inline">{t('domain.noOtherNodes')}</span> : otherNodes.map((node) => <button type="button" key={node.id} className={syncNodeIDs.includes(node.id) ? 'selected' : ''} onClick={() => setSyncNodeIDs((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} />{node.name}{syncNodeIDs.includes(node.id) && <Icon name="check" size={14} />}</button>)}</div><small>{t('domain.syncDescription')}</small></div>
          <div className="form-row preview-row"><label>{t('domain.preview')}</label><pre><span>server {'{'}</span>{!httpOnly && <><br />{'  '}listen <em>443 ssl</em>;<br />{'  '}ssl_certificate <em>/etc/ssl/{previewDomain}/fullchain.pem</em>;</>}<br />{'  '}server_name <em>{previewDomain}</em>;<br />{'  '}location / {'{'}<br />{'    '}proxy_pass <em>http://{upstreamHost || '127.0.0.1'}:{previewPort}</em>;<br />{'  }'}<br />{'}'}</pre></div>
          <label className="http-only-row"><input type="checkbox" checked={httpOnly} onChange={(event) => setHTTPOnly(event.target.checked)} /><span>{t('domain.httpOnly')}</span></label>
          <div className="deploy-note"><Icon name="terminal" size={17} /><span>{t('domain.deployProof')}</span></div>
          {selectedNode?.status !== 'online' && nodeID && <div className="form-warning"><Icon name="warning" size={17} />{t('domain.offlineWarning')}</div>}
          {error && <div className="form-error drawer-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        </div>
        <footer className="drawer-footer"><button className="cancel-button" type="button" onClick={onClose} disabled={busy}>{t('common.cancel')}</button><ActionButton type="submit" wide disabled={busy || availableNodes.length === 0}>{busy ? t('common.queueing') : t('domain.submit')}</ActionButton></footer>
      </form>
    </div>
  )
}

function FileField({ label, file, onChange, accept }: { label: string; file?: File; onChange: (file?: File) => void; accept: string }) {
  const { t } = usePreferences()
  return <label className={file ? 'file-field file-selected' : 'file-field'}><input type="file" accept={accept} onChange={(event) => onChange(event.target.files?.[0])} /><Icon name={file ? 'check' : 'upload'} size={18} /><span><strong>{label}</strong><small>{file ? file.name : t('certificate.chooseFile')}</small></span></label>
}
