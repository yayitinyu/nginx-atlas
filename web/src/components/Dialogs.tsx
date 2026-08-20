import { useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import type { ACMEAccount, CertificateAutomationInput, CertificateRecord, ControllerSettings, ControllerSettingsInput, DNSAccount, NodeRecord, ReleaseInfo } from '../types'
import { usePreferences } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, IconButton, StatusDot } from './Primitives'
import { SelectField } from './SelectField'

export type DNSAccountInput = { name: string; provider: string; credentials: Record<string, string>; keep_credentials: boolean }
export type ACMEAccountInput = { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string; keep_eab: boolean }
export type CertificateAutomationSettingsInput = { node_id: string; auto_renew: boolean; renew_before_days: number; acme_account_id: string; dns_account_id: string; dns_names: string[] }
export type CertificateSubmission =
  | { mode: 'upload'; input: CertificateAutomationInput; certificate: File; privateKey: File }
  | { mode: 'issue' | 'import'; input: CertificateAutomationInput }

function DialogShell({ open, title, description, onClose, children, wide = false }: {
  open: boolean
  title: string
  description: string
  onClose: () => void
  children: ReactNode
  wide?: boolean
}) {
  const { t } = usePreferences()
  const titleID = useId()
  useEffect(() => {
    if (!open) return
    const close = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="modal-layer" role="presentation" onMouseDown={(event) => event.currentTarget === event.target && onClose()}>
      <section className={`form-dialog ${wide ? 'form-dialog-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleID}>
        <header><div><h2 id={titleID}>{title}</h2>{description && <p>{description}</p>}</div><IconButton name="close" label={t('common.close')} onClick={onClose} /></header>
        {children}
      </section>
    </div>
  )
}

export function NodeManageDialog({ open, node, release, busy, onClose, onRename, onCheckRelease, onUpdateAtlas, onUpdateSystem, onRemoveAndUninstall }: {
  open: boolean
  node?: NodeRecord
  release?: ReleaseInfo
  busy: string
  onClose: () => void
  onRename: (name: string) => Promise<void>
  onCheckRelease: () => Promise<void>
  onUpdateAtlas: () => Promise<void>
  onUpdateSystem: () => Promise<void>
  onRemoveAndUninstall: () => Promise<string>
}) {
  const { t, locale } = usePreferences()
  const [name, setName] = useState('')
  const [confirm, setConfirm] = useState<'atlas' | 'system' | 'remove'>()
  const [uninstallCommand, setUninstallCommand] = useState('')
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!open || !node) return
    setName(node.name)
    setConfirm(undefined)
    setUninstallCommand('')
    setCopied(false)
  }, [open, node?.id, node?.name])
  if (!node) return null
  const nodeNeedsUpdate = Boolean(release && node.agent_version && (node.agent_version === 'dev' || isVersionNewer(release.latest_version, node.agent_version)))
  return (
    <DialogShell open={open} title={t('nodes.manageTitle', { node: node.name })} description={t(node.controller_installed ? 'nodes.manageControllerDescription' : 'nodes.manageDescription')} onClose={onClose} wide>
      <div className="node-manage-dialog node-manage-refined">
        <section className="node-manage-identity"><span className="node-machine"><Icon name="server" size={24} /></span><span><span className="node-name-line"><strong>{node.name}</strong>{node.controller_installed && <span className="controller-badge"><Icon name="home" size={13} />{t('nodes.controller')}</span>}</span><small>{node.os_name || [node.os, node.arch].filter(Boolean).join(' / ')}</small></span><span className={`node-state node-state-${node.status}`}>{t(`common.${node.status}`)}</span></section>
        <form className="rename-node-form" onSubmit={(event) => { event.preventDefault(); void onRename(name.trim()) }}><label><span>{t('nodes.rename')}</span><div className="field-control"><Icon name="edit" size={17} /><input value={name} onChange={(event) => setName(event.target.value)} /></div></label><button type="submit" disabled={busy === 'rename' || name.trim().length < 2 || name.trim() === node.name}>{busy === 'rename' ? t('common.saving') : t('common.save')}</button></form>
        <section className="node-action-section"><div className="node-action-heading"><span><strong>{t(node.controller_installed ? 'nodes.controllerRelease' : 'nodes.atlasRelease')}</strong><small>{t('nodes.versionPair', { current: node.agent_version || '—', latest: release?.latest_version || '—' })}</small></span><button type="button" onClick={() => void onCheckRelease()} disabled={busy === 'release'}><Icon name="refresh" size={16} />{t('nodes.checkUpdate')}</button></div>{release && <div className={nodeNeedsUpdate ? 'release-card release-available' : 'release-card'}><span><Icon name={nodeNeedsUpdate ? 'download' : 'check'} size={20} /></span><div><strong>{nodeNeedsUpdate ? t('nodes.updateAvailable', { version: release.latest_version }) : t('nodes.upToDate')}</strong><small>{release.published_at ? new Intl.DateTimeFormat(locale, { year: 'numeric', month: 'short', day: '2-digit' }).format(new Date(release.published_at)) : release.repository}</small></div>{nodeNeedsUpdate && (confirm === 'atlas' ? <div className="inline-confirm"><button type="button" onClick={() => setConfirm(undefined)}>{t('common.cancel')}</button><button type="button" onClick={() => void onUpdateAtlas()} disabled={busy === 'atlas'}>{busy === 'atlas' ? t('common.queueing') : t('nodes.confirmUpdate')}</button></div> : <button type="button" className="node-primary-action" onClick={() => setConfirm('atlas')}><Icon name="download" size={16} />{t('nodes.updateAtlas')}</button>)}</div>}</section>
        <section className="node-action-section"><div className="system-update-card"><span className="node-action-icon"><Icon name="package" size={21} /></span><span><strong>{t('nodes.systemUpdate')}</strong><small>{node.package_manager === 'apt' ? t('nodes.systemUpdateHint') : t('nodes.systemUpdateUnsupported')}</small></span>{confirm === 'system' ? <div className="inline-confirm danger-confirm"><button type="button" onClick={() => setConfirm(undefined)}>{t('common.cancel')}</button><button type="button" onClick={() => void onUpdateSystem()} disabled={busy === 'system'}>{busy === 'system' ? t('common.queueing') : t('nodes.confirmSystemUpdate')}</button></div> : <button type="button" onClick={() => setConfirm('system')} disabled={node.package_manager !== 'apt'}><Icon name="refresh" size={16} />{t('nodes.updatePackages')}</button>}</div></section>
        <section className="node-action-section uninstall-section">
          <div><strong>{t('nodes.removeAndUninstall')}</strong><small>{t('nodes.removeAndUninstallHint')}</small></div>
          {uninstallCommand ? <div className="uninstall-command"><pre>{uninstallCommand}</pre><button type="button" onClick={() => { void navigator.clipboard.writeText(uninstallCommand); setCopied(true) }}><Icon name={copied ? 'check' : 'copy'} size={16} />{t(copied ? 'common.copied' : 'nodes.copyUninstall')}</button></div> : confirm === 'remove' ? <div className="inline-confirm remove-node-confirm"><button type="button" onClick={() => setConfirm(undefined)}>{t('common.cancel')}</button><button type="button" disabled={busy === 'remove-node'} onClick={() => void onRemoveAndUninstall().then((command) => { if (command) setUninstallCommand(command); setConfirm(undefined) })}>{busy === 'remove-node' ? t('common.removing') : t('nodes.confirmRemove')}</button></div> : <button type="button" className="remove-node-button" onClick={() => setConfirm('remove')}><Icon name="trash" size={16} />{t('nodes.removeAndUninstall')}</button>}
        </section>
      </div>
    </DialogShell>
  )
}


export function DNSAccountDialog({ open, account, busy, onClose, onSave }: {
  open: boolean
  account?: DNSAccount
  busy: boolean
  onClose: () => void
  onSave: (input: DNSAccountInput, id?: string) => Promise<void>
}) {
  const { t } = usePreferences()
  const [token, setToken] = useState('')
  useEffect(() => {
    if (!open) return
    setToken('')
  }, [open, account?.id])
  function submit(event: FormEvent) {
    event.preventDefault()
    const value = token.trim()
    void onSave({ name: 'Cloudflare', provider: 'cloudflare', credentials: value ? { CLOUDFLARE_DNS_API_TOKEN: value } : {}, keep_credentials: Boolean(account) && !value }, account?.id)
  }
  return (
    <DialogShell open={open} title={account ? t('dialog.dnsEditTitle') : t('dialog.dnsAddTitle')} description={t('dialog.dnsDescription')} onClose={onClose}>
      <form className="dialog-form" onSubmit={submit}>
        <label><span>{t('settings.cloudflareToken')}</span><div className="field-control"><Icon name="key" size={17} /><input type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder={account ? t('dialog.keepCredentials') : 'Cloudflare API Token'} autoFocus /></div></label>
        <ActionButton wide plain disabled={busy || (!account && !token.trim())}>{busy ? t('common.saving') : t('common.save')}</ActionButton>
      </form>
    </DialogShell>
  )
}

export function ACMEAccountDialog({ open, account, busy, onClose, onSave }: {
  open: boolean
  account?: ACMEAccount
  busy: boolean
  onClose: () => void
  onSave: (input: ACMEAccountInput, id?: string) => Promise<void>
}) {
  const { t } = usePreferences()
  const [email, setEmail] = useState('')
  useEffect(() => {
    if (!open) return
    setEmail(account?.email ?? '')
  }, [open, account?.id])
  return (
    <DialogShell open={open} title={account ? t('dialog.acmeEditTitle') : t('dialog.acmeAddTitle')} description={t('dialog.acmeDescription')} onClose={onClose}>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void onSave({ name: account?.name ?? "Let's Encrypt", email: email.trim(), directory_url: account?.directory_url ?? 'https://acme-v02.api.letsencrypt.org/directory', eab_kid: '', eab_hmac: '', keep_eab: Boolean(account?.has_eab) }, account?.id) }}>
        <label><span>{t('dialog.email')}</span><div className="field-control"><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="admin@example.com" /></div></label>
        <ActionButton wide plain disabled={busy || !email.includes('@')}>{busy ? t('common.saving') : t('common.save')}</ActionButton>
      </form>
    </DialogShell>
  )
}

export function AccessSettingsDialog({ open, settings, busy, onClose, onSave }: {
  open: boolean
  settings: ControllerSettings
  busy: boolean
  onClose: () => void
  onSave: (input: ControllerSettingsInput) => Promise<void>
}) {
  const { t } = usePreferences()
  const [turnstileEnabled, setTurnstileEnabled] = useState(false)
  const [siteKey, setSiteKey] = useState('')
  const [secret, setSecret] = useState('')
  const [allowlist, setAllowlist] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setTurnstileEnabled(settings.turnstile_enabled)
    setSiteKey(settings.turnstile_site_key)
    setSecret('')
    setAllowlist(settings.panel_allowed_cidrs.join('\n'))
    setError('')
  // Background polling must not replace credentials or rules while this form is open.
  }, [open])

  function submit(event: FormEvent) {
    event.preventDefault()
    if (turnstileEnabled && (!siteKey.trim() || (!settings.turnstile_secret_configured && !secret.trim()))) {
      setError(t('settings.turnstileCredentialsRequired'))
      return
    }
    const panelAllowedCIDRs = allowlist.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean)
    void onSave({
      turnstile_enabled: turnstileEnabled,
      turnstile_site_key: siteKey.trim(),
      turnstile_secret: secret.trim(),
      panel_allowed_cidrs: panelAllowedCIDRs,
    })
  }

  return (
    <DialogShell open={open} title={t('settings.accessProtection')} description="" onClose={onClose} wide>
      <form className="dialog-form access-settings-form" onSubmit={submit}>
        <label className="switch-row access-turnstile-row">
          <button type="button" role="switch" aria-checked={turnstileEnabled} className={turnstileEnabled ? 'switch-on' : ''} onClick={() => setTurnstileEnabled((value) => !value)}><i /></button>
          <span><strong>Cloudflare Turnstile</strong></span>
        </label>
        {turnstileEnabled && <div className="access-key-grid">
          <label><span>Site Key</span><div className="field-control"><Icon name="key" size={17} /><input value={siteKey} onChange={(event) => setSiteKey(event.target.value)} autoComplete="off" /></div></label>
          <label><span>Secret Key</span><div className="field-control"><Icon name="lock" size={17} /><input type="password" value={secret} onChange={(event) => setSecret(event.target.value)} placeholder={settings.turnstile_secret_configured ? t('settings.keepSecret') : ''} autoComplete="new-password" /></div></label>
        </div>}
        <label className="allowlist-field">
          <span>{t('settings.ipAllowlist')}</span>
          <textarea value={allowlist} onChange={(event) => setAllowlist(event.target.value)} placeholder="203.0.113.8&#10;2001:db8::/48" />
          {settings.request_ip && <small>{t('settings.currentIP', { ip: settings.request_ip })}</small>}
        </label>
        {error && <div className="form-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        <ActionButton wide plain disabled={busy}>{busy ? t('common.saving') : t('common.save')}</ActionButton>
      </form>
    </DialogShell>
  )
}

export function CertificateDialog({ open, nodes, dnsAccounts, acmeAccounts, busy, onClose, onSubmit }: {
  open: boolean
  nodes: NodeRecord[]
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  busy: boolean
  onClose: () => void
  onSubmit: (submission: CertificateSubmission) => Promise<void>
}) {
  const { t } = usePreferences()
  const availableNodes = useMemo(() => nodes.filter((node) => node.status !== 'revoked'), [nodes])
  const [mode, setMode] = useState<'upload' | 'issue' | 'import'>('upload')
  const [domain, setDomain] = useState('')
  const [nodeID, setNodeID] = useState('')
  const [nodeDomain, setNodeDomain] = useState('')
  const [fullchain, setFullchain] = useState<File>()
  const [privkey, setPrivkey] = useState<File>()
  const [dnsAccountID, setDNSAccountID] = useState('')
  const [acmeAccountID, setACMEAccountID] = useState('')
  const [autoRenew, setAutoRenew] = useState(false)
  const [additionalNames, setAdditionalNames] = useState<string[]>([])
  const [nameDraft, setNameDraft] = useState('')
  const [syncNodeIDs, setSyncNodeIDs] = useState<string[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setMode('upload'); setDomain(''); setNodeDomain(''); setFullchain(undefined); setPrivkey(undefined)
    setNodeID(availableNodes[0]?.id ?? ''); setDNSAccountID(dnsAccounts[0]?.id ?? ''); setACMEAccountID(acmeAccounts[0]?.id ?? '')
    setAutoRenew(false); setAdditionalNames([]); setNameDraft(''); setSyncNodeIDs([]); setError('')
  // Only initialize when the dialog opens. Background polling replaces these
  // arrays and must never wipe a form the administrator is editing.
  }, [open])

  useEffect(() => {
    if (!open) return
    if (!availableNodes.some((node) => node.id === nodeID)) setNodeID(availableNodes[0]?.id ?? '')
    if (!dnsAccounts.some((account) => account.id === dnsAccountID)) setDNSAccountID(dnsAccounts[0]?.id ?? '')
    if (!acmeAccounts.some((account) => account.id === acmeAccountID)) setACMEAccountID(acmeAccounts[0]?.id ?? '')
  }, [open, availableNodes, nodeID, dnsAccounts, dnsAccountID, acmeAccounts, acmeAccountID])

  const selectedNode = availableNodes.find((node) => node.id === nodeID)
  const importableCertificates = (selectedNode?.certificates ?? []).filter((certificate) => certificate.key_matches && !certificate.error)
  useEffect(() => {
    if (mode !== 'import') return
    if (!importableCertificates.some((certificate) => certificate.domain === nodeDomain)) setNodeDomain(importableCertificates[0]?.domain ?? '')
  }, [mode, nodeID, nodeDomain, importableCertificates])

  function switchMode(next: 'upload' | 'issue' | 'import') {
    setMode(next)
    setError('')
    setAutoRenew(next === 'issue')
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const certificateDomain = (mode === 'upload' ? '' : mode === 'import' ? nodeDomain : domain).trim().toLowerCase()
    if (mode !== 'upload' && !certificateDomain.includes('.')) { setError(t('certificate.validationDomain')); return }
    if (mode === 'upload' && (!fullchain || !privkey)) { setError(t('certificate.validationFiles')); return }
    if ((mode !== 'upload' || autoRenew) && !nodeID) { setError(t('certificate.validationNode')); return }
    const input: CertificateAutomationInput = {
      domain: certificateDomain,
      node_id: mode === 'upload' && !autoRenew ? '' : nodeID,
      auto_renew: autoRenew,
      renew_before_days: 30,
      dns_account_id: mode === 'issue' || autoRenew ? dnsAccountID : undefined,
      acme_account_id: mode === 'issue' || autoRenew ? acmeAccountID : undefined,
      sync_node_ids: syncNodeIDs,
      dns_names: mode === 'issue' ? [certificateDomain, ...additionalNames] : [],
    }
    if (mode === 'upload') await onSubmit({ mode, input, certificate: fullchain!, privateKey: privkey! })
    else await onSubmit({ mode, input })
  }

  const nodeOptions = availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.status === 'online' ? t('common.online') : t('common.offline') }))
  const otherNodes = availableNodes.filter((node) => node.id !== nodeID || mode === 'upload')
  return (
    <DialogShell open={open} title={t('certificate.add')} description="" onClose={onClose} wide>
      <form className="certificate-dialog-form" onSubmit={submit}>
        <div className="certificate-mode-grid">
          {(['upload', 'issue', 'import'] as const).map((item) => <button type="button" className={mode === item ? 'certificate-mode selected' : 'certificate-mode'} onClick={() => switchMode(item)} key={item}><Icon name={item === 'upload' ? 'upload' : item === 'issue' ? 'certificate' : 'server'} size={24} /><span><strong>{t(`certificate.mode${item === 'upload' ? 'Upload' : item === 'issue' ? 'Issue' : 'Import'}`)}</strong><small>{t(`certificate.mode${item === 'upload' ? 'Upload' : item === 'issue' ? 'Issue' : 'Import'}Hint`)}</small></span>{mode === item && <Icon name="check" size={16} weight="bold" />}</button>)}
        </div>
        <div className="certificate-dialog-scroll">
          {mode === 'issue' && <label className="dialog-field"><span>{t('certificate.domain')}</span><div className="field-control"><Icon name="globe" size={17} /><input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="atlas.example.com" /></div></label>}
          {mode === 'issue' && <CertificateNamesField primary={domain.trim().toLowerCase()} values={additionalNames} draft={nameDraft} onDraft={setNameDraft} onChange={setAdditionalNames} />}
          {(mode === 'issue' || mode === 'import' || autoRenew) && <label className="dialog-field"><span>{mode === 'import' ? t('certificate.sourceNode') : t('certificate.signingNode')}</span><SelectField ariaLabel={t('certificate.signingNode')} value={nodeID} onChange={(value) => { setNodeID(value); setSyncNodeIDs((items) => items.filter((id) => id !== value)) }} placeholder={t('common.select')} icon="server" options={nodeOptions} /></label>}
          {mode === 'import' && <label className="dialog-field"><span>{t('certificate.nodeCertificate')}</span><SelectField ariaLabel={t('certificate.nodeCertificate')} value={nodeDomain} onChange={setNodeDomain} placeholder={t('certificate.noNodeCertificates')} icon="shield" options={importableCertificates.map((certificate) => ({ value: certificate.domain, label: certificate.domain, description: certificate.not_after ? new Date(certificate.not_after).toLocaleDateString() : certificate.path }))} /></label>}
          {mode === 'upload' && <div className="certificate-upload-surface"><div className="upload-recognition"><Icon name="shield" size={20} /><span>{t('certificate.detectDomain')}</span></div><div className="certificate-upload-grid"><FileField label={t('certificate.certificateFile')} file={fullchain} onChange={setFullchain} accept="" /><FileField label={t('certificate.privateKeyFile')} file={privkey} onChange={setPrivkey} accept="" /></div></div>}
          <label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: 30 })}</small></span></label>
          <div className="certificate-node-field"><span>{t('certificate.syncNodes')}</span><div className="node-check-list">{otherNodes.length ? otherNodes.map((node) => <button type="button" className={syncNodeIDs.includes(node.id) ? 'selected' : ''} onClick={() => setSyncNodeIDs((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])} key={node.id}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /><span><strong>{node.name}</strong><small>{node.hostname || node.status}</small></span>{syncNodeIDs.includes(node.id) && <Icon name="check" size={16} weight="bold" />}</button>) : <small>{t('common.none')}</small>}</div><small>{t('certificate.syncHint')}</small></div>
          {error && <div className="form-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        </div>
        <footer className="certificate-dialog-footer"><button className="text-button" type="button" onClick={onClose}>{t('common.cancel')}</button><ActionButton type="submit" plain disabled={busy}>{busy ? t('common.queueing') : t(mode === 'upload' ? 'certificate.submitUpload' : mode === 'issue' ? 'certificate.submitIssue' : 'certificate.submitImport')}</ActionButton></footer>
      </form>
    </DialogShell>
  )
}

function CertificateNamesField({ primary, values, draft, onDraft, onChange }: {
  primary: string
  values: string[]
  draft: string
  onDraft: (value: string) => void
  onChange: (values: string[]) => void
}) {
  const { t } = usePreferences()
  function addDraft() {
    const candidates = draft.split(/[\s,]+/).map((value) => value.trim().toLowerCase()).filter(Boolean)
    if (!candidates.length) return
    onChange([...new Set([...values, ...candidates].filter((value) => value !== primary))].slice(0, 19))
    onDraft('')
  }
  return <div className="certificate-names-field"><span>{t('certificate.additionalNames')}</span><div className="certificate-name-chips">{primary && <span className="primary-name"><Icon name="check" size={14} />{primary}</span>}{values.map((value) => <button type="button" key={value} onClick={() => onChange(values.filter((item) => item !== value))}>{value}<Icon name="close" size={13} /></button>)}</div><div className="certificate-name-entry"><div className="field-control"><Icon name="globe" size={17} /><input value={draft} onChange={(event) => onDraft(event.target.value)} onBlur={addDraft} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ',') { event.preventDefault(); addDraft() } }} placeholder="*.example.com" /></div><button type="button" onClick={addDraft} disabled={!draft.trim()}><Icon name="plus" size={17} />{t('common.add')}</button></div><small>{t('certificate.additionalNamesHint')}</small></div>
}

function isVersionNewer(latest: string, current: string): boolean {
  const parse = (value: string) => {
    const normalized = value.trim().replace(/^v/, '')
    const separator = normalized.indexOf('-')
    const core = separator >= 0 ? normalized.slice(0, separator) : normalized
    return { numbers: core.split('.').map((part) => Number(part)), prerelease: separator >= 0 }
  }
  const next = parse(latest)
  const installed = parse(current)
  if (!next.numbers.length || !installed.numbers.length || [...next.numbers, ...installed.numbers].some((part) => !Number.isInteger(part) || part < 0)) return false
  for (let index = 0; index < Math.max(next.numbers.length, installed.numbers.length, 3); index += 1) {
    const difference = (next.numbers[index] ?? 0) - (installed.numbers[index] ?? 0)
    if (difference !== 0) return difference > 0
  }
  return installed.prerelease && !next.prerelease
}

function FileField({ label, file, onChange, accept }: { label: string; file?: File; onChange: (file?: File) => void; accept: string }) {
  const { t } = usePreferences()
  return <label className={file ? 'file-field file-selected' : 'file-field'}><input type="file" accept={accept} onChange={(event) => onChange(event.target.files?.[0])} /><Icon name={file ? 'check' : 'upload'} size={19} /><span><strong>{label}</strong><small>{file ? file.name : t('certificate.chooseFile')}</small></span></label>
}

export function CertificateAutomationDialog({ open, certificate, nodes, dnsAccounts, acmeAccounts, busy, onClose, onSave }: {
  open: boolean
  certificate?: CertificateRecord
  nodes: NodeRecord[]
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  busy: boolean
  onClose: () => void
  onSave: (input: CertificateAutomationSettingsInput) => Promise<void>
}) {
  const { t } = usePreferences()
  const availableNodes = nodes.filter((node) => node.status !== 'revoked')
  const [nodeID, setNodeID] = useState('')
  const [dnsAccountID, setDNSAccountID] = useState('')
  const [acmeAccountID, setACMEAccountID] = useState('')
  const [autoRenew, setAutoRenew] = useState(false)
  const [renewDays, setRenewDays] = useState('30')
  const [names, setNames] = useState<string[]>([])
  const [nameDraft, setNameDraft] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    if (!open || !certificate) return
    setNodeID(certificate.issuer_node_id || availableNodes[0]?.id || '')
    setDNSAccountID(certificate.dns_account_id || dnsAccounts[0]?.id || '')
    setACMEAccountID(certificate.acme_account_id || acmeAccounts[0]?.id || '')
    setAutoRenew(certificate.auto_renew)
    setRenewDays(String(certificate.renew_before_days || 30))
    setNames((certificate.requested_dns_names?.length ? certificate.requested_dns_names : certificate.dns_names).filter((name) => name !== certificate.domain))
    setNameDraft('')
    setError('')
  }, [open, certificate?.id])
  useEffect(() => {
    if (!open || !certificate) return
    if (!availableNodes.some((node) => node.id === nodeID)) {
      const preferredNodeID = availableNodes.some((node) => node.id === certificate.issuer_node_id) ? certificate.issuer_node_id : availableNodes[0]?.id
      setNodeID(preferredNodeID ?? '')
    }
    if (!dnsAccounts.some((account) => account.id === dnsAccountID)) {
      const preferredDNSID = dnsAccounts.some((account) => account.id === certificate.dns_account_id) ? certificate.dns_account_id : dnsAccounts[0]?.id
      setDNSAccountID(preferredDNSID ?? '')
    }
    if (!acmeAccounts.some((account) => account.id === acmeAccountID)) {
      const preferredACMEID = acmeAccounts.some((account) => account.id === certificate.acme_account_id) ? certificate.acme_account_id : acmeAccounts[0]?.id
      setACMEAccountID(preferredACMEID ?? '')
    }
  }, [open, certificate, availableNodes, nodeID, dnsAccounts, dnsAccountID, acmeAccounts, acmeAccountID])
  if (!certificate) return null
  function submit(event: FormEvent) {
    event.preventDefault()
    const days = Number(renewDays)
    if (!nodeID || !Number.isInteger(days) || days < 7 || days > 60) {
      setError(t('certificate.validationAutomation'))
      return
    }
    void onSave({ node_id: nodeID, dns_account_id: dnsAccountID, acme_account_id: acmeAccountID, auto_renew: autoRenew, renew_before_days: days, dns_names: [certificate!.domain, ...names] })
  }
  return (
    <DialogShell open={open} title={t('certificate.editAutomation')} description={t('certificate.editAutomationHint', { domain: certificate.domain })} onClose={onClose} wide>
      <form className="certificate-dialog-form automation-dialog-form" onSubmit={submit}>
        <div className="certificate-dialog-scroll">
          <CertificateNamesField primary={certificate.domain} values={names} draft={nameDraft} onDraft={setNameDraft} onChange={setNames} />
          <div className="account-fields certificate-account-fields compact-automation-fields">
            <label><span>{t('certificate.signingNode')}</span><SelectField ariaLabel={t('certificate.signingNode')} value={nodeID} onChange={setNodeID} icon="server" options={availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.os_name || node.hostname }))} /></label>
            <label><span>{t('certificate.renewDays')}</span><div className="field-control"><Icon name="clock" size={17} /><input inputMode="numeric" value={renewDays} onChange={(event) => setRenewDays(event.target.value.replace(/\D/g, '').slice(0, 2))} /></div></label>
          </div>
          <label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: Number(renewDays) || 30 })}</small></span></label>
          {error && <div className="form-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        </div>
        <footer className="certificate-dialog-footer"><button className="text-button" type="button" onClick={onClose}>{t('common.cancel')}</button><ActionButton type="submit" plain disabled={busy}>{busy ? t('common.saving') : t('common.save')}</ActionButton></footer>
      </form>
    </DialogShell>
  )
}

export function SyncDialog({ open, certificate, nodes, busy, onClose, onSync }: {
  open: boolean
  certificate?: CertificateRecord
  nodes: NodeRecord[]
  busy: boolean
  onClose: () => void
  onSync: (nodeIDs: string[]) => Promise<void>
}) {
  const { t } = usePreferences()
  const [selected, setSelected] = useState<string[]>([])
  useEffect(() => { if (open && certificate) setSelected(nodes.filter((node) => node.status !== 'revoked' && !certificate.deployed_node_ids.includes(node.id)).map((node) => node.id)) }, [open, certificate?.id])
  return <DialogShell open={open} title={t('dialog.syncTitle')} description={certificate ? t('dialog.syncDescription', { domain: certificate.domain }) : ''} onClose={onClose}><div className="sync-dialog-body"><div className="sync-dialog-list">{nodes.filter((node) => node.status !== 'revoked').map((node) => <button key={node.id} className={selected.includes(node.id) ? 'selected' : ''} onClick={() => setSelected((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /><span><strong>{node.name}</strong><small>{node.status === 'online' ? t('dialog.syncOnline') : t('dialog.syncOffline')}</small></span>{selected.includes(node.id) && <Icon name="check" size={17} />}</button>)}</div><ActionButton wide plain disabled={busy || selected.length === 0} onClick={() => void onSync(selected)}>{busy ? t('common.queueing') : t('dialog.syncAction', { count: selected.length })}</ActionButton></div></DialogShell>
}

export function PasswordDialog({ open, busy, onClose, onSave }: { open: boolean; busy: boolean; onClose: () => void; onSave: (currentPassword: string, newPassword: string) => Promise<void> }) {
  const { t } = usePreferences()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { if (open) { setCurrentPassword(''); setNewPassword(''); setConfirmation(''); setError('') } }, [open])
  return <DialogShell open={open} title={t('dialog.passwordTitle')} description={t('dialog.passwordDescription')} onClose={onClose}><form className="dialog-form" onSubmit={(event) => { event.preventDefault(); if (newPassword !== confirmation) { setError(t('dialog.passwordMismatch')); return }; void onSave(currentPassword, newPassword) }}><label><span>{t('dialog.currentPassword')}</span><div className="field-control"><Icon name="key" size={17} /><input type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></div></label><label><span>{t('dialog.newPassword')}</span><div className="field-control"><Icon name="lock" size={17} /><input type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></div></label><label><span>{t('dialog.confirmPassword')}</span><div className="field-control"><Icon name="check" size={17} /><input type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div></label><div className="dialog-note"><Icon name="shield" size={17} /><span>{t('dialog.passwordRule')}</span></div>{error && <div className="form-error" role="alert">{error}</div>}<ActionButton wide plain disabled={busy || currentPassword.length < 12 || newPassword.length < 12}>{busy ? t('common.saving') : t('dialog.changePassword')}</ActionButton></form></DialogShell>
}
