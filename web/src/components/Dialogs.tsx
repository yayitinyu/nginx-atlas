import { useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import type { ACMEAccount, CertificateAutomationInput, CertificateRecord, DNSAccount, EnrollmentResponse, NodeRecord, ReleaseInfo, UninstallCommand } from '../types'
import { api } from '../api'
import { usePreferences } from '../preferences'
import { Icon } from './Icon'
import { ActionButton, IconButton, StatusDot } from './Primitives'
import { SelectField } from './SelectField'

export type DNSAccountInput = { name: string; provider: string; credentials: Record<string, string>; keep_credentials: boolean }
export type ACMEAccountInput = { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string; keep_eab: boolean }
export type CertificateAutomationSettingsInput = { node_id: string; auto_renew: boolean; renew_before_days: number; acme_account_id: string; dns_account_id: string; dns_names: string[] }
export type CertificateSubmission =
  | { mode: 'upload'; input: CertificateAutomationInput; fullchain: File; privkey: File }
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
        <header><div><h2 id={titleID}>{title}</h2><p>{description}</p></div><IconButton name="close" label={t('common.close')} onClick={onClose} /></header>
        {children}
      </section>
    </div>
  )
}

export function NodeDialog({ open, busy, result, onClose, onCreate }: {
  open: boolean
  busy: boolean
  result?: EnrollmentResponse
  onClose: () => void
  onCreate: (name: string) => Promise<void>
}) {
  const { t } = usePreferences()
  const [name, setName] = useState('')
  const [copied, setCopied] = useState(false)
  useEffect(() => { if (open && !result) { setName(''); setCopied(false) } }, [open, result])
  return (
    <DialogShell open={open} title={result ? t('dialog.commandReady') : t('dialog.nodeTitle')} description={result ? t('dialog.commandHint') : t('dialog.nodeDescription')} onClose={onClose}>
      {result ? <div className="command-result"><pre>{result.command}</pre><button className="copy-command" onClick={() => { void navigator.clipboard.writeText(result.command); setCopied(true) }}><Icon name={copied ? 'check' : 'copy'} size={17} />{copied ? t('dialog.copied') : t('dialog.copyCommand')}</button><small>{t('dialog.commandHint')}</small></div> : <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void onCreate(name) }}><label><span>{t('dialog.nodeName')}</span><div className="field-control"><Icon name="server" size={17} /><input value={name} onChange={(event) => setName(event.target.value)} placeholder={t('dialog.nodeNamePlaceholder')} autoFocus /></div></label><ActionButton wide icon="terminal" disabled={busy || name.trim().length < 2}>{busy ? t('common.queueing') : t('dialog.generate')}</ActionButton></form>}
    </DialogShell>
  )
}

export function NodeManageDialog({ open, node, release, uninstall, busy, onClose, onRename, onCheckRelease, onUpdateAtlas, onUpdateSystem }: {
  open: boolean
  node?: NodeRecord
  release?: ReleaseInfo
  uninstall?: UninstallCommand
  busy: string
  onClose: () => void
  onRename: (name: string) => Promise<void>
  onCheckRelease: () => Promise<void>
  onUpdateAtlas: () => Promise<void>
  onUpdateSystem: () => Promise<void>
}) {
  const { t, locale } = usePreferences()
  const [name, setName] = useState('')
  const [confirm, setConfirm] = useState<'atlas' | 'system'>()
  const [copied, setCopied] = useState(false)
  const [enrollmentCmd, setEnrollmentCmd] = useState('')
  const [enrollmentCopied, setEnrollmentCopied] = useState(false)
  const [fetchingCmd, setFetchingCmd] = useState(false)
  useEffect(() => {
    if (!open || !node) return
    setName(node.name)
    setConfirm(undefined)
    setCopied(false)
    setEnrollmentCmd('')
    setEnrollmentCopied(false)
  }, [open, node?.id, node?.name])
  if (!node) return null
  const nodeNeedsUpdate = Boolean(release && node.agent_version && (node.agent_version === 'dev' || isVersionNewer(release.latest_version, node.agent_version)))
  return <DialogShell open={open} title={t('nodes.manageTitle', { node: node.name })} description={t(node.controller_installed ? 'nodes.manageControllerDescription' : 'nodes.manageDescription')} onClose={onClose} wide><div className="node-manage-dialog"><section className="node-manage-identity"><span className="node-machine"><Icon name="server" size={24} /></span><span><span className="node-name-line"><strong>{node.name}</strong>{node.controller_installed && <span className="controller-badge"><Icon name="home" size={13} />{t('nodes.controller')}</span>}</span><small>{node.os_name || [node.os, node.arch].filter(Boolean).join(' / ')}</small></span><span className={`node-state node-state-${node.status}`}>{t(`common.${node.status}`)}</span></section><form className="rename-node-form" onSubmit={(event) => { event.preventDefault(); void onRename(name.trim()) }}><label><span>{t('nodes.rename')}</span><div className="field-control"><Icon name="edit" size={17} /><input value={name} onChange={(event) => setName(event.target.value)} /></div></label><button type="submit" disabled={busy === 'rename' || name.trim().length < 2 || name.trim() === node.name}>{busy === 'rename' ? t('common.saving') : t('common.save')}</button></form><section className="node-action-section"><div className="node-action-heading"><span><strong>{t(node.controller_installed ? 'nodes.controllerRelease' : 'nodes.atlasRelease')}</strong><small>{t('nodes.versionPair', { current: node.agent_version || '—', latest: release?.latest_version || '—' })}</small></span><button type="button" onClick={() => void onCheckRelease()} disabled={busy === 'release'}><Icon name="refresh" size={16} />{t('nodes.checkUpdate')}</button></div>{release && <div className={nodeNeedsUpdate ? 'release-card release-available' : 'release-card'}><span><Icon name={nodeNeedsUpdate ? 'download' : 'check'} size={20} /></span><div><strong>{nodeNeedsUpdate ? t('nodes.updateAvailable', { version: release.latest_version }) : t('nodes.upToDate')}</strong><small>{release.published_at ? new Intl.DateTimeFormat(locale, { year: 'numeric', month: 'short', day: '2-digit' }).format(new Date(release.published_at)) : release.repository}</small></div>{confirm === 'atlas' ? <div className="inline-confirm"><button type="button" onClick={() => setConfirm(undefined)}>{t('common.cancel')}</button><button type="button" onClick={() => void onUpdateAtlas()} disabled={busy === 'atlas'}>{busy === 'atlas' ? t('common.queueing') : t('nodes.confirmUpdate')}</button></div> : <button type="button" className="node-primary-action" onClick={() => setConfirm('atlas')}><Icon name="download" size={16} />{t('nodes.updateAtlas')}</button>}</div>}</section><section className="node-action-section"><div className="system-update-card"><span className="node-action-icon"><Icon name="package" size={21} /></span><span><strong>{t('nodes.systemUpdate')}</strong><small>{node.package_manager === 'apt' ? t('nodes.systemUpdateHint') : t('nodes.systemUpdateUnsupported')}</small></span>{confirm === 'system' ? <div className="inline-confirm danger-confirm"><button type="button" onClick={() => setConfirm(undefined)}>{t('common.cancel')}</button><button type="button" onClick={() => void onUpdateSystem()} disabled={busy === 'system'}>{busy === 'system' ? t('common.queueing') : t('nodes.confirmSystemUpdate')}</button></div> : <button type="button" onClick={() => setConfirm('system')} disabled={node.package_manager !== 'apt'}><Icon name="refresh" size={16} />{t('nodes.updatePackages')}</button>}</div></section><section className="node-action-section reinstall-section"><div><strong>{t('nodes.reinstallTitle')}</strong><small>{t('nodes.reinstallHint')}</small></div>{enrollmentCmd ? <div className="uninstall-command"><pre>{enrollmentCmd}</pre><button type="button" onClick={() => { void navigator.clipboard.writeText(enrollmentCmd); setEnrollmentCopied(true) }}><Icon name={enrollmentCopied ? 'check' : 'copy'} size={17} />{enrollmentCopied ? t('dialog.copied') : t('nodes.copyInstall')}</button></div> : <button type="button" className="inline-action" disabled={fetchingCmd} onClick={async () => { setFetchingCmd(true); try { const res = await api.createEnrollment(node.name); setEnrollmentCmd(res.command) } catch (err) { console.error(err) } finally { setFetchingCmd(false) } }}><Icon name="terminal" size={16} />{fetchingCmd ? t('common.loading') : t('nodes.generateInstallCommand')}</button>}</section><section className="node-action-section uninstall-section"><div><strong>{t('nodes.uninstallTitle')}</strong><small>{t('nodes.uninstallHint')}</small></div>{uninstall ? <div className="uninstall-command"><pre>{uninstall.command}</pre><button type="button" onClick={() => { void navigator.clipboard.writeText(uninstall.command); setCopied(true) }}><Icon name={copied ? 'check' : 'copy'} size={17} />{copied ? t('dialog.copied') : t('nodes.copyUninstall')}</button></div> : <div className="loading-inline"><span className="loading-orbit" />{t('common.loading')}</div>}</section></div></DialogShell>
}

export function DNSAccountDialog({ open, account, busy, onClose, onSave }: {
  open: boolean
  account?: DNSAccount
  busy: boolean
  onClose: () => void
  onSave: (input: DNSAccountInput, id?: string) => Promise<void>
}) {
  const { t } = usePreferences()
  const [name, setName] = useState('')
  const [provider, setProvider] = useState('cloudflare')
  const [replaceCredentials, setReplaceCredentials] = useState(true)
  const [credentials, setCredentials] = useState([{ key: 'CLOUDFLARE_DNS_API_TOKEN', value: '' }])
  useEffect(() => {
    if (!open) return
    setName(account?.name ?? '')
    setProvider(account?.provider ?? 'cloudflare')
    setReplaceCredentials(!account)
    setCredentials(account?.credential_keys.length ? account.credential_keys.map((key) => ({ key, value: '' })) : [{ key: 'CLOUDFLARE_DNS_API_TOKEN', value: '' }])
  }, [open, account?.id])
  function submit(event: FormEvent) {
    event.preventDefault()
    const values = replaceCredentials ? Object.fromEntries(credentials.map((item) => [item.key.trim().toUpperCase(), item.value.trim()])) : {}
    void onSave({ name: name.trim(), provider: provider.trim().toLowerCase(), credentials: values, keep_credentials: Boolean(account) && !replaceCredentials }, account?.id)
  }
  const invalidCredentials = replaceCredentials && credentials.some((item) => !item.key.trim() || !item.value.trim())
  return (
    <DialogShell open={open} title={account ? t('dialog.dnsEditTitle') : t('dialog.dnsAddTitle')} description={t('dialog.dnsDescription')} onClose={onClose}>
      <form className="dialog-form" onSubmit={submit}>
        <label><span>{t('dialog.accountName')}</span><div className="field-control"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Cloudflare" /></div></label>
        <label><span>{t('dialog.provider')}</span><div className="field-control"><input value={provider} onChange={(event) => setProvider(event.target.value.toLowerCase())} placeholder="cloudflare" /></div></label>
        {account && <label className="switch-row compact-switch"><button type="button" role="switch" aria-checked={!replaceCredentials} className={!replaceCredentials ? 'switch-on' : ''} onClick={() => setReplaceCredentials((value) => !value)}><i /></button><span><strong>{t('dialog.keepCredentials')}</strong><small>{t('dialog.credentialHint')}</small></span></label>}
        {replaceCredentials && <div className="credential-editor"><div className="credential-title"><span>{t('dialog.credentials')}</span><button type="button" onClick={() => setCredentials((items) => [...items, { key: '', value: '' }])}><Icon name="plus" size={15} />{t('dialog.addCredential')}</button></div>{credentials.map((item, index) => <div className="credential-line" key={`${item.key}-${index}`}><input aria-label={t('dialog.credentialName', { index: index + 1 })} value={item.key} onChange={(event) => setCredentials((items) => items.map((value, itemIndex) => itemIndex === index ? { ...value, key: event.target.value.toUpperCase() } : value))} placeholder="CLOUDFLARE_DNS_API_TOKEN" /><input aria-label={t('dialog.credentialValue', { index: index + 1 })} type="password" value={item.value} onChange={(event) => setCredentials((items) => items.map((value, itemIndex) => itemIndex === index ? { ...value, value: event.target.value } : value))} placeholder="••••••••••••" />{credentials.length > 1 && <IconButton name="close" label={t('dialog.removeCredential')} type="button" onClick={() => setCredentials((items) => items.filter((_, itemIndex) => itemIndex !== index))} />}</div>)}</div>}
        {replaceCredentials && <div className="dialog-note"><Icon name="shield" size={17} /><span>{t('dialog.credentialHint')}</span></div>}
        <ActionButton wide disabled={busy || name.trim().length < 2 || invalidCredentials}>{busy ? t('common.saving') : t('common.save')}</ActionButton>
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
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [directory, setDirectory] = useState('https://acme-v02.api.letsencrypt.org/directory')
  const [eabMode, setEABMode] = useState<'none' | 'keep' | 'replace'>('none')
  const [eabKID, setEABKID] = useState('')
  const [eabHMAC, setEABHMAC] = useState('')
  useEffect(() => {
    if (!open) return
    setName(account?.name ?? '')
    setEmail(account?.email ?? '')
    setDirectory(account?.directory_url ?? 'https://acme-v02.api.letsencrypt.org/directory')
    setEABMode(account?.has_eab ? 'keep' : 'none')
    setEABKID('')
    setEABHMAC('')
  }, [open, account?.id])
  const eabInvalid = eabMode === 'replace' && (!eabKID.trim() || !eabHMAC.trim())
  return (
    <DialogShell open={open} title={account ? t('dialog.acmeEditTitle') : t('dialog.acmeAddTitle')} description={t('dialog.acmeDescription')} onClose={onClose}>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void onSave({ name: name.trim(), email: email.trim(), directory_url: directory.trim(), eab_kid: eabMode === 'replace' ? eabKID.trim() : '', eab_hmac: eabMode === 'replace' ? eabHMAC : '', keep_eab: eabMode === 'keep' }, account?.id) }}>
        <label><span>{t('dialog.accountName')}</span><div className="field-control"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Let's Encrypt" /></div></label>
        <label><span>{t('dialog.email')}</span><div className="field-control"><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="admin@example.com" /></div></label>
        <label><span>{t('dialog.directory')}</span><div className="field-control"><input type="url" value={directory} onChange={(event) => setDirectory(event.target.value)} /></div></label>
        <div className="eab-details"><span className="eab-label">{t('dialog.eab')}</span><div className="segmented-control eab-segments">{account?.has_eab && <button type="button" className={eabMode === 'keep' ? 'selected' : ''} onClick={() => setEABMode('keep')}>{t('dialog.keepEAB')}</button>}<button type="button" className={eabMode === 'replace' ? 'selected' : ''} onClick={() => setEABMode('replace')}>{t('dialog.replaceCredentials')}</button><button type="button" className={eabMode === 'none' ? 'selected' : ''} onClick={() => setEABMode('none')}>{t('dialog.clearEAB')}</button></div>{eabMode === 'replace' && <><label><span>{t('dialog.eabKID')}</span><div className="field-control"><input value={eabKID} onChange={(event) => setEABKID(event.target.value)} /></div></label><label><span>{t('dialog.eabHMAC')}</span><div className="field-control"><input type="password" value={eabHMAC} onChange={(event) => setEABHMAC(event.target.value)} /></div></label></>}</div>
        <ActionButton wide disabled={busy || name.trim().length < 2 || !email.includes('@') || eabInvalid}>{busy ? t('common.saving') : t('common.save')}</ActionButton>
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
    const certificateDomain = (mode === 'import' ? nodeDomain : domain).trim().toLowerCase()
    if (!certificateDomain.includes('.')) { setError(t('certificate.validationDomain')); return }
    if (mode === 'upload' && (!fullchain || !privkey)) { setError(t('certificate.validationFiles')); return }
    if ((mode !== 'upload' || autoRenew) && !nodeID) { setError(t('certificate.validationNode')); return }
    if ((mode === 'issue' || autoRenew) && (!dnsAccountID || !acmeAccountID)) { setError(t('certificate.validationAccounts')); return }
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
    if (mode === 'upload') await onSubmit({ mode, input, fullchain: fullchain!, privkey: privkey! })
    else await onSubmit({ mode, input })
  }

  const nodeOptions = availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.status === 'online' ? t('common.online') : t('common.offline') }))
  const showAutomation = mode === 'issue' || autoRenew
  const otherNodes = availableNodes.filter((node) => node.id !== nodeID || mode === 'upload')
  return (
    <DialogShell open={open} title={t('certificate.add')} description={t('certificate.description')} onClose={onClose} wide>
      <form className="certificate-dialog-form" onSubmit={submit}>
        <div className="certificate-mode-grid">
          {(['upload', 'issue', 'import'] as const).map((item) => <button type="button" className={mode === item ? 'certificate-mode selected' : 'certificate-mode'} onClick={() => switchMode(item)} key={item}><Icon name={item === 'upload' ? 'upload' : item === 'issue' ? 'certificate' : 'server'} size={24} /><span><strong>{t(`certificate.mode${item === 'upload' ? 'Upload' : item === 'issue' ? 'Issue' : 'Import'}`)}</strong><small>{t(`certificate.mode${item === 'upload' ? 'Upload' : item === 'issue' ? 'Issue' : 'Import'}Hint`)}</small></span>{mode === item && <Icon name="check" size={16} weight="bold" />}</button>)}
        </div>
        <div className="certificate-dialog-scroll">
          {mode !== 'import' && <label className="dialog-field"><span>{t('certificate.domain')}</span><div className="field-control"><Icon name="globe" size={17} /><input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="atlas.example.com" /></div></label>}
          {mode === 'issue' && <CertificateNamesField primary={domain.trim().toLowerCase()} values={additionalNames} draft={nameDraft} onDraft={setNameDraft} onChange={setAdditionalNames} />}
          {(mode === 'issue' || mode === 'import' || autoRenew) && <label className="dialog-field"><span>{mode === 'import' ? t('certificate.sourceNode') : t('certificate.signingNode')}</span><SelectField ariaLabel={t('certificate.signingNode')} value={nodeID} onChange={(value) => { setNodeID(value); setSyncNodeIDs((items) => items.filter((id) => id !== value)) }} placeholder={t('common.select')} icon="server" options={nodeOptions} /></label>}
          {mode === 'import' && <label className="dialog-field"><span>{t('certificate.nodeCertificate')}</span><SelectField ariaLabel={t('certificate.nodeCertificate')} value={nodeDomain} onChange={setNodeDomain} placeholder={t('certificate.noNodeCertificates')} icon="shield" options={importableCertificates.map((certificate) => ({ value: certificate.domain, label: certificate.domain, description: certificate.not_after ? new Date(certificate.not_after).toLocaleDateString() : certificate.path }))} /></label>}
          {mode === 'upload' && <div className="certificate-upload-grid"><FileField label={t('certificate.fullchain')} file={fullchain} onChange={setFullchain} accept=".pem,.crt" /><FileField label={t('certificate.privkey')} file={privkey} onChange={setPrivkey} accept=".pem,.key" /></div>}
          <label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: 30 })}</small></span></label>
          {showAutomation && <div className="account-fields certificate-account-fields"><label><span>{t('certificate.dnsAccount')}</span><SelectField ariaLabel={t('certificate.dnsAccount')} value={dnsAccountID} onChange={setDNSAccountID} placeholder={t('common.select')} icon="dns" options={dnsAccounts.map((account) => ({ value: account.id, label: account.name, description: account.provider }))} /></label><label><span>{t('certificate.acmeAccount')}</span><SelectField ariaLabel={t('certificate.acmeAccount')} value={acmeAccountID} onChange={setACMEAccountID} placeholder={t('common.select')} icon="key" options={acmeAccounts.map((account) => ({ value: account.id, label: account.name, description: account.email }))} /></label></div>}
          <div className="certificate-node-field"><span>{t('certificate.syncNodes')}</span><div className="node-check-list">{otherNodes.length ? otherNodes.map((node) => <button type="button" className={syncNodeIDs.includes(node.id) ? 'selected' : ''} onClick={() => setSyncNodeIDs((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])} key={node.id}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /><span><strong>{node.name}</strong><small>{node.hostname || node.status}</small></span>{syncNodeIDs.includes(node.id) && <Icon name="check" size={16} weight="bold" />}</button>) : <small>{t('common.none')}</small>}</div><small>{t('certificate.syncHint')}</small></div>
          {error && <div className="form-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        </div>
        <footer className="certificate-dialog-footer"><button className="text-button" type="button" onClick={onClose}>{t('common.cancel')}</button><ActionButton type="submit" icon={mode === 'upload' ? 'upload' : mode === 'issue' ? 'certificate' : 'download'} disabled={busy}>{busy ? t('common.queueing') : t(mode === 'upload' ? 'certificate.submitUpload' : mode === 'issue' ? 'certificate.submitIssue' : 'certificate.submitImport')}</ActionButton></footer>
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
    if (!nodeID || !dnsAccountID || !acmeAccountID || !Number.isInteger(days) || days < 7 || days > 60) {
      setError(t('certificate.validationAutomation'))
      return
    }
    void onSave({ node_id: nodeID, dns_account_id: dnsAccountID, acme_account_id: acmeAccountID, auto_renew: autoRenew, renew_before_days: days, dns_names: [certificate!.domain, ...names] })
  }
  return <DialogShell open={open} title={t('certificate.editAutomation')} description={t('certificate.editAutomationHint', { domain: certificate.domain })} onClose={onClose} wide><form className="certificate-dialog-form automation-dialog-form" onSubmit={submit}><div className="certificate-dialog-scroll"><CertificateNamesField primary={certificate.domain} values={names} draft={nameDraft} onDraft={setNameDraft} onChange={setNames} /><div className="account-fields certificate-account-fields"><label><span>{t('certificate.signingNode')}</span><SelectField ariaLabel={t('certificate.signingNode')} value={nodeID} onChange={setNodeID} icon="server" options={availableNodes.map((node) => ({ value: node.id, label: node.name, description: node.os_name || node.hostname }))} /></label><label><span>{t('certificate.dnsAccount')}</span><SelectField ariaLabel={t('certificate.dnsAccount')} value={dnsAccountID} onChange={setDNSAccountID} icon="dns" options={dnsAccounts.map((account) => ({ value: account.id, label: account.name, description: account.provider }))} /></label><label><span>{t('certificate.acmeAccount')}</span><SelectField ariaLabel={t('certificate.acmeAccount')} value={acmeAccountID} onChange={setACMEAccountID} icon="key" options={acmeAccounts.map((account) => ({ value: account.id, label: account.name, description: account.email }))} /></label><label><span>{t('certificate.renewDays')}</span><div className="field-control"><Icon name="clock" size={17} /><input inputMode="numeric" value={renewDays} onChange={(event) => setRenewDays(event.target.value.replace(/\D/g, '').slice(0, 2))} /></div></label></div><label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>{t('certificate.renewToggle')}</strong><small>{t('certificate.renewHint', { days: Number(renewDays) || 30 })}</small></span></label>{error && <div className="form-error" role="alert"><Icon name="warning" size={16} />{error}</div>}</div><footer className="certificate-dialog-footer"><button className="text-button" type="button" onClick={onClose}>{t('common.cancel')}</button><ActionButton type="submit" icon="edit" disabled={busy}>{busy ? t('common.saving') : t('common.save')}</ActionButton></footer></form></DialogShell>
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
  return <DialogShell open={open} title={t('dialog.syncTitle')} description={certificate ? t('dialog.syncDescription', { domain: certificate.domain }) : ''} onClose={onClose}><div className="sync-dialog-body"><div className="sync-dialog-list">{nodes.filter((node) => node.status !== 'revoked').map((node) => <button key={node.id} className={selected.includes(node.id) ? 'selected' : ''} onClick={() => setSelected((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /><span><strong>{node.name}</strong><small>{node.status === 'online' ? t('dialog.syncOnline') : t('dialog.syncOffline')}</small></span>{selected.includes(node.id) && <Icon name="check" size={17} />}</button>)}</div><div className="dialog-note"><Icon name="terminal" size={17} /><span>{t('dialog.syncProof')}</span></div><ActionButton wide icon="upload" disabled={busy || selected.length === 0} onClick={() => void onSync(selected)}>{busy ? t('common.queueing') : t('dialog.syncAction', { count: selected.length })}</ActionButton></div></DialogShell>
}

export function PasswordDialog({ open, busy, onClose, onSave }: { open: boolean; busy: boolean; onClose: () => void; onSave: (currentPassword: string, newPassword: string) => Promise<void> }) {
  const { t } = usePreferences()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { if (open) { setCurrentPassword(''); setNewPassword(''); setConfirmation(''); setError('') } }, [open])
  return <DialogShell open={open} title={t('dialog.passwordTitle')} description={t('dialog.passwordDescription')} onClose={onClose}><form className="dialog-form" onSubmit={(event) => { event.preventDefault(); if (newPassword !== confirmation) { setError(t('dialog.passwordMismatch')); return }; void onSave(currentPassword, newPassword) }}><label><span>{t('dialog.currentPassword')}</span><div className="field-control"><Icon name="key" size={17} /><input type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></div></label><label><span>{t('dialog.newPassword')}</span><div className="field-control"><Icon name="lock" size={17} /><input type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></div></label><label><span>{t('dialog.confirmPassword')}</span><div className="field-control"><Icon name="check" size={17} /><input type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div></label><div className="dialog-note"><Icon name="shield" size={17} /><span>{t('dialog.passwordRule')}</span></div>{error && <div className="form-error" role="alert">{error}</div>}<ActionButton wide icon="lock" disabled={busy || currentPassword.length < 12 || newPassword.length < 12}>{busy ? t('common.saving') : t('dialog.changePassword')}</ActionButton></form></DialogShell>
}
