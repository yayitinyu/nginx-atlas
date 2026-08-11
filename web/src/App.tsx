import { useCallback, useEffect, useMemo, useState } from 'react'
import { APIError, api, clearToken, getToken, setToken } from './api'
import type { ACMEAccount, CertificateRecord, DashboardData, DNSAccount, DomainRecord, EnrollmentResponse, NginxSiteMeta, NodeRecord } from './types'
import { usePreferences, type LanguageMode, type ThemeMode } from './preferences'
import { Icon } from './components/Icon'
import { LoginGate } from './components/LoginGate'
import { MobileHeader, MobileMenu, MobileNavigation, NavigationRail, type PageKey } from './components/Navigation'
import { AdminAvatar, ConfirmDialog, LoadingState, ToastRegion, type ToastMessage } from './components/Primitives'
import { DomainDrawer, type DomainSubmission } from './components/DomainDrawer'
import { ACMEAccountDialog, CertificateDialog, DNSAccountDialog, NodeDialog, PasswordDialog, SyncDialog, type ACMEAccountInput, type CertificateSubmission, type DNSAccountInput } from './components/Dialogs'
import { SelectField } from './components/SelectField'
import { Overview } from './views/Overview'
import { AccountsPage, AuditPage, CertificatesPage, DomainsPage, NodesPage, SettingsPage } from './views/Operations'

type AuthState = 'checking' | 'anonymous' | 'authenticated'
const emptyDashboard: DashboardData = { nodes: [], domains: [], certificates: [], audit: [], jobs: [], server_time: new Date().toISOString() }

export default function App() {
  const { t, theme, language, effectiveLanguage, setTheme, setLanguage } = usePreferences()
  const [auth, setAuth] = useState<AuthState>(getToken() ? 'checking' : 'anonymous')
  const [page, setPage] = useState<PageKey>('overview')
  const [data, setData] = useState<DashboardData>(emptyDashboard)
  const [dnsAccounts, setDNSAccounts] = useState<DNSAccount[]>([])
  const [acmeAccounts, setACMEAccounts] = useState<ACMEAccount[]>([])
  const [loading, setLoading] = useState(true)
  const [mobileMenu, setMobileMenu] = useState(false)
  const [domainDrawer, setDomainDrawer] = useState(false)
  const [certificateDialog, setCertificateDialog] = useState(false)
  const [nodeDialog, setNodeDialog] = useState(false)
  const [nodeResult, setNodeResult] = useState<EnrollmentResponse>()
  const [dnsDialog, setDNSDialog] = useState(false)
  const [editingDNS, setEditingDNS] = useState<DNSAccount>()
  const [acmeDialog, setACMEDialog] = useState(false)
  const [editingACME, setEditingACME] = useState<ACMEAccount>()
  const [passwordDialog, setPasswordDialog] = useState(false)
  const [syncCertificate, setSyncCertificate] = useState<CertificateRecord>()
  const [confirmCertificate, setConfirmCertificate] = useState<CertificateRecord>()
  const [confirmDomain, setConfirmDomain] = useState<DomainRecord>()
  const [confirmNode, setConfirmNode] = useState<NodeRecord>()
  const [busy, setBusy] = useState('')
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const toast = useCallback((tone: ToastMessage['tone'], message: string) => {
    const id = Date.now() + Math.round(Math.random() * 1000)
    setToasts((items) => [...items, { id, tone, message }])
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), 5200)
  }, [])

  const logout = useCallback(() => {
    clearToken(); setAuth('anonymous'); setData(emptyDashboard); setMobileMenu(false)
  }, [])

  const handleError = useCallback((error: unknown, fallback: string) => {
    if (error instanceof APIError && error.status === 401) { logout(); return }
    const message = error instanceof Error && effectiveLanguage === 'zh' ? error.message : fallback
    toast('error', message)
  }, [effectiveLanguage, logout, toast])

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const [dashboard, dns, acme] = await Promise.all([api.dashboard(), api.dnsAccounts(), api.acmeAccounts()])
      setData(dashboard); setDNSAccounts(dns); setACMEAccounts(acme)
    } catch (error) { handleError(error, t('error.dashboard')) } finally { if (!silent) setLoading(false) }
  }, [handleError, t])

  const verify = useCallback(async () => { await api.verifySession(); setAuth('authenticated') }, [])
  const login = useCallback(async (password: string) => { const session = await api.login(password); setToken(session.token); setAuth('authenticated') }, [])

  useEffect(() => { if (auth === 'checking') verify().catch(() => logout()) }, [auth, verify, logout])
  useEffect(() => {
    if (auth !== 'authenticated') return
    void refresh()
    const interval = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh(true) }, 10_000)
    return () => window.clearInterval(interval)
  }, [auth, refresh])

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [page])

  const overlayActive = domainDrawer || certificateDialog || nodeDialog || dnsDialog || acmeDialog || passwordDialog || Boolean(syncCertificate) || Boolean(confirmCertificate) || Boolean(confirmDomain) || Boolean(confirmNode) || mobileMenu
  useEffect(() => {
    document.body.classList.toggle('overlay-active', overlayActive)
    return () => document.body.classList.remove('overlay-active')
  }, [overlayActive])

  const allHealthy = useMemo(() => data.nodes.length > 0 && data.nodes.every((node) => node.status === 'online' && node.nginx_healthy), [data.nodes])

  async function createDomain(submission: DomainSubmission) {
    setBusy('domain')
    try {
      const input = { ...submission.input }
      if (input.certificate_mode === 'upload' && submission.fullchain && submission.privkey) {
        const certificate = await api.uploadCertificate({
          domain: input.domain, node_id: input.auto_renew ? input.node_id : '', auto_renew: input.auto_renew,
          renew_before_days: input.renew_before_days, acme_account_id: input.acme_account_id,
          dns_account_id: input.dns_account_id, sync_node_ids: [],
        }, submission.fullchain, submission.privkey)
        input.certificate_id = certificate.id
      }
      await api.createDomain(input)
      setDomainDrawer(false); setPage('domains'); toast('success', t('toast.domainQueued')); await refresh(true)
    } catch (error) { handleError(error, t('error.domain')) } finally { setBusy('') }
  }

  async function adoptDomain(node: NodeRecord, site: NginxSiteMeta) {
    setBusy(`adopt-${node.id}-${site.domain}`)
    try { await api.adoptDomain({ node_id: node.id, domain: site.domain, config_path: site.config_path }); toast('success', t('toast.domainObserved')); await refresh(true) }
    catch (error) { handleError(error, t('error.adopt')) } finally { setBusy('') }
  }

  async function submitCertificate(submission: CertificateSubmission) {
    setBusy('certificate')
    try {
      if (submission.mode === 'upload') { await api.uploadCertificate(submission.input, submission.fullchain, submission.privkey); toast('success', t('toast.certUploaded')) }
      else if (submission.mode === 'issue') { await api.issueCertificate(submission.input); toast('success', t('toast.certQueued')) }
      else { await api.importCertificate(submission.input); toast('success', t('toast.certQueued')) }
      setCertificateDialog(false); setPage('certificates'); await refresh(true)
    } catch (error) { handleError(error, t('error.certificate')) } finally { setBusy('') }
  }

  async function createNode(name: string) {
    setBusy('node')
    try { setNodeResult(await api.createEnrollment(name.trim())) } catch (error) { handleError(error, t('error.node')) } finally { setBusy('') }
  }

  async function saveDNS(input: DNSAccountInput, accountID?: string) {
    setBusy('dns')
    try { if (accountID) await api.updateDNSAccount(accountID, input); else await api.createDNSAccount(input); setDNSDialog(false); setEditingDNS(undefined); toast('success', t('toast.dnsSaved')); await refresh(true) }
    catch (error) { handleError(error, t('error.dns')) } finally { setBusy('') }
  }

  async function saveACME(input: ACMEAccountInput, accountID?: string) {
    setBusy('acme')
    try { if (accountID) await api.updateACMEAccount(accountID, input); else await api.createACMEAccount(input); setACMEDialog(false); setEditingACME(undefined); toast('success', t('toast.acmeSaved')); await refresh(true) }
    catch (error) { handleError(error, t('error.acme')) } finally { setBusy('') }
  }

  async function changePassword(currentPassword: string, newPassword: string) {
    setBusy('password')
    try { const session = await api.changeAdminPassword(currentPassword, newPassword); setToken(session.token); setPasswordDialog(false); toast('success', t('toast.passwordChanged')) }
    catch (error) { handleError(error, t('error.password')) } finally { setBusy('') }
  }

  async function deleteDomain() {
    if (!confirmDomain) return
    setBusy('confirm')
    try { const response = await api.deleteDomain(confirmDomain.id); toast('info', t(response.queued ? 'toast.domainRemoved' : 'toast.observationRemoved')); setConfirmDomain(undefined); await refresh(true) }
    catch (error) { handleError(error, t('error.removeDomain')) } finally { setBusy('') }
  }

  async function revokeNode() {
    if (!confirmNode) return
    setBusy('confirm')
    try { await api.revokeNode(confirmNode.id); toast('success', t('toast.nodeRevoked')); setConfirmNode(undefined); await refresh(true) }
    catch (error) { handleError(error, t('error.revokeNode')) } finally { setBusy('') }
  }

  async function setCertificateAutoRenew(certificate: CertificateRecord, enabled: boolean) {
    setBusy(`auto-renew-${certificate.id}`)
    try {
      const updated = await api.setCertificateAutoRenew(certificate.id, enabled)
      setData((current) => ({ ...current, certificates: current.certificates.map((item) => item.id === updated.id ? updated : item) }))
      toast('success', t(enabled ? 'toast.autoRenewEnabled' : 'toast.autoRenewDisabled', { domain: certificate.domain }))
      await refresh(true)
    } catch (error) { handleError(error, t('error.autoRenew')) } finally { setBusy('') }
  }

  async function renewCertificate() {
    if (!confirmCertificate) return
    const certificate = confirmCertificate
    setBusy(`renew-${certificate.id}`)
    try { await api.renewCertificate(certificate.id); setConfirmCertificate(undefined); toast('success', t('toast.renewQueued', { domain: certificate.domain })); await refresh(true) }
    catch (error) { handleError(error, t('error.renew')) } finally { setBusy('') }
  }

  async function syncSelectedNodes(nodeIDs: string[]) {
    if (!syncCertificate) return
    setBusy('sync')
    try { await api.syncCertificate(syncCertificate.id, nodeIDs); toast('success', t('toast.syncQueued', { count: nodeIDs.length })); setSyncCertificate(undefined); await refresh(true) }
    catch (error) { handleError(error, t('error.sync')) } finally { setBusy('') }
  }

  if (auth === 'checking') return <div className="app-loading"><LoadingState /></div>
  if (auth === 'anonymous') return <LoginGate onLogin={login} />

  return (
    <div className="app-shell">
      <NavigationRail page={page} onChange={setPage} onLogout={logout} />
      <MobileHeader onMenu={() => setMobileMenu(true)} />
      <div className="workspace">
        <header className="command-bar">
          <span className="system-state"><span className={`pulse-dot ${allHealthy ? '' : 'pulse-warning'}`} />{allHealthy ? t('app.allHealthy') : data.nodes.length === 0 ? t('app.waitingNode') : t('app.needsAttention')}</span>
          <div className="command-tools">
            <div className="command-proof"><Icon name="terminal" size={18} weight="light" /><code>nginx -t</code><span><Icon name={allHealthy ? 'check' : 'warning'} size={16} />{allHealthy ? t('app.configVerified') : t('app.statusSynced')}</span><button onClick={() => void refresh()} aria-label={t('app.refreshNow')}><Icon name="refresh" size={18} /></button></div>
            <SelectField ariaLabel={t('app.language')} value={language} onChange={(value) => setLanguage(value as LanguageMode)} icon="language" className="utility-select" options={[{ value: 'system', label: t('common.system') }, { value: 'zh', label: t('common.chinese') }, { value: 'en', label: t('common.english') }]} />
            <SelectField ariaLabel={t('app.theme')} value={theme} onChange={(value) => setTheme(value as ThemeMode)} icon={theme === 'light' ? 'sun' : theme === 'dark' ? 'moon' : 'system'} className="utility-select" options={[{ value: 'system', label: t('common.system') }, { value: 'light', label: t('common.light') }, { value: 'dark', label: t('common.dark') }]} />
            <AdminAvatar compact />
          </div>
        </header>
        <main className="workspace-content">{loading ? <LoadingState /> : renderPage(page, {
          data, dnsAccounts, acmeAccounts, onAddDomain: () => setDomainDrawer(true), onAddCertificate: () => setCertificateDialog(true), onPage: setPage,
          onDeleteDomain: setConfirmDomain, onAdoptDomain: adoptDomain, onAddNode: () => { setNodeResult(undefined); setNodeDialog(true) }, onRevokeNode: setConfirmNode,
          onRenew: setConfirmCertificate, onToggleAutoRenew: (certificate, enabled) => void setCertificateAutoRenew(certificate, enabled), onSync: setSyncCertificate, busy,
          onAddDNS: () => { setEditingDNS(undefined); setDNSDialog(true) }, onEditDNS: (account) => { setEditingDNS(account); setDNSDialog(true) },
          onAddACME: () => { setEditingACME(undefined); setACMEDialog(true) }, onEditACME: (account) => { setEditingACME(account); setACMEDialog(true) },
          onPassword: () => setPasswordDialog(true), onLogout: logout,
        })}</main>
      </div>
      <MobileNavigation page={page} onChange={setPage} />
      <MobileMenu open={mobileMenu} page={page} onChange={setPage} onClose={() => setMobileMenu(false)} onLogout={logout} />
      <DomainDrawer open={domainDrawer} nodes={data.nodes} certificates={data.certificates} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'domain'} onClose={() => !busy && setDomainDrawer(false)} onSubmit={createDomain} />
      <CertificateDialog open={certificateDialog} nodes={data.nodes} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'certificate'} onClose={() => !busy && setCertificateDialog(false)} onSubmit={submitCertificate} />
      <NodeDialog open={nodeDialog} busy={busy === 'node'} result={nodeResult} onClose={() => { setNodeDialog(false); setNodeResult(undefined) }} onCreate={createNode} />
      <DNSAccountDialog open={dnsDialog} account={editingDNS} busy={busy === 'dns'} onClose={() => { setDNSDialog(false); setEditingDNS(undefined) }} onSave={saveDNS} />
      <ACMEAccountDialog open={acmeDialog} account={editingACME} busy={busy === 'acme'} onClose={() => { setACMEDialog(false); setEditingACME(undefined) }} onSave={saveACME} />
      <PasswordDialog open={passwordDialog} busy={busy === 'password'} onClose={() => setPasswordDialog(false)} onSave={changePassword} />
      <SyncDialog open={Boolean(syncCertificate)} certificate={syncCertificate} nodes={data.nodes} busy={busy === 'sync'} onClose={() => setSyncCertificate(undefined)} onSync={syncSelectedNodes} />
      <ConfirmDialog open={Boolean(confirmCertificate)} title={t('certificate.renewConfirmTitle')} description={t('certificate.renewConfirmDescription', { domain: confirmCertificate?.domain ?? '' })} confirmLabel={t('certificate.renewConfirmAction')} onCancel={() => setConfirmCertificate(undefined)} onConfirm={() => void renewCertificate()} busy={busy === `renew-${confirmCertificate?.id}`} busyLabel={t('common.queueing')} tone="primary" icon="refresh" />
      <ConfirmDialog open={Boolean(confirmDomain)} title={t(confirmDomain?.observed_only ? 'domain.removeObservedTitle' : 'domain.removeTitle')} description={t(confirmDomain?.observed_only ? 'domain.removeObservedDescription' : 'domain.removeDescription', { domain: confirmDomain?.name ?? '' })} confirmLabel={t(confirmDomain?.observed_only ? 'domain.stopManaging' : 'domain.removeAction')} onCancel={() => setConfirmDomain(undefined)} onConfirm={() => void deleteDomain()} busy={busy === 'confirm'} />
      <ConfirmDialog open={Boolean(confirmNode)} title={t('nodes.revokeTitle')} description={t('nodes.revokeDescription', { node: confirmNode?.name ?? '' })} confirmLabel={t('nodes.revoke')} onCancel={() => setConfirmNode(undefined)} onConfirm={() => void revokeNode()} busy={busy === 'confirm'} />
      <ToastRegion messages={toasts} dismiss={(id) => setToasts((items) => items.filter((item) => item.id !== id))} />
    </div>
  )
}

interface PageProps {
  data: DashboardData
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDomain: () => void
  onAddCertificate: () => void
  onPage: (page: PageKey) => void
  onDeleteDomain: (domain: DomainRecord) => void
  onAdoptDomain: (node: NodeRecord, site: NginxSiteMeta) => void
  onAddNode: () => void
  onRevokeNode: (node: NodeRecord) => void
  onRenew: (certificate: CertificateRecord) => void
  onToggleAutoRenew: (certificate: CertificateRecord, enabled: boolean) => void
  onSync: (certificate: CertificateRecord) => void
  busy: string
  onAddDNS: () => void
  onEditDNS: (account: DNSAccount) => void
  onAddACME: () => void
  onEditACME: (account: ACMEAccount) => void
  onPassword: () => void
  onLogout: () => void
}

function renderPage(page: PageKey, props: PageProps) {
  switch (page) {
    case 'overview': return <Overview data={props.data} onNavigate={props.onPage} />
    case 'domains': return <DomainsPage domains={props.data.domains} nodes={props.data.nodes} onAdd={props.onAddDomain} onDelete={props.onDeleteDomain} onAdopt={props.onAdoptDomain} />
    case 'certificates': return <CertificatesPage certificates={props.data.certificates} nodes={props.data.nodes} onAdd={props.onAddCertificate} onRenew={props.onRenew} onToggleAutoRenew={props.onToggleAutoRenew} onSync={props.onSync} busy={props.busy} />
    case 'nodes': return <NodesPage nodes={props.data.nodes} onAdd={props.onAddNode} onRevoke={props.onRevokeNode} />
    case 'accounts': return <AccountsPage dnsAccounts={props.dnsAccounts} acmeAccounts={props.acmeAccounts} onAddDNS={props.onAddDNS} onAddACME={props.onAddACME} onEditDNS={props.onEditDNS} onEditACME={props.onEditACME} />
    case 'audit': return <AuditPage events={props.data.audit} domains={props.data.domains} nodes={props.data.nodes} />
    case 'settings': return <SettingsPage onPassword={props.onPassword} onLogout={props.onLogout} />
  }
}
