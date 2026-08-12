import { useCallback, useEffect, useMemo, useState } from 'react'
import { APIError, api, clearToken, getToken, setToken } from './api'
import type { ACMEAccount, CertificateRecord, DashboardData, DNSAccount, DomainRecord, JobRecord, NginxSiteMeta, NodeRecord, ReleaseInfo } from './types'
import { usePreferences, type LanguageMode, type ThemeMode } from './preferences'
import { Icon } from './components/Icon'
import { LoginGate } from './components/LoginGate'
import { MobileHeader, MobileMenu, MobileNavigation, NavigationRail, type PageKey } from './components/Navigation'
import { ConfirmDialog, LoadingState, ToastRegion, type ToastMessage } from './components/Primitives'
import { DomainDrawer, type DomainSubmission } from './components/DomainDrawer'
import { ACMEAccountDialog, CertificateAutomationDialog, CertificateDialog, DNSAccountDialog, NodeManageDialog, PasswordDialog, SyncDialog, type ACMEAccountInput, type CertificateAutomationSettingsInput, type CertificateSubmission, type DNSAccountInput } from './components/Dialogs'
import { SelectField } from './components/SelectField'
import { Overview } from './views/Overview'
import { AuditPage, CertificatesPage, ControllerUpdatePage, DomainsPage, NodesPage, SettingsPage } from './views/Operations'

type AuthState = 'checking' | 'anonymous' | 'authenticated'
const emptyDashboard: DashboardData = { nodes: [], domains: [], certificates: [], audit: [], jobs: [], settings: { node_poll_seconds: 30 }, server_time: new Date().toISOString() }

export default function App() {
  const { t, effectiveTheme, effectiveLanguage, setTheme, setLanguage } = usePreferences()
  const [auth, setAuth] = useState<AuthState>(getToken() ? 'checking' : 'anonymous')
  const [page, setPage] = useState<PageKey>('overview')
  const [data, setData] = useState<DashboardData>(emptyDashboard)
  const [dnsAccounts, setDNSAccounts] = useState<DNSAccount[]>([])
  const [acmeAccounts, setACMEAccounts] = useState<ACMEAccount[]>([])
  const [loading, setLoading] = useState(true)
  const [mobileMenu, setMobileMenu] = useState(false)
  const [domainDrawer, setDomainDrawer] = useState(false)
  const [certificateDialog, setCertificateDialog] = useState(false)
  const [dnsDialog, setDNSDialog] = useState(false)
  const [editingDNS, setEditingDNS] = useState<DNSAccount>()
  const [acmeDialog, setACMEDialog] = useState(false)
  const [editingACME, setEditingACME] = useState<ACMEAccount>()
  const [passwordDialog, setPasswordDialog] = useState(false)
  const [syncCertificate, setSyncCertificate] = useState<CertificateRecord>()
  const [automationCertificate, setAutomationCertificate] = useState<CertificateRecord>()
  const [confirmCertificate, setConfirmCertificate] = useState<CertificateRecord>()
  const [confirmDomain, setConfirmDomain] = useState<DomainRecord>()
  const [managedNode, setManagedNode] = useState<NodeRecord>()
  const [releaseInfo, setReleaseInfo] = useState<ReleaseInfo>()
  const [updateJob, setUpdateJob] = useState<JobRecord>()
  const [updatingNode, setUpdatingNode] = useState<NodeRecord>()
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
      setData({ ...dashboard, settings: dashboard.settings ?? { node_poll_seconds: 30 } }); setDNSAccounts(dns); setACMEAccounts(acme)
    } catch (error) { handleError(error, t('error.dashboard')) } finally { if (!silent) setLoading(false) }
  }, [handleError, t])

  const verify = useCallback(async () => { await api.verifySession(); setAuth('authenticated') }, [])
  const login = useCallback(async (password: string) => { const session = await api.login(password); setToken(session.token); setAuth('authenticated') }, [])

  useEffect(() => { if (auth === 'checking') verify().catch(() => logout()) }, [auth, verify, logout])
  useEffect(() => {
    if (auth !== 'authenticated') return
    void refresh()
    const pollSeconds = data.settings?.node_poll_seconds ?? 30
    const interval = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh(true) }, Math.max(10, pollSeconds) * 1000)
    return () => window.clearInterval(interval)
  }, [auth, refresh, data.settings?.node_poll_seconds])

  useEffect(() => {
    if (auth !== 'authenticated' || page !== 'update') return
    const interval = window.setInterval(() => void refresh(true), 2_000)
    return () => window.clearInterval(interval)
  }, [auth, page, refresh])

  useEffect(() => {
    window.scrollTo(0, 0)
    document.querySelector<HTMLElement>('.workspace')?.scrollTo(0, 0)
  }, [page])

  const overlayActive = domainDrawer || certificateDialog || dnsDialog || acmeDialog || passwordDialog || Boolean(syncCertificate) || Boolean(automationCertificate) || Boolean(confirmCertificate) || Boolean(confirmDomain) || Boolean(managedNode) || mobileMenu
  useEffect(() => {
    if (!overlayActive) return

    const root = document.documentElement
    const body = document.body
    const workspace = document.querySelector<HTMLElement>('.workspace')
    const pageScroll = window.scrollY
    const workspaceScroll = workspace?.scrollTop ?? 0
    const previousBodyStyle = {
      position: body.style.position,
      top: body.style.top,
      left: body.style.left,
      right: body.style.right,
      width: body.style.width,
    }

    root.classList.add('overlay-active')
    body.classList.add('overlay-active')
    body.style.position = 'fixed'
    body.style.top = `-${pageScroll}px`
    body.style.left = '0'
    body.style.right = '0'
    body.style.width = '100%'

    return () => {
      root.classList.remove('overlay-active')
      body.classList.remove('overlay-active')
      body.style.position = previousBodyStyle.position
      body.style.top = previousBodyStyle.top
      body.style.left = previousBodyStyle.left
      body.style.right = previousBodyStyle.right
      body.style.width = previousBodyStyle.width
      window.scrollTo(0, pageScroll)
      workspace?.scrollTo(0, workspaceScroll)
    }
  }, [overlayActive])

  const allHealthy = useMemo(() => data.nodes.length > 0 && data.nodes.every((node) => node.status === 'online' && node.nginx_healthy), [data.nodes])

  const [editingDomain, setEditingDomain] = useState<DomainRecord>()

  async function createDomain(submission: DomainSubmission) {
    setBusy('domain')
    try {
      await api.createDomain(submission.input)
      setDomainDrawer(false); setEditingDomain(undefined); setPage('domains'); toast('success', t('toast.domainQueued')); await refresh(true)
    } catch (error) { handleError(error, t('error.domain')) } finally { setBusy('') }
  }

  async function updateDomain(id: string, submission: DomainSubmission) {
    setBusy('domain')
    try {
      await api.updateDomain(id, submission.input)
      setDomainDrawer(false); setEditingDomain(undefined); toast('success', t('toast.domainQueued')); await refresh(true)
    } catch (error) { handleError(error, t('error.domain')) } finally { setBusy('') }
  }

  async function submitCertificate(submission: CertificateSubmission) {
    setBusy('certificate')
    try {
      if (submission.mode === 'upload') { await api.uploadCertificate(submission.input, submission.certificate, submission.privateKey); toast('success', t('toast.certUploaded')) }
      else if (submission.mode === 'issue') { await api.issueCertificate(submission.input); toast('success', t('toast.certQueued')) }
      else { await api.importCertificate(submission.input); toast('success', t('toast.certQueued')) }
      setCertificateDialog(false); setPage('certificates'); await refresh(true)
    } catch (error) { handleError(error, t('error.certificate')) } finally { setBusy('') }
  }

  async function saveCertificateAutomation(input: CertificateAutomationSettingsInput) {
    if (!automationCertificate) return
    setBusy('certificate-automation')
    try { const updated = await api.updateCertificateAutomation(automationCertificate.id, input); setData((current) => ({ ...current, certificates: current.certificates.map((item) => item.id === updated.id ? updated : item) })); setAutomationCertificate(undefined); toast('success', t('toast.certificateAutomationSaved')); await refresh(true) }
    catch (error) { handleError(error, t('error.certificateAutomation')) } finally { setBusy('') }
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

  async function openNodeManager(node: NodeRecord) {
    setManagedNode(node); setReleaseInfo(undefined)
    setBusy('node-details')
    try { setReleaseInfo(await api.releaseInfo()) } catch (error) { handleError(error, t('error.release')) }
    setBusy('')
  }

  async function checkRelease() {
    setBusy('release')
    try { setReleaseInfo(await api.releaseInfo()); toast('info', t('toast.releaseChecked')) }
    catch (error) { handleError(error, t('error.release')) } finally { setBusy('') }
  }

  async function renameManagedNode(name: string) {
    if (!managedNode) return
    setBusy('rename')
    try { const updated = await api.renameNode(managedNode.id, name); setManagedNode(updated); setData((current) => ({ ...current, nodes: current.nodes.map((node) => node.id === updated.id ? updated : node) })); toast('success', t('toast.nodeRenamed')) }
    catch (error) { handleError(error, t('error.renameNode')) } finally { setBusy('') }
  }

  async function updateManagedNodeAtlas() {
    if (!managedNode) return
    const target = managedNode
    setBusy('atlas')
    try {
      const job = await api.updateNodeAtlas(target.id)
      setManagedNode(undefined)
      if (target.controller_installed) { setUpdateJob(job); setUpdatingNode(target); setPage('update') }
      else toast('success', t('toast.atlasUpdateQueued'))
      await refresh(true)
    }
    catch (error) { handleError(error, t('error.atlasUpdate')) } finally { setBusy('') }
  }

  async function updatePollSeconds(seconds: number) {
    setBusy('settings-poll')
    try {
      const settings = await api.updateSettings({ node_poll_seconds: seconds })
      setData((current) => ({ ...current, settings }))
      toast('success', t('toast.pollFrequencySaved'))
    } catch (error) { handleError(error, t('error.settings')) } finally { setBusy('') }
  }

  async function updateManagedNodeSystem() {
    if (!managedNode) return
    setBusy('system')
    try { await api.updateNodeSystem(managedNode.id); toast('success', t('toast.systemUpdateQueued')); setManagedNode(undefined); await refresh(true) }
    catch (error) { handleError(error, t('error.systemUpdate')) } finally { setBusy('') }
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
            <SelectField ariaLabel={t('app.language')} value={effectiveLanguage} onChange={(value) => setLanguage(value as LanguageMode)} icon="language" className="utility-select" options={[{ value: 'zh', label: t('common.chinese') }, { value: 'en', label: t('common.english') }]} />
            <SelectField ariaLabel={t('app.theme')} value={effectiveTheme} onChange={(value) => setTheme(value as ThemeMode)} icon={effectiveTheme === 'light' ? 'sun' : 'moon'} className="utility-select" options={[{ value: 'light', label: t('common.light') }, { value: 'dark', label: t('common.dark') }]} />
          </div>
        </header>
        <main className="workspace-content">{loading ? <LoadingState /> : renderPage(page, {
          data, dnsAccounts, acmeAccounts, onAddDomain: () => { setEditingDomain(undefined); setDomainDrawer(true) }, onEditDomain: (domain) => { setEditingDomain(domain); setDomainDrawer(true) }, onAddCertificate: () => setCertificateDialog(true), onPage: setPage,
          onDeleteDomain: setConfirmDomain, onManageNode: (node) => void openNodeManager(node),
          onRenew: setConfirmCertificate, onToggleAutoRenew: (certificate, enabled) => void setCertificateAutoRenew(certificate, enabled), onSync: setSyncCertificate, onEditCertificate: setAutomationCertificate, busy,
          onAddDNS: () => { setEditingDNS(undefined); setDNSDialog(true) }, onEditDNS: (account) => { setEditingDNS(account); setDNSDialog(true) },
          onAddACME: () => { setEditingACME(undefined); setACMEDialog(true) }, onEditACME: (account) => { setEditingACME(account); setACMEDialog(true) },
          onPollSeconds: (seconds) => void updatePollSeconds(seconds), onPassword: () => setPasswordDialog(true), onLogout: logout,
          updateJob: updateJob ? data.jobs.find((job) => job.id === updateJob.id) ?? updateJob : undefined, updatingNode,
        })}</main>
      </div>
      <MobileNavigation page={page} onChange={setPage} />
      <MobileMenu open={mobileMenu} page={page} onChange={setPage} onClose={() => setMobileMenu(false)} onLogout={logout} />
      <DomainDrawer open={domainDrawer} nodes={data.nodes} certificates={data.certificates} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'domain'} editingDomain={editingDomain} onClose={() => { if (!busy) { setDomainDrawer(false); setEditingDomain(undefined) } }} onSubmit={createDomain} onUpdate={updateDomain} />
      <CertificateDialog open={certificateDialog} nodes={data.nodes} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'certificate'} onClose={() => !busy && setCertificateDialog(false)} onSubmit={submitCertificate} />
      <CertificateAutomationDialog open={Boolean(automationCertificate)} certificate={automationCertificate} nodes={data.nodes} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'certificate-automation'} onClose={() => !busy && setAutomationCertificate(undefined)} onSave={saveCertificateAutomation} />
      <NodeManageDialog open={Boolean(managedNode)} node={managedNode} release={releaseInfo} busy={busy} onClose={() => !busy && setManagedNode(undefined)} onRename={renameManagedNode} onCheckRelease={checkRelease} onUpdateAtlas={updateManagedNodeAtlas} onUpdateSystem={updateManagedNodeSystem} />
      <DNSAccountDialog open={dnsDialog} account={editingDNS} busy={busy === 'dns'} onClose={() => { setDNSDialog(false); setEditingDNS(undefined) }} onSave={saveDNS} />
      <ACMEAccountDialog open={acmeDialog} account={editingACME} busy={busy === 'acme'} onClose={() => { setACMEDialog(false); setEditingACME(undefined) }} onSave={saveACME} />
      <PasswordDialog open={passwordDialog} busy={busy === 'password'} onClose={() => setPasswordDialog(false)} onSave={changePassword} />
      <SyncDialog open={Boolean(syncCertificate)} certificate={syncCertificate} nodes={data.nodes} busy={busy === 'sync'} onClose={() => setSyncCertificate(undefined)} onSync={syncSelectedNodes} />
      <ConfirmDialog open={Boolean(confirmCertificate)} title={t('certificate.renewConfirmTitle')} description={t('certificate.renewConfirmDescription', { domain: confirmCertificate?.domain ?? '' })} confirmLabel={t('certificate.renewConfirmAction')} onCancel={() => setConfirmCertificate(undefined)} onConfirm={() => void renewCertificate()} busy={busy === `renew-${confirmCertificate?.id}`} busyLabel={t('common.queueing')} tone="primary" icon="refresh" />
      <ConfirmDialog open={Boolean(confirmDomain)} title={t(confirmDomain?.observed_only ? 'domain.removeObservedTitle' : confirmDomain?.taken_over ? 'domain.removeTakenOverTitle' : 'domain.removeTitle')} description={t(confirmDomain?.observed_only ? 'domain.removeObservedDescription' : confirmDomain?.taken_over ? 'domain.removeTakenOverDescription' : 'domain.removeDescription', { domain: confirmDomain?.name ?? '' })} confirmLabel={t(confirmDomain?.observed_only ? 'domain.stopManaging' : confirmDomain?.taken_over ? 'domain.restoreOriginal' : 'domain.removeAction')} onCancel={() => setConfirmDomain(undefined)} onConfirm={() => void deleteDomain()} busy={busy === 'confirm'} />
      <ToastRegion messages={toasts} dismiss={(id) => setToasts((items) => items.filter((item) => item.id !== id))} />
    </div>
  )
}

interface PageProps {
  data: DashboardData
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDomain: () => void
  onEditDomain: (domain: DomainRecord) => void
  onAddCertificate: () => void
  onPage: (page: PageKey) => void
  onDeleteDomain: (domain: DomainRecord) => void
  onManageNode: (node: NodeRecord) => void
  onRenew: (certificate: CertificateRecord) => void
  onToggleAutoRenew: (certificate: CertificateRecord, enabled: boolean) => void
  onSync: (certificate: CertificateRecord) => void
  onEditCertificate: (certificate: CertificateRecord) => void
  busy: string
  onAddDNS: () => void
  onEditDNS: (account: DNSAccount) => void
  onAddACME: () => void
  onEditACME: (account: ACMEAccount) => void
  onPollSeconds: (seconds: number) => void
  onPassword: () => void
  onLogout: () => void
  updateJob?: JobRecord
  updatingNode?: NodeRecord
}

function renderPage(page: PageKey, props: PageProps) {
  switch (page) {
    case 'overview': return <Overview data={props.data} onNavigate={props.onPage} />
    case 'domains': return <DomainsPage domains={props.data.domains} nodes={props.data.nodes} onAdd={props.onAddDomain} onEdit={props.onEditDomain} onDelete={props.onDeleteDomain} />
    case 'certificates': return <CertificatesPage certificates={props.data.certificates} nodes={props.data.nodes} onAdd={props.onAddCertificate} onRenew={props.onRenew} onToggleAutoRenew={props.onToggleAutoRenew} onSync={props.onSync} onEdit={props.onEditCertificate} busy={props.busy} />
    case 'nodes': return <NodesPage nodes={props.data.nodes} onManage={props.onManageNode} />
    case 'audit': return <AuditPage events={props.data.audit} domains={props.data.domains} nodes={props.data.nodes} />
    case 'settings': return <SettingsPage dnsAccounts={props.dnsAccounts} acmeAccounts={props.acmeAccounts} settings={props.data.settings} busy={props.busy === 'settings-poll'} onAddDNS={props.onAddDNS} onAddACME={props.onAddACME} onEditDNS={props.onEditDNS} onEditACME={props.onEditACME} onPollSeconds={props.onPollSeconds} onPassword={props.onPassword} onLogout={props.onLogout} />
    case 'update': return <ControllerUpdatePage job={props.updateJob} node={props.updatingNode} />
  }
}
