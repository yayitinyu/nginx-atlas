import { useCallback, useEffect, useMemo, useState } from 'react'
import { APIError, api, clearToken, getToken } from './api'
import type { ACMEAccount, CertificateRecord, DashboardData, DNSAccount, DomainRecord, EnrollmentResponse, NodeRecord } from './types'
import { Icon } from './components/Icon'
import { LoginGate } from './components/LoginGate'
import { MobileHeader, MobileMenu, MobileNavigation, NavigationRail, type PageKey } from './components/Navigation'
import { ConfirmDialog, LoadingState, ToastRegion, type ToastMessage } from './components/Primitives'
import { DomainDrawer, type DomainSubmission } from './components/DomainDrawer'
import { ACMEAccountDialog, DNSAccountDialog, NodeDialog, SyncDialog } from './components/Dialogs'
import { Overview } from './views/Overview'
import { AccountsPage, AuditPage, CertificatesPage, DomainsPage, NodesPage, SettingsPage } from './views/Operations'

type AuthState = 'checking' | 'anonymous' | 'authenticated'

const emptyDashboard: DashboardData = { nodes: [], domains: [], certificates: [], audit: [], jobs: [], server_time: new Date().toISOString() }

export default function App() {
  const [auth, setAuth] = useState<AuthState>(getToken() ? 'checking' : 'anonymous')
  const [page, setPage] = useState<PageKey>('overview')
  const [data, setData] = useState<DashboardData>(emptyDashboard)
  const [dnsAccounts, setDNSAccounts] = useState<DNSAccount[]>([])
  const [acmeAccounts, setACMEAccounts] = useState<ACMEAccount[]>([])
  const [loading, setLoading] = useState(true)
  const [mobileMenu, setMobileMenu] = useState(false)
  const [domainDrawer, setDomainDrawer] = useState(false)
  const [nodeDialog, setNodeDialog] = useState(false)
  const [nodeResult, setNodeResult] = useState<EnrollmentResponse>()
  const [dnsDialog, setDNSDialog] = useState(false)
  const [acmeDialog, setACMEDialog] = useState(false)
  const [syncCertificate, setSyncCertificate] = useState<CertificateRecord>()
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
    clearToken()
    setAuth('anonymous')
    setData(emptyDashboard)
    setMobileMenu(false)
  }, [])

  const handleError = useCallback((error: unknown, fallback: string) => {
    if (error instanceof APIError && error.status === 401) {
      logout()
      return
    }
    toast('error', error instanceof Error ? error.message : fallback)
  }, [logout, toast])

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const [dashboard, dns, acme] = await Promise.all([api.dashboard(), api.dnsAccounts(), api.acmeAccounts()])
      setData(dashboard)
      setDNSAccounts(dns)
      setACMEAccounts(acme)
    } catch (error) {
      handleError(error, '无法读取主控状态')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [handleError])

  const verify = useCallback(async () => {
    await api.verifySession()
    setAuth('authenticated')
  }, [])

  useEffect(() => {
    if (auth !== 'checking') return
    verify().catch(() => logout())
  }, [auth, verify, logout])

  useEffect(() => {
    if (auth !== 'authenticated') return
    void refresh()
    const interval = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh(true) }, 10_000)
    return () => window.clearInterval(interval)
  }, [auth, refresh])

  useEffect(() => {
    document.body.classList.toggle('overlay-active', domainDrawer || nodeDialog || dnsDialog || acmeDialog || Boolean(syncCertificate) || Boolean(confirmDomain) || Boolean(confirmNode) || mobileMenu)
    return () => document.body.classList.remove('overlay-active')
  }, [domainDrawer, nodeDialog, dnsDialog, acmeDialog, syncCertificate, confirmDomain, confirmNode, mobileMenu])

  const allHealthy = useMemo(() => data.nodes.length > 0 && data.nodes.every((node) => node.status === 'online' && node.nginx_healthy), [data.nodes])

  async function createDomain(submission: DomainSubmission) {
    setBusy('domain')
    try {
      const input = { ...submission.input }
      if (input.certificate_mode === 'upload' && submission.fullchain && submission.privkey) {
        const certificate = await api.uploadCertificate(input.domain, submission.fullchain, submission.privkey)
        input.certificate_id = certificate.id
      }
      await api.createDomain(input)
      setDomainDrawer(false)
      setPage('domains')
      toast('success', '域名已加入部署队列；节点将先验证 Nginx 配置。')
      await refresh(true)
    } catch (error) {
      handleError(error, '无法创建域名')
      throw error
    } finally {
      setBusy('')
    }
  }

  async function createNode(name: string) {
    setBusy('node')
    try {
      setNodeResult(await api.createEnrollment(name.trim()))
    } catch (error) {
      handleError(error, '无法生成节点命令')
    } finally {
      setBusy('')
    }
  }

  async function createDNS(input: { name: string; provider: string; credentials: Record<string, string> }) {
    setBusy('dns')
    try {
      await api.createDNSAccount(input)
      setDNSDialog(false)
      toast('success', 'DNS 账户已加密保存。')
      await refresh(true)
    } catch (error) {
      handleError(error, '无法保存 DNS 账户')
    } finally { setBusy('') }
  }

  async function createACME(input: { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string }) {
    setBusy('acme')
    try {
      await api.createACMEAccount(input)
      setACMEDialog(false)
      toast('success', 'ACME 账户已保存。')
      await refresh(true)
    } catch (error) {
      handleError(error, '无法保存 ACME 账户')
    } finally { setBusy('') }
  }

  async function deleteDomain() {
    if (!confirmDomain) return
    setBusy('confirm')
    try {
      await api.deleteDomain(confirmDomain.id)
      toast('info', '域名移除任务已排队，配置通过验证后才会重载。')
      setConfirmDomain(undefined)
      await refresh(true)
    } catch (error) { handleError(error, '无法移除域名') } finally { setBusy('') }
  }

  async function revokeNode() {
    if (!confirmNode) return
    setBusy('confirm')
    try {
      await api.revokeNode(confirmNode.id)
      toast('success', '节点凭据已撤销。')
      setConfirmNode(undefined)
      await refresh(true)
    } catch (error) { handleError(error, '无法撤销节点') } finally { setBusy('') }
  }

  async function renewCertificate(certificate: CertificateRecord) {
    setBusy(`renew-${certificate.id}`)
    try {
      await api.renewCertificate(certificate.id)
      toast('success', `${certificate.domain} 已加入 DNS-01 续期队列。`)
      await refresh(true)
    } catch (error) { handleError(error, '无法创建续期任务') } finally { setBusy('') }
  }

  async function syncSelectedNodes(nodeIDs: string[]) {
    if (!syncCertificate) return
    setBusy('sync')
    try {
      await api.syncCertificate(syncCertificate.id, nodeIDs)
      toast('success', `证书已加入 ${nodeIDs.length} 个节点的同步队列。`)
      setSyncCertificate(undefined)
      await refresh(true)
    } catch (error) { handleError(error, '无法创建同步任务') } finally { setBusy('') }
  }

  if (auth === 'checking') return <div className="app-loading"><LoadingState label="正在验证管理员会话" /></div>
  if (auth === 'anonymous') return <LoginGate onVerify={verify} />

  return (
    <div className="app-shell">
      <NavigationRail page={page} onChange={setPage} onLogout={logout} />
      <MobileHeader onMenu={() => setMobileMenu(true)} />
      <div className="workspace">
        <header className="command-bar">
          <span className="system-state"><span className={`pulse-dot ${allHealthy ? '' : 'pulse-warning'}`} />{allHealthy ? '所有系统正常运行' : data.nodes.length === 0 ? '等待添加首个节点' : '部分节点需要检查'}</span>
          <div className="command-proof"><Icon name="terminal" size={17} /><code>nginx -t</code><span><Icon name={allHealthy ? 'check' : 'warning'} size={16} />{allHealthy ? '配置已验证' : '状态已同步'}</span><button onClick={() => void refresh()} aria-label="立即刷新"><Icon name="refresh" size={18} /></button></div>
        </header>
        <main className="workspace-content">
          {loading ? <LoadingState /> : renderPage(page, {
            data,
            dnsAccounts,
            acmeAccounts,
            onAddDomain: () => setDomainDrawer(true),
            onPage: setPage,
            onDeleteDomain: setConfirmDomain,
            onAddNode: () => { setNodeResult(undefined); setNodeDialog(true) },
            onRevokeNode: setConfirmNode,
            onRenew: (certificate) => void renewCertificate(certificate),
            onSync: setSyncCertificate,
            onAddDNS: () => setDNSDialog(true),
            onAddACME: () => setACMEDialog(true),
            onLogout: logout,
          })}
        </main>
      </div>
      <MobileNavigation page={page} onChange={setPage} />
      <MobileMenu open={mobileMenu} page={page} onChange={setPage} onClose={() => setMobileMenu(false)} onLogout={logout} />

      <DomainDrawer open={domainDrawer} nodes={data.nodes} certificates={data.certificates} dnsAccounts={dnsAccounts} acmeAccounts={acmeAccounts} busy={busy === 'domain'} onClose={() => !busy && setDomainDrawer(false)} onSubmit={createDomain} />
      <NodeDialog open={nodeDialog} busy={busy === 'node'} result={nodeResult} onClose={() => { setNodeDialog(false); setNodeResult(undefined) }} onCreate={createNode} />
      <DNSAccountDialog open={dnsDialog} busy={busy === 'dns'} onClose={() => setDNSDialog(false)} onCreate={createDNS} />
      <ACMEAccountDialog open={acmeDialog} busy={busy === 'acme'} onClose={() => setACMEDialog(false)} onCreate={createACME} />
      <SyncDialog open={Boolean(syncCertificate)} certificate={syncCertificate} nodes={data.nodes} busy={busy === 'sync'} onClose={() => setSyncCertificate(undefined)} onSync={syncSelectedNodes} />
      <ConfirmDialog open={Boolean(confirmDomain)} title="移除域名配置？" description={`节点将删除 ${confirmDomain?.name ?? ''} 的托管配置，通过 nginx -t 后才会重载。证书文件不会自动删除。`} confirmLabel="移除域名" onCancel={() => setConfirmDomain(undefined)} onConfirm={() => void deleteDomain()} busy={busy === 'confirm'} />
      <ConfirmDialog open={Boolean(confirmNode)} title="撤销节点访问？" description={`${confirmNode?.name ?? ''} 将无法继续领取任务。节点本地现有 Nginx 配置与证书不会被删除。`} confirmLabel="撤销节点" onCancel={() => setConfirmNode(undefined)} onConfirm={() => void revokeNode()} busy={busy === 'confirm'} />
      <ToastRegion messages={toasts} dismiss={(id) => setToasts((items) => items.filter((item) => item.id !== id))} />
    </div>
  )
}

interface PageProps {
  data: DashboardData
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDomain: () => void
  onPage: (page: PageKey) => void
  onDeleteDomain: (domain: DomainRecord) => void
  onAddNode: () => void
  onRevokeNode: (node: NodeRecord) => void
  onRenew: (certificate: CertificateRecord) => void
  onSync: (certificate: CertificateRecord) => void
  onAddDNS: () => void
  onAddACME: () => void
  onLogout: () => void
}

function renderPage(page: PageKey, props: PageProps) {
  switch (page) {
    case 'overview': return <Overview data={props.data} onAddDomain={props.onAddDomain} onNavigate={props.onPage} />
    case 'domains': return <DomainsPage domains={props.data.domains} onAdd={props.onAddDomain} onDelete={props.onDeleteDomain} />
    case 'certificates': return <CertificatesPage certificates={props.data.certificates} nodes={props.data.nodes} onRenew={props.onRenew} onSync={props.onSync} />
    case 'nodes': return <NodesPage nodes={props.data.nodes} onAdd={props.onAddNode} onRevoke={props.onRevokeNode} />
    case 'accounts': return <AccountsPage dnsAccounts={props.dnsAccounts} acmeAccounts={props.acmeAccounts} onAddDNS={props.onAddDNS} onAddACME={props.onAddACME} />
    case 'audit': return <AuditPage events={props.data.audit} domains={props.data.domains} nodes={props.data.nodes} />
    case 'settings': return <SettingsPage onLogout={props.onLogout} />
  }
}
