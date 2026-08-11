import { useMemo, useState } from 'react'
import type { ACMEAccount, AuditEvent, CertificateRecord, DNSAccount, DomainRecord, NodeRecord } from '../types'
import { Icon } from '../components/Icon'
import { ActionButton, Bezel, EmptyState, IconButton, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'
import { DomainTable, relativeTime } from './Overview'

export function DomainsPage({ domains, onAdd, onDelete }: { domains: DomainRecord[]; onAdd: () => void; onDelete: (domain: DomainRecord) => void }) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => {
    const value = query.trim().toLowerCase()
    return domains.filter((domain) => !value || domain.name.includes(value) || domain.node_name.toLowerCase().includes(value) || `${domain.upstream_host}:${domain.upstream_port}`.includes(value))
  }, [domains, query])
  return (
    <div className="content-page page-enter">
      <PageHeader title="域名与路由" description="将外部域名映射到各节点上的项目端口，并以事务方式部署 Nginx 配置。" action={<ActionButton icon="plus" onClick={onAdd}>添加域名</ActionButton>} />
      <Bezel className="operation-panel">
        <div className="panel-toolbar">
          <div className="toolbar-tabs"><button className="active">域名</button><button>部署队列</button></div>
          <label className="search-field"><Icon name="search" size={17} /><span className="sr-only">搜索域名</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索域名、节点或端口" /></label>
        </div>
        {filtered.length ? <DomainTable domains={filtered} showActions={(domain) => <IconButton name="trash" label={`移除 ${domain.name}`} onClick={() => onDelete(domain)} />} /> : <EmptyState icon="globe" title="没有域名" description="创建一条路由后，代理会先运行 nginx -t，再安全重载。" action={<button className="inline-action" onClick={onAdd}><Icon name="plus" size={17} />添加域名</button>} />}
        <div className="panel-footer"><span>显示 {filtered.length} / {domains.length} 条</span><span className="footer-note"><Icon name="terminal" size={15} />每次变更都需要通过 nginx -t</span></div>
      </Bezel>
    </div>
  )
}

export function CertificatesPage({ certificates, nodes, onRenew, onSync }: {
  certificates: CertificateRecord[]
  nodes: NodeRecord[]
  onRenew: (certificate: CertificateRecord) => void
  onSync: (certificate: CertificateRecord) => void
}) {
  return (
    <div className="content-page page-enter">
      <PageHeader title="证书" description="检查证书链、私钥匹配与到期窗口，并将同一版本安全同步到多台 VPS。" />
      <Bezel className="operation-panel certificate-list-panel">
        <div className="certificate-list-head"><span>域名 / 签发者</span><span>来源</span><span>到期时间</span><span>已部署节点</span><span /></div>
        {certificates.length === 0 ? <EmptyState icon="shield" title="还没有证书" description="可在添加域名时上传 fullchain.pem 与 privkey.pem，或通过 DNS-01 自动签发。" /> : certificates.map((certificate) => (
          <div className="certificate-list-row" key={certificate.id}>
            <span className="cert-identity"><StatusIcon tone={certificate.status === 'valid' ? 'success' : certificate.status === 'expiring' ? 'warning' : 'error'} /><span><strong>{certificate.domain}</strong><small>{certificate.issuer}</small></span></span>
            <span className="source-label">{certificate.source === 'acme' ? "Let's Encrypt / ACME" : certificate.source === 'upload' ? '手动上传' : '节点已有'}</span>
            <span className={`expiry-label expiry-${certificate.status}`}><strong>{certificate.days_remaining > 0 ? `${certificate.days_remaining} 天` : '已到期'}</strong><small>{formatDate(certificate.not_after)}</small></span>
            <span className="deployed-count"><strong>{certificate.deployed_node_ids.length}</strong> / {nodes.length}</span>
            <span className="certificate-actions"><button onClick={() => onRenew(certificate)}><Icon name="refresh" size={16} />续期</button><button onClick={() => onSync(certificate)}><Icon name="upload" size={16} />同步</button></span>
          </div>
        ))}
      </Bezel>
    </div>
  )
}

export function NodesPage({ nodes, onAdd, onRevoke }: { nodes: NodeRecord[]; onAdd: () => void; onRevoke: (node: NodeRecord) => void }) {
  return (
    <div className="content-page page-enter">
      <PageHeader title="节点" description="节点只需主动连接主控，不必在公网暴露新的管理端口。" action={<ActionButton icon="plus" onClick={onAdd}>添加节点</ActionButton>} />
      <div className="nodes-canvas">
        {nodes.length === 0 ? <Bezel><EmptyState icon="server" title="还没有 Linux 节点" description="生成一次性安装命令，并在目标 VPS 上执行。" action={<button className="inline-action" onClick={onAdd}><Icon name="terminal" size={17} />生成添加命令</button>} /></Bezel> : nodes.map((node) => (
          <Bezel className="node-detail" key={node.id}>
            <div className="node-detail-top"><span className="node-machine"><Icon name="server" size={22} /></span><span><strong>{node.name}</strong><small>{node.hostname || '等待上报主机名'}</small></span><span className={`node-state node-state-${node.status}`}><StatusDot tone={node.status === 'online' && node.nginx_healthy ? 'good' : node.status === 'offline' ? 'danger' : 'warning'} />{node.status === 'online' ? '在线' : node.status === 'offline' ? '离线' : node.status === 'revoked' ? '已撤销' : '待连接'}</span></div>
            <div className="node-specs"><span><small>公网 / 内网地址</small><strong>{node.ip_addresses?.join(' · ') || '—'}</strong></span><span><small>Nginx</small><strong>{node.nginx_version || '未检测'}</strong></span><span><small>平台</small><strong>{[node.os, node.arch].filter(Boolean).join(' / ') || '—'}</strong></span><span><small>证书目录</small><strong>{node.certificates?.length ?? 0} 个已发现</strong></span></div>
            <div className="node-detail-footer"><span><Icon name="clock" size={15} />最后在线：{node.last_seen_at ? relativeTime(node.last_seen_at) : '从未连接'}</span>{node.status !== 'revoked' && <button className="danger-link" onClick={() => onRevoke(node)}><Icon name="trash" size={15} />撤销节点</button>}</div>
          </Bezel>
        ))}
      </div>
    </div>
  )
}

export function AccountsPage({ dnsAccounts, acmeAccounts, onAddDNS, onAddACME }: {
  dnsAccounts: DNSAccount[]
  acmeAccounts: ACMEAccount[]
  onAddDNS: () => void
  onAddACME: () => void
}) {
  return (
    <div className="content-page page-enter">
      <PageHeader title="DNS / ACME" description="凭据在主控使用 AES-256-GCM 加密，仅在签发任务下发时短暂解密。" />
      <div className="account-split">
        <Bezel className="account-panel">
          <SectionHeading title="DNS 账户" action={<IconButton name="plus" label="添加 DNS 账户" onClick={onAddDNS} />} />
          {dnsAccounts.length === 0 ? <EmptyState icon="dns" title="尚未配置 DNS" description="添加 lego 支持的 DNS 提供商和最小权限 API 凭据。" action={<button className="inline-action" onClick={onAddDNS}><Icon name="plus" size={17} />添加 DNS 账户</button>} /> : <div className="account-list">{dnsAccounts.map((account) => <div className="account-row" key={account.id}><span className="account-icon"><Icon name="dns" size={20} /></span><span><strong>{account.name}</strong><small>{account.provider}</small></span><span className="credential-keys">{account.credential_keys.length} 项凭据</span><Icon name="chevron" size={17} /></div>)}</div>}
        </Bezel>
        <Bezel className="account-panel">
          <SectionHeading title="ACME 账户" action={<IconButton name="plus" label="添加 ACME 账户" onClick={onAddACME} />} />
          {acmeAccounts.length === 0 ? <EmptyState icon="key" title="尚未配置 ACME" description="保存邮箱、目录地址以及可选的 EAB 信息。" action={<button className="inline-action" onClick={onAddACME}><Icon name="plus" size={17} />添加 ACME 账户</button>} /> : <div className="account-list">{acmeAccounts.map((account) => <div className="account-row" key={account.id}><span className="account-icon"><Icon name="key" size={20} /></span><span><strong>{account.name}</strong><small>{account.email}</small></span><span className="credential-keys">{account.has_eab ? '已配置 EAB' : '标准账户'}</span><Icon name="chevron" size={17} /></div>)}</div>}
        </Bezel>
      </div>
    </div>
  )
}

export function AuditPage({ events, domains, nodes }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[] }) {
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return (
    <div className="content-page page-enter">
      <PageHeader title="审计日志" description="部署、续期、同步、重试与节点变更均保留可追踪记录。" />
      <Bezel className="operation-panel audit-panel">
        <div className="audit-head"><span>事件</span><span>对象</span><span>时间</span><span>级别</span></div>
        {events.length === 0 ? <EmptyState icon="log" title="暂无审计记录" description="完成一次配置操作后会出现在这里。" /> : events.map((event, index) => (
          <div className="audit-row" key={event.id || `${event.action}-${index}`}><span><StatusIcon tone={event.level === 'error' ? 'error' : event.level} /><span><strong>{event.message}</strong><small>{event.action}</small></span></span><span>{domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? ''] || '主控'}</span><time>{formatDateTime(event.created_at)}</time><span className={`audit-level audit-${event.level}`}>{event.level === 'success' ? '成功' : event.level === 'warning' ? '警告' : event.level === 'error' ? '错误' : '信息'}</span></div>
        ))}
      </Bezel>
    </div>
  )
}

export function SettingsPage({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="content-page page-enter">
      <PageHeader title="设置" description="运行边界与安全策略由安装配置控制，敏感值不会返回到浏览器。" />
      <div className="settings-list">
        <Bezel className="settings-row"><span className="settings-icon"><Icon name="shield" size={22} /></span><span><strong>证书安全</strong><small>私钥与 DNS 凭据使用主密钥加密；代理写入私钥时权限为 0600。</small></span><span className="settings-value">AES-256-GCM</span></Bezel>
        <Bezel className="settings-row"><span className="settings-icon"><Icon name="server" size={22} /></span><span><strong>节点通信</strong><small>一次性令牌注册，节点凭据哈希保存，仅允许出站 HTTPS 轮询。</small></span><span className="settings-value">10 秒</span></Bezel>
        <Bezel className="settings-row"><span className="settings-icon"><Icon name="terminal" size={22} /></span><span><strong>Nginx 事务</strong><small>写入配置和证书后执行 nginx -t；验证或重载失败会恢复旧文件。</small></span><span className="settings-value">原子回滚</span></Bezel>
      </div>
      <button className="logout-row" onClick={onLogout}><Icon name="logout" size={19} />退出当前管理员会话</button>
    </div>
  )
}

function PageHeader({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) {
  return <header className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{action}</header>
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(value))
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}
