import { useMemo, useState } from 'react'
import type { AuditEvent, DashboardData, DomainRecord, NodeRecord } from '../types'
import { Icon } from '../components/Icon'
import { ActionButton, Bezel, EmptyState, IconButton, SectionHeading, StatusDot, StatusIcon } from '../components/Primitives'

interface Props {
  data: DashboardData
  onAddDomain: () => void
  onNavigate: (page: 'domains' | 'certificates' | 'nodes' | 'audit') => void
}

export function Overview({ data, onAddDomain, onNavigate }: Props) {
  const [query, setQuery] = useState('')
  const domains = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return data.domains.filter((domain) => !normalized || domain.name.includes(normalized) || domain.node_name.toLowerCase().includes(normalized))
  }, [data.domains, query])
  const onlineNodes = data.nodes.filter((node) => node.status === 'online' && node.nginx_healthy).length
  const expiring = data.certificates.filter((certificate) => certificate.status !== 'valid').length

  return (
    <div className="overview-page page-enter">
      <section className="overview-hero">
        <div>
          <h1>基础设施，<span>一目了然</span></h1>
        </div>
        <ActionButton icon="plus" onClick={onAddDomain}>添加域名</ActionButton>
      </section>

      <section className="mobile-status-strip" aria-label="运行摘要">
        <div><StatusDot tone="good" /><span>节点在线</span><strong>{onlineNodes} / {data.nodes.length}</strong><small>{onlineNodes === data.nodes.length ? '全部正常' : '需要检查'}</small></div>
        <div><StatusDot tone={expiring > 0 ? 'warning' : 'good'} /><span>证书临期</span><strong>{expiring}</strong><small>{expiring > 0 ? '30 天内到期' : '暂无风险'}</small></div>
      </section>

      <div className="overview-grid">
        <div className="overview-primary">
          <Bezel className="domain-panel">
            <div className="panel-toolbar">
              <h2>域名与路由</h2>
              <div className="toolbar-actions">
                <label className="search-field">
                  <Icon name="search" size={17} />
                  <span className="sr-only">搜索域名</span>
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索域名" />
                </label>
                <IconButton name="filter" label="筛选" />
              </div>
            </div>
            {domains.length > 0 ? (
              <DomainTable domains={domains.slice(0, 6)} onOpen={() => onNavigate('domains')} />
            ) : (
              <EmptyState icon="globe" title="还没有匹配的域名" description={query ? '调整搜索词，或直接创建新的路由。' : '添加第一个域名后，Nginx Atlas 会自动验证并部署。'} action={!query && <button className="inline-action" onClick={onAddDomain}><Icon name="plus" size={17} />添加域名</button>} />
            )}
            {data.domains.length > 0 && (
              <div className="panel-footer">
                <span>共 {data.domains.length} 条</span>
                <button className="text-link" onClick={() => onNavigate('domains')}>查看全部 <Icon name="arrow" size={17} /></button>
              </div>
            )}
          </Bezel>

          <CertificateTimeline data={data} onOpen={() => onNavigate('certificates')} />
        </div>
        <aside className="overview-rail">
          <NodeHealth nodes={data.nodes} onOpen={() => onNavigate('nodes')} />
          <ActivityFeed events={data.audit} domains={data.domains} nodes={data.nodes} onOpen={() => onNavigate('audit')} />
        </aside>
      </div>
    </div>
  )
}

export function DomainTable({ domains, onOpen, showActions }: { domains: DomainRecord[]; onOpen?: (domain: DomainRecord) => void; showActions?: (domain: DomainRecord) => React.ReactNode }) {
  return (
    <div className="domain-table" role="table" aria-label="域名与路由">
      <div className="domain-table-head" role="row">
        <span role="columnheader">域名</span>
        <span role="columnheader">路由目标</span>
        <span role="columnheader">证书状态</span>
        <span role="columnheader">节点</span>
        <span role="columnheader">状态</span>
        <span aria-hidden="true" />
      </div>
      {domains.map((domain) => {
        const certificate = certificateLabel(domain)
        return (
          <div className="domain-row" role="row" key={domain.id}>
            <button className="domain-name" role="cell" onClick={() => onOpen?.(domain)}>{domain.name}</button>
            <span className="route-target" role="cell">{domain.upstream_host}:{domain.upstream_port}<Icon name="link" size={14} /></span>
            <span className={`certificate-cell certificate-${domain.certificate_status}`} role="cell"><StatusDot tone={certificate.tone} />{certificate.label}</span>
            <span className="node-cell" role="cell"><Icon name="server" size={15} />{domain.node_name || '未连接'}</span>
            <span className="runtime-cell" role="cell"><StatusDot tone={domain.enabled && domain.job_status !== 'failed' ? 'good' : domain.job_status === 'failed' ? 'danger' : 'warning'} />{domain.job_status === 'queued' ? '排队中' : domain.job_status === 'running' ? '部署中' : domain.job_status === 'failed' ? '失败' : domain.enabled ? '运行中' : '待部署'}</span>
            <span className="row-action" role="cell">{showActions?.(domain) ?? <IconButton name="more" label={`${domain.name} 更多操作`} onClick={() => onOpen?.(domain)} />}</span>
          </div>
        )
      })}
    </div>
  )
}

function CertificateTimeline({ data, onOpen }: { data: DashboardData; onOpen: () => void }) {
  const certificates = data.certificates.slice(0, 4)
  return (
    <Bezel className="timeline-panel">
      <SectionHeading title="证书到期时间线" action={<span className="section-context">未来 90 天</span>} />
      {certificates.length === 0 ? (
        <EmptyState icon="shield" title="暂无证书" description="上传证书或使用 Let's Encrypt 后将在这里显示到期窗口。" />
      ) : (
        <div className="timeline-list">
          {certificates.map((certificate) => {
            const width = Math.max(6, Math.min(100, (certificate.days_remaining / 90) * 100))
            return (
              <div className="timeline-row" key={certificate.id}>
                <div><Icon name="shield" size={17} /><span><strong>{certificate.domain}</strong><small>{certificate.source === 'acme' ? "Let's Encrypt / ACME" : certificate.source === 'upload' ? '手动上传' : '节点已有'}</small></span></div>
                <div className="timeline-track"><span className={`timeline-fill timeline-${certificate.status}`} style={{ transform: `scaleX(${width / 100})` }} /></div>
                <span className={`timeline-days timeline-${certificate.status}`}>{certificate.days_remaining > 0 ? `${certificate.days_remaining} 天` : '已到期'}</span>
              </div>
            )
          })}
        </div>
      )}
      <div className="panel-footer timeline-footer"><span className="timeline-legend"><StatusDot tone="good" />有效 <StatusDot tone="warning" />即将到期 <StatusDot tone="danger" />已到期</span><button className="text-link" onClick={onOpen}>查看证书 <Icon name="arrow" size={17} /></button></div>
    </Bezel>
  )
}

function NodeHealth({ nodes, onOpen }: { nodes: NodeRecord[]; onOpen: () => void }) {
  return (
    <Bezel className="node-health-panel">
      <SectionHeading title="节点状态" action={<button className="square-link" onClick={onOpen} aria-label="打开节点列表"><Icon name="arrow" size={17} /></button>} />
      {nodes.length === 0 ? <EmptyState icon="server" title="还没有节点" description="生成添加命令并在 Linux VPS 上运行。" /> : (
        <div className="node-health-list">
          {nodes.slice(0, 5).map((node) => (
            <button className="node-health-row" key={node.id} onClick={onOpen}>
              <StatusDot tone={node.status === 'online' && node.nginx_healthy ? 'good' : node.status === 'offline' ? 'danger' : 'warning'} />
              <span><strong>{node.name}</strong><small>{node.ip_addresses?.[0] ?? node.hostname ?? '等待上报'}</small><small>{node.nginx_version || 'Nginx 未检测'}</small></span>
              <span className={node.status === 'online' ? 'node-online' : 'node-offline'}>{node.status === 'online' ? '在线' : '离线'}<strong>{node.nginx_healthy ? '100%' : '—'}</strong></span>
            </button>
          ))}
        </div>
      )}
      {nodes.length > 0 && <button className="rail-link" onClick={onOpen}>查看所有节点 <Icon name="arrow" size={17} /></button>}
    </Bezel>
  )
}

function ActivityFeed({ events, domains, nodes, onOpen }: { events: AuditEvent[]; domains: DomainRecord[]; nodes: NodeRecord[]; onOpen: () => void }) {
  const domainNames = Object.fromEntries(domains.map((domain) => [domain.id, domain.name]))
  const nodeNames = Object.fromEntries(nodes.map((node) => [node.id, node.name]))
  return (
    <Bezel className="activity-panel">
      <SectionHeading title="最近活动" action={<button className="plain-link" onClick={onOpen}>查看全部</button>} />
      {events.length === 0 ? <EmptyState icon="log" title="暂无活动" description="部署和续期事件会记录在这里。" /> : (
        <div className="activity-list">
          {events.slice(0, 6).map((event, index) => (
            <button className="activity-row" key={event.id || `${event.action}-${index}`} onClick={onOpen}>
              <StatusIcon tone={event.level === 'error' ? 'error' : event.level} />
              <span><strong>{event.message}</strong><small>{domainNames[event.domain_id ?? ''] || nodeNames[event.node_id ?? ''] || event.action}</small></span>
              <time>{relativeTime(event.created_at)}</time>
            </button>
          ))}
        </div>
      )}
    </Bezel>
  )
}

function certificateLabel(domain: DomainRecord): { label: string; tone: 'good' | 'warning' | 'danger' | 'muted' } {
  if (!domain.certificate_expiry) return { label: domain.certificate_mode ? '等待证书' : '仅 HTTP', tone: 'muted' }
  const days = Math.ceil((new Date(domain.certificate_expiry).getTime() - Date.now()) / 86_400_000)
  if (days <= 0) return { label: '已到期', tone: 'danger' }
  if (days <= 30) return { label: `${days} 天后到期`, tone: 'warning' }
  return { label: '有效', tone: 'good' }
}

export function relativeTime(value: string): string {
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000)
  if (seconds < 60) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}
