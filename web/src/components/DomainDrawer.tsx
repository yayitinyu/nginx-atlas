import { useEffect, useMemo, useState, type FormEvent } from 'react'
import type { ACMEAccount, CertificateRecord, CreateDomainInput, DNSAccount, NodeRecord } from '../types'
import { Icon } from './Icon'
import { ActionButton, IconButton, StatusDot } from './Primitives'

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
  const [domain, setDomain] = useState('')
  const [nodeId, setNodeId] = useState('')
  const [upstreamHost, setUpstreamHost] = useState('127.0.0.1')
  const [port, setPort] = useState('')
  const [source, setSource] = useState<Source>('existing')
  const [existingCertificate, setExistingCertificate] = useState('local')
  const [fullchain, setFullchain] = useState<File>()
  const [privkey, setPrivkey] = useState<File>()
  const [dnsAccount, setDNSAccount] = useState('')
  const [acmeAccount, setACMEAccount] = useState('')
  const [autoRenew, setAutoRenew] = useState(true)
  const [syncNodes, setSyncNodes] = useState<string[]>([])
  const [httpOnly, setHTTPOnly] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setNodeId((current) => current || nodes.find((node) => node.status !== 'revoked')?.id || '')
    setDNSAccount((current) => current || dnsAccounts[0]?.id || '')
    setACMEAccount((current) => current || acmeAccounts[0]?.id || '')
  }, [open, nodes, dnsAccounts, acmeAccounts])

  const eligibleCertificates = useMemo(() => certificates.filter((certificate) => !domain || certificate.domain === domain.trim().toLowerCase() || certificate.dns_names.includes(domain.trim().toLowerCase())), [certificates, domain])
  const selectedNode = nodes.find((node) => node.id === nodeId)
  const otherNodes = nodes.filter((node) => node.id !== nodeId && node.status !== 'revoked')
  const previewDomain = domain.trim().toLowerCase() || 'api.example.com'
  const previewPort = Number(port) || 8080
  const tls = !httpOnly

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const parsedPort = Number(port)
    if (!domain.trim() || !nodeId || !upstreamHost.trim() || !Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setError('请完整填写有效域名、目标节点、上游地址和端口。')
      return
    }
    if (!httpOnly && source === 'upload' && (!fullchain || !privkey)) {
      setError('请同时选择 fullchain.pem 与 privkey.pem。')
      return
    }
    if (!httpOnly && source === 'acme' && (!dnsAccount || !acmeAccount)) {
      setError('使用 Let’s Encrypt 需要先选择 DNS 与 ACME 账户。')
      return
    }
    if (!httpOnly && autoRenew && source !== 'acme' && (!dnsAccount || !acmeAccount)) {
      setError('为已有或上传证书开启自动续期时，需要选择 DNS 与 ACME 账户。')
      return
    }
    let certificateMode: CreateDomainInput['certificate_mode'] = 'none'
    let certificateId: string | undefined
    if (!httpOnly) {
      if (source === 'acme') certificateMode = 'acme'
      else if (source === 'upload') certificateMode = 'upload'
      else if (existingCertificate === 'local') certificateMode = 'local'
      else {
        certificateMode = 'upload'
        certificateId = existingCertificate
      }
    }
    await onSubmit({
      input: {
        domain: domain.trim().toLowerCase(),
        node_id: nodeId,
        upstream_host: upstreamHost.trim().toLowerCase(),
        upstream_port: parsedPort,
        certificate_mode: certificateMode,
        certificate_id: certificateId,
        acme_account_id: autoRenew || source === 'acme' ? acmeAccount : undefined,
        dns_account_id: autoRenew || source === 'acme' ? dnsAccount : undefined,
        auto_renew: tls && autoRenew,
        renew_before_days: 30,
        sync_node_ids: syncNodes,
      },
      fullchain,
      privkey,
    })
  }

  function toggleSync(nodeID: string) {
    setSyncNodes((current) => current.includes(nodeID) ? current.filter((id) => id !== nodeID) : [...current, nodeID])
  }

  return (
    <div className={`drawer-layer ${open ? 'drawer-open' : ''}`} aria-hidden={!open} onMouseDown={(event) => event.currentTarget === event.target && !busy && onClose()}>
      <form className="domain-drawer" onSubmit={submit} aria-label="添加域名">
        <header className="drawer-header"><div><h2>添加域名</h2><p>配置路由、证书与多节点同步</p></div><IconButton name="close" label="关闭" type="button" onClick={onClose} disabled={busy} /></header>
        <div className="drawer-steps" aria-label="部署步骤"><span className="step-active"><i>1</i>路由</span><b /><span className={domain && nodeId ? 'step-ready' : ''}><i>2</i>证书</span><b /><span className={domain && nodeId && port ? 'step-ready' : ''}><i>3</i>部署</span></div>
        <div className="drawer-body">
          <div className="form-row">
            <label htmlFor="domain-name">域名</label>
            <div className="field-control"><input id="domain-name" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="api.example.com" autoComplete="off" /><span className="field-state">{domain.includes('.') && <Icon name="check" size={17} />}</span></div>
          </div>
          <div className="form-row">
            <label htmlFor="target-node">目标节点</label>
            <div className="field-control select-control"><Icon name="server" size={17} /><select id="target-node" value={nodeId} onChange={(event) => { setNodeId(event.target.value); setSyncNodes((current) => current.filter((id) => id !== event.target.value)) }}><option value="">选择 Linux 节点</option>{nodes.filter((node) => node.status !== 'revoked').map((node) => <option key={node.id} value={node.id}>{node.name} · {node.status === 'online' ? '在线' : '离线'}</option>)}</select><Icon name="chevron" size={16} /></div>
          </div>
          <div className="form-row form-row-split">
            <label htmlFor="upstream-host">上游地址</label>
            <div className="split-fields"><div className="field-control"><input id="upstream-host" value={upstreamHost} onChange={(event) => setUpstreamHost(event.target.value)} placeholder="127.0.0.1" /></div><div className="port-field"><span>项目端口</span><div className="field-control"><input aria-label="项目端口" inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))} placeholder="8080" /></div></div></div>
          </div>

          <fieldset className="certificate-source" disabled={httpOnly}>
            <legend>证书来源</legend>
            <div className="segmented-control">
              <button type="button" className={source === 'existing' ? 'selected' : ''} onClick={() => setSource('existing')}><Icon name="shield" size={17} />已有证书{source === 'existing' && <Icon name="check" size={15} />}</button>
              <button type="button" className={source === 'upload' ? 'selected' : ''} onClick={() => setSource('upload')}><Icon name="upload" size={17} />上传证书{source === 'upload' && <Icon name="check" size={15} />}</button>
              <button type="button" className={source === 'acme' ? 'selected' : ''} onClick={() => setSource('acme')}><Icon name="key" size={17} />Let’s Encrypt{source === 'acme' && <Icon name="check" size={15} />}</button>
            </div>
            <div className="certificate-source-body">
              {source === 'existing' && <label className="source-select"><span>证书位置</span><div className="field-control select-control"><select value={existingCertificate} onChange={(event) => setExistingCertificate(event.target.value)}><option value="local">使用目标节点 /etc/ssl/{domain.trim().toLowerCase() || 'example.com'}</option>{eligibleCertificates.map((certificate) => <option value={certificate.id} key={certificate.id}>主控证书 · {certificate.domain} · {certificate.days_remaining} 天</option>)}</select><Icon name="chevron" size={16} /></div></label>}
              {source === 'upload' && <div className="certificate-upload-grid"><FileField label="fullchain.pem" file={fullchain} onChange={setFullchain} accept=".pem,.crt" /><FileField label="privkey.pem" file={privkey} onChange={setPrivkey} accept=".pem,.key" /></div>}
              {(source === 'acme' || autoRenew) && (
                <div className="account-fields">
                  <label><span>DNS 账户</span><div className="field-control select-control"><select value={dnsAccount} onChange={(event) => setDNSAccount(event.target.value)}><option value="">选择 DNS 账户</option>{dnsAccounts.map((account) => <option value={account.id} key={account.id}>{account.name} · {account.provider}</option>)}</select><Icon name="chevron" size={16} /></div></label>
                  <label><span>ACME 账户</span><div className="field-control select-control"><select value={acmeAccount} onChange={(event) => setACMEAccount(event.target.value)}><option value="">选择 ACME 账户</option>{acmeAccounts.map((account) => <option value={account.id} key={account.id}>{account.name} · {account.email}</option>)}</select><Icon name="chevron" size={16} /></div></label>
                </div>
              )}
              <label className="switch-row"><button type="button" role="switch" aria-checked={autoRenew} className={autoRenew ? 'switch-on' : ''} onClick={() => setAutoRenew((value) => !value)}><i /></button><span><strong>到期前自动续期</strong><small>证书进入 30 天到期窗口后自动执行 DNS-01</small></span></label>
            </div>
          </fieldset>

          <div className="form-row sync-row">
            <label>同步到其他节点</label>
            <div className="sync-node-select">
              {otherNodes.length === 0 ? <span className="empty-inline">暂无其他可用节点</span> : otherNodes.map((node) => <button type="button" key={node.id} className={syncNodes.includes(node.id) ? 'selected' : ''} onClick={() => toggleSync(node.id)}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} />{node.name}{syncNodes.includes(node.id) && <Icon name="check" size={14} />}</button>)}
            </div>
            <small>部署后将证书安全推送到所选节点，并分别验证、重载 Nginx。</small>
          </div>

          <div className="form-row preview-row">
            <label>Nginx 配置预览</label>
            <pre><span>server {'{'}</span>{tls && <><br />{'  '}listen <em>443 ssl</em>;<br />{'  '}ssl_certificate <em>/etc/ssl/{previewDomain}/fullchain.pem</em>;</>}<br />{'  '}server_name <em>{previewDomain}</em>;<br />{'  '}location / {'{'}<br />{'    '}proxy_pass <em>http://{upstreamHost || '127.0.0.1'}:{previewPort}</em>;<br />{'  }'}<br />{'}'}</pre>
          </div>

          <label className="http-only-row"><input type="checkbox" checked={httpOnly} onChange={(event) => setHTTPOnly(event.target.checked)} /><span>暂不启用 TLS，仅创建 HTTP 路由</span></label>
          <div className="deploy-note"><Icon name="info" size={17} /><span>部署时将先执行 <code>nginx -t</code>。验证或重载失败会自动恢复旧配置与证书。</span></div>
          {selectedNode?.status !== 'online' && nodeId && <div className="form-warning"><Icon name="warning" size={17} />目标节点当前离线；任务会排队，节点恢复连接后自动执行。</div>}
          {error && <div className="form-error drawer-error" role="alert"><Icon name="warning" size={16} />{error}</div>}
        </div>
        <footer className="drawer-footer"><button className="cancel-button" type="button" onClick={onClose} disabled={busy}>取消</button><ActionButton type="submit" wide disabled={busy || nodes.length === 0}>{busy ? '正在创建任务' : '验证并部署'}</ActionButton></footer>
      </form>
    </div>
  )
}

function FileField({ label, file, onChange, accept }: { label: string; file?: File; onChange: (file?: File) => void; accept: string }) {
  return (
    <label className={file ? 'file-field file-selected' : 'file-field'}>
      <input type="file" accept={accept} onChange={(event) => onChange(event.target.files?.[0])} />
      <Icon name={file ? 'check' : 'upload'} size={18} />
      <span><strong>{label}</strong><small>{file ? file.name : '选择 PEM 文件'}</small></span>
    </label>
  )
}
