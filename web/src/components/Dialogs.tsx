import { useEffect, useState, type FormEvent } from 'react'
import type { CertificateRecord, EnrollmentResponse, NodeRecord } from '../types'
import { Icon } from './Icon'
import { ActionButton, IconButton, StatusDot } from './Primitives'

function DialogShell({ open, title, description, children, onClose }: { open: boolean; title: string; description: string; children: React.ReactNode; onClose: () => void }) {
  if (!open) return null
  return <div className="modal-layer" onMouseDown={(event) => event.currentTarget === event.target && onClose()}><section className="form-dialog" role="dialog" aria-modal="true" aria-label={title}><header><div><h2>{title}</h2><p>{description}</p></div><IconButton name="close" label="关闭" onClick={onClose} /></header>{children}</section></div>
}

export function NodeDialog({ open, busy, result, onClose, onCreate }: { open: boolean; busy: boolean; result?: EnrollmentResponse; onClose: () => void; onCreate: (name: string) => Promise<void> }) {
  const [name, setName] = useState('')
  const [copied, setCopied] = useState(false)
  useEffect(() => { if (!open) { setName(''); setCopied(false) } }, [open])
  async function copy() {
    if (!result) return
    await navigator.clipboard.writeText(result.command)
    setCopied(true)
  }
  return <DialogShell open={open} title="添加 Linux 节点" description="生成 30 分钟有效、仅可使用一次的安装命令。" onClose={onClose}>{result ? <div className="command-result"><span className="success-ring"><Icon name="check" size={23} /></span><h3>命令已生成</h3><p>请以 root 或 sudo 权限在目标 VPS 上执行：</p><pre>{result.command}</pre><button className="copy-command" onClick={copy}><Icon name={copied ? 'check' : 'copy'} size={17} />{copied ? '已复制' : '复制命令'}</button><small>令牌将在 {new Date(result.expires_at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })} 失效。安装器会检查 Nginx、证书目录和系统服务。</small></div> : <form onSubmit={(event) => { event.preventDefault(); void onCreate(name) }} className="dialog-form"><label><span>节点名称</span><div className="field-control"><Icon name="server" size={17} /><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Tokyo-02" autoFocus /></div></label><div className="dialog-note"><Icon name="info" size={17} /><span>节点主动访问主控，不需要开放额外入站管理端口。</span></div><ActionButton wide icon="terminal" disabled={busy || name.trim().length < 2}>{busy ? '正在生成' : '生成添加命令'}</ActionButton></form>}</DialogShell>
}

export function DNSAccountDialog({ open, busy, onClose, onCreate }: { open: boolean; busy: boolean; onClose: () => void; onCreate: (input: { name: string; provider: string; credentials: Record<string, string> }) => Promise<void> }) {
  const [name, setName] = useState('')
  const [provider, setProvider] = useState('cloudflare')
  const [credentials, setCredentials] = useState<Array<{ key: string; value: string }>>([{ key: 'CLOUDFLARE_DNS_API_TOKEN', value: '' }])
  function submit(event: FormEvent) {
    event.preventDefault()
    void onCreate({ name, provider, credentials: Object.fromEntries(credentials.map((item) => [item.key.trim(), item.value])) })
  }
  return <DialogShell open={open} title="添加 DNS 账户" description="使用 lego 提供商名称与环境变量凭据；建议创建仅可修改 DNS 记录的令牌。" onClose={onClose}><form className="dialog-form" onSubmit={submit}><label><span>账户名称</span><div className="field-control"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Cloudflare 主账户" /></div></label><label><span>lego 提供商</span><div className="field-control"><input value={provider} onChange={(event) => setProvider(event.target.value.toLowerCase())} placeholder="cloudflare" /></div></label><div className="credential-editor"><div className="credential-title"><span>环境变量凭据</span><button type="button" onClick={() => setCredentials((items) => [...items, { key: '', value: '' }])}><Icon name="plus" size={15} />增加</button></div>{credentials.map((item, index) => <div className="credential-line" key={index}><input aria-label={`凭据变量 ${index + 1}`} value={item.key} onChange={(event) => setCredentials((items) => items.map((value, itemIndex) => itemIndex === index ? { ...value, key: event.target.value.toUpperCase() } : value))} placeholder="CLOUDFLARE_DNS_API_TOKEN" /><input aria-label={`凭据值 ${index + 1}`} type="password" value={item.value} onChange={(event) => setCredentials((items) => items.map((value, itemIndex) => itemIndex === index ? { ...value, value: event.target.value } : value))} placeholder="••••••••••••" />{credentials.length > 1 && <IconButton name="close" label="移除此项" type="button" onClick={() => setCredentials((items) => items.filter((_, itemIndex) => itemIndex !== index))} />}</div>)}</div><div className="dialog-note"><Icon name="shield" size={17} /><span>凭据使用主密钥加密保存，API 列表只返回变量名。</span></div><ActionButton wide disabled={busy || name.trim().length < 2 || credentials.some((item) => !item.key || !item.value)}>{busy ? '正在保存' : '加密并保存'}</ActionButton></form></DialogShell>
}

export function ACMEAccountDialog({ open, busy, onClose, onCreate }: { open: boolean; busy: boolean; onClose: () => void; onCreate: (input: { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string }) => Promise<void> }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [directory, setDirectory] = useState('https://acme-v02.api.letsencrypt.org/directory')
  const [eabKID, setEABKID] = useState('')
  const [eabHMAC, setEABHMAC] = useState('')
  return <DialogShell open={open} title="添加 ACME 账户" description="默认使用 Let’s Encrypt 生产目录，也支持需要 EAB 的兼容 ACME 服务。" onClose={onClose}><form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void onCreate({ name, email, directory_url: directory, eab_kid: eabKID, eab_hmac: eabHMAC }) }}><label><span>账户名称</span><div className="field-control"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Let’s Encrypt 生产" /></div></label><label><span>联系邮箱</span><div className="field-control"><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="admin@example.com" /></div></label><label><span>ACME 目录</span><div className="field-control"><input type="url" value={directory} onChange={(event) => setDirectory(event.target.value)} /></div></label><details className="eab-details"><summary>外部账户绑定（EAB，可选）<Icon name="chevron" size={16} /></summary><label><span>EAB KID</span><div className="field-control"><input value={eabKID} onChange={(event) => setEABKID(event.target.value)} /></div></label><label><span>EAB HMAC</span><div className="field-control"><input type="password" value={eabHMAC} onChange={(event) => setEABHMAC(event.target.value)} /></div></label></details><ActionButton wide disabled={busy || name.trim().length < 2 || !email.includes('@')}>{busy ? '正在保存' : '保存 ACME 账户'}</ActionButton></form></DialogShell>
}

export function SyncDialog({ open, certificate, nodes, busy, onClose, onSync }: { open: boolean; certificate?: CertificateRecord; nodes: NodeRecord[]; busy: boolean; onClose: () => void; onSync: (nodeIDs: string[]) => Promise<void> }) {
  const [selected, setSelected] = useState<string[]>([])
  useEffect(() => { if (open && certificate) setSelected(nodes.filter((node) => node.status !== 'revoked' && !certificate.deployed_node_ids.includes(node.id)).map((node) => node.id)) }, [open, certificate, nodes])
  return <DialogShell open={open} title="同步证书" description={certificate ? `将 ${certificate.domain} 的当前证书版本安全推送到其他节点。` : ''} onClose={onClose}><div className="sync-dialog-body"><div className="sync-dialog-list">{nodes.filter((node) => node.status !== 'revoked').map((node) => <button key={node.id} className={selected.includes(node.id) ? 'selected' : ''} onClick={() => setSelected((items) => items.includes(node.id) ? items.filter((id) => id !== node.id) : [...items, node.id])}><StatusDot tone={node.status === 'online' ? 'good' : 'warning'} /><span><strong>{node.name}</strong><small>{node.status === 'online' ? '在线，任务将立即领取' : '离线，任务会保持排队'}</small></span>{selected.includes(node.id) && <Icon name="check" size={17} />}</button>)}</div><div className="dialog-note"><Icon name="terminal" size={17} /><span>每台节点都会独立校验证书、执行 nginx -t，并在失败时恢复旧文件。</span></div><ActionButton wide icon="upload" disabled={busy || selected.length === 0} onClick={() => void onSync(selected)}>{busy ? '正在创建任务' : `同步到 ${selected.length} 个节点`}</ActionButton></div></DialogShell>
}
