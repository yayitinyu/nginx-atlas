import { useState, type FormEvent } from 'react'
import { setToken } from '../api'
import { Icon } from './Icon'
import { ActionButton, Logo } from './Primitives'

export function LoginGate({ onVerify }: { onVerify: () => Promise<void> }) {
  const [token, setValue] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (token.trim().length < 24) {
      setError('请输入安装时生成的管理员令牌')
      return
    }
    setBusy(true)
    setError('')
    setToken(token)
    try {
      await onVerify()
    } catch {
      sessionStorage.removeItem('nginx-atlas-token')
      setError('令牌无效，或主控暂时无法连接')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-screen">
      <div className="login-field-light" aria-hidden="true" />
      <section className="login-copy">
        <Logo />
        <h1>基础设施，<br />一目了然</h1>
        <p>在同一个安全平面中编排域名、证书与 Linux 节点。</p>
      </section>
      <div className="login-shell">
        <form className="login-card" onSubmit={submit}>
          <span className="login-key"><Icon name="key" size={24} /></span>
          <h2>进入控制台</h2>
          <p>管理员令牌只保存在当前浏览器会话中。</p>
          <label htmlFor="admin-token">管理员令牌</label>
          <div className={`login-input ${error ? 'field-error' : ''}`}>
            <Icon name="terminal" size={18} />
            <input
              id="admin-token"
              type="password"
              autoComplete="current-password"
              value={token}
              onChange={(event) => setValue(event.target.value)}
              placeholder="粘贴 ATLAS_ADMIN_TOKEN"
              autoFocus
            />
          </div>
          {error && <span className="form-error" role="alert">{error}</span>}
          <ActionButton wide disabled={busy}>{busy ? '正在验证' : '验证并进入'}</ActionButton>
        </form>
      </div>
    </main>
  )
}
