import type {
  ACMEAccount,
  CertificateAutomationInput,
  CertificateRecord,
  CreateDomainInput,
  DashboardData,
  DNSAccount,
  DomainRecord,
  EnrollmentResponse,
  JobRecord,
  ManagementCommands,
  NodeRecord,
  ControllerSettings,
  ReleaseInfo,
  UninstallCommand,
} from './types'

const tokenKey = 'nginx-atlas-token'

export class APIError extends Error {
  readonly status: number
  readonly code?: string
  readonly details?: Record<string, string>

  constructor(message: string, status: number, code?: string, details?: Record<string, string>) {
    super(message)
    this.name = 'APIError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export function getToken(): string {
  return sessionStorage.getItem(tokenKey) ?? ''
}

export function setToken(token: string): void {
  sessionStorage.setItem(tokenKey, token.trim())
}

export function clearToken(): void {
  sessionStorage.removeItem(tokenKey)
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const token = getToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  headers.set('Accept', 'application/json')
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')

  const response = await fetch(path, { ...init, headers })
  if (!response.ok) {
    let payload: { error?: string; code?: string; details?: Record<string, string> } = {}
    try {
      payload = await response.json()
    } catch {
      // The HTTP status remains the authoritative fallback.
    }
    throw new APIError(payload.error ?? `请求失败（${response.status}）`, response.status, payload.code, payload.details)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  login: (password: string) => request<{ authenticated: boolean; token: string; expires_at: string }>('/api/v1/session', {
    method: 'POST', body: JSON.stringify({ password }),
  }),
  verifySession: () => request<{ authenticated: boolean }>('/api/v1/session'),
  dashboard: () => request<DashboardData>('/api/v1/dashboard'),
  nodes: () => request<NodeRecord[]>('/api/v1/nodes'),
  domains: () => request<DomainRecord[]>('/api/v1/domains'),
  certificates: () => request<CertificateRecord[]>('/api/v1/certificates'),
  dnsAccounts: () => request<DNSAccount[]>('/api/v1/dns-accounts'),
  acmeAccounts: () => request<ACMEAccount[]>('/api/v1/acme-accounts'),
  createEnrollment: (ttlMinutes = 30) =>
    request<EnrollmentResponse>('/api/v1/enrollments', {
      method: 'POST',
      body: JSON.stringify({ ttl_minutes: ttlMinutes }),
    }),
  revokeNode: (id: string) => request<void>(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  renameNode: (id: string, name: string) => request<NodeRecord>(`/api/v1/nodes/${encodeURIComponent(id)}`, {
    method: 'PUT', body: JSON.stringify({ name }),
  }),
  releaseInfo: () => request<ReleaseInfo>('/api/v1/release'),
  updateNodeAtlas: (id: string) => request<JobRecord>(`/api/v1/nodes/${encodeURIComponent(id)}/update-atlas`, { method: 'POST', body: '{}' }),
  updateNodeSystem: (id: string) => request<unknown>(`/api/v1/nodes/${encodeURIComponent(id)}/update-system`, { method: 'POST', body: '{}' }),
  nodeUninstallCommand: (id: string) => request<UninstallCommand>(`/api/v1/nodes/${encodeURIComponent(id)}/uninstall-command`),
  createDomain: (input: CreateDomainInput) =>
    request<DomainRecord>('/api/v1/domains', { method: 'POST', body: JSON.stringify(input) }),
  updateDomain: (id: string, input: Partial<CreateDomainInput>) =>
    request<DomainRecord>(`/api/v1/domains/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(input) }),
  adoptDomain: (input: { node_id: string; domain: string; config_path?: string; takeover?: boolean }) =>
    request<DomainRecord>('/api/v1/domains/adopt', { method: 'POST', body: JSON.stringify(input) }),
  deleteDomain: (id: string) =>
    request<{ queued: boolean }>(`/api/v1/domains/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  uploadCertificate: async (input: CertificateAutomationInput, certificate: File, privateKey: File) => {
    const body = new FormData()
    body.set('node_id', input.node_id)
    body.set('auto_renew', String(input.auto_renew))
    body.set('renew_before_days', String(input.renew_before_days))
    if (input.acme_account_id) body.set('acme_account_id', input.acme_account_id)
    if (input.dns_account_id) body.set('dns_account_id', input.dns_account_id)
    body.set('sync_node_ids', JSON.stringify(input.sync_node_ids))
    body.set('certificate', certificate)
    body.set('private_key', privateKey)
    return request<CertificateRecord>('/api/v1/certificates/upload', { method: 'POST', body })
  },
  issueCertificate: (input: CertificateAutomationInput) =>
    request<unknown>('/api/v1/certificates/issue', { method: 'POST', body: JSON.stringify(input) }),
  importCertificate: (input: CertificateAutomationInput) =>
    request<unknown>('/api/v1/certificates/import', { method: 'POST', body: JSON.stringify(input) }),
  setCertificateAutoRenew: (id: string, enabled: boolean) =>
    request<CertificateRecord>(`/api/v1/certificates/${encodeURIComponent(id)}/auto-renew`, {
      method: 'PUT', body: JSON.stringify({ enabled }),
    }),
  updateCertificateAutomation: (id: string, input: {
    node_id: string
    auto_renew: boolean
    renew_before_days: number
    acme_account_id: string
    dns_account_id: string
    dns_names: string[]
  }) => request<CertificateRecord>(`/api/v1/certificates/${encodeURIComponent(id)}/automation`, {
    method: 'PUT', body: JSON.stringify(input),
  }),
  renewCertificate: (id: string) =>
    request<unknown>(`/api/v1/certificates/${encodeURIComponent(id)}/renew`, { method: 'POST', body: '{}' }),
  syncCertificate: (id: string, nodeIds: string[]) =>
    request<unknown>(`/api/v1/certificates/${encodeURIComponent(id)}/sync`, {
      method: 'POST',
      body: JSON.stringify({ node_ids: nodeIds }),
    }),
  createDNSAccount: (input: { name: string; provider: string; credentials: Record<string, string>; keep_credentials?: boolean }) =>
    request<DNSAccount>('/api/v1/dns-accounts', { method: 'POST', body: JSON.stringify(input) }),
  updateDNSAccount: (id: string, input: { name: string; provider: string; credentials: Record<string, string>; keep_credentials: boolean }) =>
    request<DNSAccount>(`/api/v1/dns-accounts/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(input) }),
  createACMEAccount: (input: { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string; keep_eab?: boolean }) =>
    request<ACMEAccount>('/api/v1/acme-accounts', { method: 'POST', body: JSON.stringify(input) }),
  updateACMEAccount: (id: string, input: { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string; keep_eab: boolean }) =>
    request<ACMEAccount>(`/api/v1/acme-accounts/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(input) }),
  changeAdminPassword: (currentPassword: string, newPassword: string) =>
    request<{ changed: boolean; token: string; expires_at: string }>('/api/v1/settings/admin-password', {
      method: 'PUT', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  settings: () => request<ControllerSettings>('/api/v1/settings'),
  updateSettings: (settings: ControllerSettings) => request<ControllerSettings>('/api/v1/settings', {
    method: 'PUT', body: JSON.stringify(settings),
  }),
  managementCommands: () => request<ManagementCommands>('/api/v1/management-commands'),
}
