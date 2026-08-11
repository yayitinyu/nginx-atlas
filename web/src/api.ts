import type {
  ACMEAccount,
  CertificateRecord,
  CreateDomainInput,
  DashboardData,
  DNSAccount,
  DomainRecord,
  EnrollmentResponse,
  NodeRecord,
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
  verifySession: () => request<{ authenticated: boolean }>('/api/v1/session'),
  dashboard: () => request<DashboardData>('/api/v1/dashboard'),
  nodes: () => request<NodeRecord[]>('/api/v1/nodes'),
  domains: () => request<DomainRecord[]>('/api/v1/domains'),
  certificates: () => request<CertificateRecord[]>('/api/v1/certificates'),
  dnsAccounts: () => request<DNSAccount[]>('/api/v1/dns-accounts'),
  acmeAccounts: () => request<ACMEAccount[]>('/api/v1/acme-accounts'),
  createEnrollment: (name: string, ttlMinutes = 30) =>
    request<EnrollmentResponse>('/api/v1/enrollments', {
      method: 'POST',
      body: JSON.stringify({ name, ttl_minutes: ttlMinutes }),
    }),
  revokeNode: (id: string) => request<void>(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  createDomain: (input: CreateDomainInput) =>
    request<DomainRecord>('/api/v1/domains', { method: 'POST', body: JSON.stringify(input) }),
  deleteDomain: (id: string) =>
    request<{ queued: boolean }>(`/api/v1/domains/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  uploadCertificate: async (domain: string, fullchain: File, privkey: File) => {
    const body = new FormData()
    body.set('domain', domain)
    body.set('fullchain', fullchain)
    body.set('privkey', privkey)
    return request<CertificateRecord>('/api/v1/certificates/upload', { method: 'POST', body })
  },
  renewCertificate: (id: string) =>
    request<unknown>(`/api/v1/certificates/${encodeURIComponent(id)}/renew`, { method: 'POST', body: '{}' }),
  syncCertificate: (id: string, nodeIds: string[]) =>
    request<unknown>(`/api/v1/certificates/${encodeURIComponent(id)}/sync`, {
      method: 'POST',
      body: JSON.stringify({ node_ids: nodeIds }),
    }),
  createDNSAccount: (input: { name: string; provider: string; credentials: Record<string, string> }) =>
    request<DNSAccount>('/api/v1/dns-accounts', { method: 'POST', body: JSON.stringify(input) }),
  createACMEAccount: (input: { name: string; email: string; directory_url: string; eab_kid: string; eab_hmac: string }) =>
    request<ACMEAccount>('/api/v1/acme-accounts', { method: 'POST', body: JSON.stringify(input) }),
}
