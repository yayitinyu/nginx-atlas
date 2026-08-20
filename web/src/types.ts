export type NodeStatus = 'pending' | 'online' | 'offline' | 'revoked'
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed'
export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'none'

export interface CertificateMeta {
  domain: string
  path: string
  fingerprint_sha256: string
  issuer: string
  not_after: string
  dns_names?: string[]
  key_matches: boolean
  error?: string
}

export interface NginxSiteMeta {
  domain: string
  config_path?: string
  upstream_host?: string
  upstream_port?: number
  tls: boolean
  certificate_path?: string
  managed_by_atlas: boolean
}

export interface NodeRecord {
  id: string
  name: string
  status: NodeStatus
  hostname?: string
  ip_addresses?: string[]
  os?: string
  os_name?: string
  os_version?: string
  arch?: string
  package_manager?: string
  controller_installed?: boolean
  nginx_version?: string
  nginx_healthy: boolean
  agent_version?: string
  last_seen_at?: string
  created_at: string
  certificates?: CertificateMeta[]
  nginx_sites?: NginxSiteMeta[]
  last_error?: string
  running_job_id?: string
  status_history?: Array<{ status: NodeStatus; observed_at: string }>
}

export interface DomainRecord {
  id: string
  name: string
  node_id: string
  node_name: string
  node_status: NodeStatus
  upstream_host: string
  upstream_port: number
  certificate_id?: string
  certificate_mode: 'local' | 'upload' | 'acme' | ''
  certificate_issuer?: string
  certificate_expiry?: string
  certificate_status: CertificateStatus
  acme_account_id?: string
  dns_account_id?: string
  auto_renew: boolean
  renew_before_days: number
  sync_node_ids?: string[]
  enabled: boolean
  observed_only?: boolean
  taken_over?: boolean
  config_path?: string
  cloudflare_enabled: boolean
  cloudflare_dns_account_id?: string
  cloudflare_proxied: boolean
  cloudflare_record_type?: string
  cloudflare_record_content?: string
  nginx_websocket: boolean
  nginx_http2: boolean
  nginx_gzip: boolean
  last_job_id?: string
  last_error?: string
  job_status?: JobStatus
  created_at: string
  updated_at: string
}

export interface CertificateRecord {
  id: string
  domain: string
  source: 'local' | 'upload' | 'acme'
  fingerprint_sha256: string
  issuer: string
  serial_number: string
  not_before: string
  not_after: string
  dns_names: string[]
  requested_dns_names: string[]
  auto_renew: boolean
  renew_before_days: number
  acme_account_id?: string
  dns_account_id?: string
  issuer_node_id?: string
  deployed_node_ids: string[]
  days_remaining: number
  status: Exclude<CertificateStatus, 'none'>
  created_at: string
  updated_at: string
}

export interface AuditEvent {
  id: string
  level: 'success' | 'info' | 'warning' | 'error'
  action: string
  message: string
  node_id?: string
  domain_id?: string
  job_id?: string
  created_at: string
}

export interface JobRecord {
  id: string
  node_id: string
  domain_id?: string
  type: string
  status: JobStatus
  attempts: number
  max_attempts: number
  error?: string
  created_at: string
  started_at?: string
  finished_at?: string
  retry_of_id?: string
  retry_job_id?: string
}

export interface DashboardData {
  nodes: NodeRecord[]
  domains: DomainRecord[]
  certificates: CertificateRecord[]
  audit: AuditEvent[]
  jobs: JobRecord[]
  pending_job_count: number
  settings: ControllerSettings
  server_time: string
}

export interface ControllerSettings {
  node_poll_seconds: number
  turnstile_enabled: boolean
  turnstile_site_key: string
  turnstile_secret_configured: boolean
  panel_allowed_cidrs: string[]
  request_ip?: string
}

export interface ControllerSettingsInput {
  node_poll_seconds?: number
  turnstile_enabled?: boolean
  turnstile_site_key?: string
  turnstile_secret?: string
  panel_allowed_cidrs?: string[]
}

export interface LoginConfig {
  turnstile_enabled: boolean
  turnstile_site_key: string
}

export interface ManagementCommands {
  uninstall_node: string
  uninstall_controller: string
}

export interface DNSAccount {
  id: string
  name: string
  provider: string
  credential_keys: string[]
  created_at: string
  updated_at: string
}

export interface ACMEAccount {
  id: string
  name: string
  email: string
  directory_url: string
  has_eab: boolean
  created_at: string
  updated_at: string
}

export interface CreateDomainInput {
  domain: string
  node_id: string
  upstream_host: string
  upstream_port: number
  certificate_mode: 'none' | 'local' | 'upload' | 'acme'
  certificate_id?: string
  acme_account_id?: string
  dns_account_id?: string
  auto_renew: boolean
  renew_before_days: number
  sync_node_ids: string[]
  cloudflare_enabled?: boolean
  cloudflare_dns_account_id?: string
  cloudflare_proxied?: boolean
  cloudflare_record_type?: 'A' | 'AAAA' | 'CNAME'
  cloudflare_record_content?: string
  nginx_websocket?: boolean
  nginx_http2?: boolean
  nginx_gzip?: boolean
}

export interface CertificateAutomationInput {
  domain: string
  node_id: string
  auto_renew: boolean
  renew_before_days: number
  acme_account_id?: string
  dns_account_id?: string
  sync_node_ids: string[]
  dns_names: string[]
}

export interface ReleaseInfo {
  current_version: string
  latest_version: string
  update_available: boolean
  published_at: string
  html_url: string
  repository: string
}

export interface UninstallCommand {
  command: string
  preserves_nginx: boolean
  controller_installed: boolean
}

export interface BulkNodeUpdateResult {
  queued: number
  skipped: number
  jobs: JobRecord[]
  version: string
}

export interface EnrollmentResponse {
  id: string
  name: string
  token: string
  expires_at: string
  command: string
}
