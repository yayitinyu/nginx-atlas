package model

import (
	"encoding/json"
	"time"
)

type NodeStatus string

const (
	NodePending NodeStatus = "pending"
	NodeOnline  NodeStatus = "online"
	NodeOffline NodeStatus = "offline"
	NodeRevoked NodeStatus = "revoked"
)

type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
)

type CertificateSource string

const (
	CertificateLocal  CertificateSource = "local"
	CertificateUpload CertificateSource = "upload"
	CertificateACME   CertificateSource = "acme"
)

type Node struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	SecretHash   string            `json:"secret_hash,omitempty"`
	Status       NodeStatus        `json:"status"`
	Hostname     string            `json:"hostname,omitempty"`
	IPAddresses  []string          `json:"ip_addresses,omitempty"`
	OS           string            `json:"os,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	NginxVersion string            `json:"nginx_version,omitempty"`
	NginxHealthy bool              `json:"nginx_healthy"`
	AgentVersion string            `json:"agent_version,omitempty"`
	LastSeenAt   *time.Time        `json:"last_seen_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	RevokedAt    *time.Time        `json:"revoked_at,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Certificates []CertificateMeta `json:"certificates,omitempty"`
	LastError    string            `json:"last_error,omitempty"`
	RunningJobID string            `json:"running_job_id,omitempty"`
}

type Enrollment struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"token_hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type Domain struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	NodeID          string            `json:"node_id"`
	UpstreamHost    string            `json:"upstream_host"`
	UpstreamPort    int               `json:"upstream_port"`
	CertificateID   string            `json:"certificate_id,omitempty"`
	CertificateMode CertificateSource `json:"certificate_mode"`
	ACMEAccountID   string            `json:"acme_account_id,omitempty"`
	DNSAccountID    string            `json:"dns_account_id,omitempty"`
	AutoRenew       bool              `json:"auto_renew"`
	RenewBeforeDays int               `json:"renew_before_days"`
	SyncNodeIDs     []string          `json:"sync_node_ids,omitempty"`
	Enabled         bool              `json:"enabled"`
	LastJobID       string            `json:"last_job_id,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type Certificate struct {
	ID                   string            `json:"id"`
	Domain               string            `json:"domain"`
	Source               CertificateSource `json:"source"`
	FullchainCiphertext  string            `json:"fullchain_ciphertext"`
	PrivateKeyCiphertext string            `json:"private_key_ciphertext"`
	FingerprintSHA256    string            `json:"fingerprint_sha256"`
	Issuer               string            `json:"issuer"`
	SerialNumber         string            `json:"serial_number"`
	NotBefore            time.Time         `json:"not_before"`
	NotAfter             time.Time         `json:"not_after"`
	DNSNames             []string          `json:"dns_names,omitempty"`
	AutoRenew            bool              `json:"auto_renew"`
	ACMEAccountID        string            `json:"acme_account_id,omitempty"`
	DNSAccountID         string            `json:"dns_account_id,omitempty"`
	IssuerNodeID         string            `json:"issuer_node_id,omitempty"`
	DeployedNodeIDs      []string          `json:"deployed_node_ids,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

type CertificateMeta struct {
	Domain            string    `json:"domain"`
	Path              string    `json:"path"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Issuer            string    `json:"issuer"`
	NotAfter          time.Time `json:"not_after"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	KeyMatches        bool      `json:"key_matches"`
	Error             string    `json:"error,omitempty"`
}

type DNSAccount struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Provider              string    `json:"provider"`
	CredentialsCiphertext string    `json:"credentials_ciphertext"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type ACMEAccount struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Email             string    `json:"email"`
	DirectoryURL      string    `json:"directory_url"`
	EABKID            string    `json:"eab_kid,omitempty"`
	EABHMACCiphertext string    `json:"eab_hmac_ciphertext,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Job struct {
	ID          string          `json:"id"`
	NodeID      string          `json:"node_id"`
	DomainID    string          `json:"domain_id,omitempty"`
	Type        string          `json:"type"`
	Status      JobStatus       `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	Error       string          `json:"error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
}

type AuditEvent struct {
	ID        string         `json:"id"`
	Level     string         `json:"level"`
	Action    string         `json:"action"`
	Message   string         `json:"message"`
	NodeID    string         `json:"node_id,omitempty"`
	DomainID  string         `json:"domain_id,omitempty"`
	JobID     string         `json:"job_id,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type State struct {
	Version      int                    `json:"version"`
	Nodes        map[string]Node        `json:"nodes"`
	Enrollments  map[string]Enrollment  `json:"enrollments"`
	Domains      map[string]Domain      `json:"domains"`
	Certificates map[string]Certificate `json:"certificates"`
	DNSAccounts  map[string]DNSAccount  `json:"dns_accounts"`
	ACMEAccounts map[string]ACMEAccount `json:"acme_accounts"`
	Jobs         map[string]Job         `json:"jobs"`
	Audit        []AuditEvent           `json:"audit"`
}

func NewState() State {
	return State{
		Version:      1,
		Nodes:        make(map[string]Node),
		Enrollments:  make(map[string]Enrollment),
		Domains:      make(map[string]Domain),
		Certificates: make(map[string]Certificate),
		DNSAccounts:  make(map[string]DNSAccount),
		ACMEAccounts: make(map[string]ACMEAccount),
		Jobs:         make(map[string]Job),
		Audit:        make([]AuditEvent, 0),
	}
}
