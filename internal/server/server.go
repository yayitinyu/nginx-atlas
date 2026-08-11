package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/deploy"
	"github.com/yayitinyu/nginx-atlas/internal/id"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
	"github.com/yayitinyu/nginx-atlas/internal/ui"
)

const maxJSONBody = 2 << 20

type Config struct {
	Address      string
	PublicURL    string
	AdminToken   string
	PollAfter    time.Duration
	OfflineAfter time.Duration
	Demo         bool
}

type Server struct {
	config         Config
	store          *store.Store
	box            *securebox.Box
	logger         *slog.Logger
	adminTokenHash [32]byte
	handler        http.Handler
}

func New(config Config, stateStore *store.Store, box *securebox.Box, logger *slog.Logger) (*Server, error) {
	if stateStore == nil || box == nil {
		return nil, errors.New("state store and secret box are required")
	}
	if len(config.AdminToken) < 24 {
		return nil, errors.New("admin token must contain at least 24 characters")
	}
	if config.Address == "" {
		config.Address = "127.0.0.1:9090"
	}
	config.PublicURL = strings.TrimRight(config.PublicURL, "/")
	if config.PollAfter < 3*time.Second {
		config.PollAfter = 10 * time.Second
	}
	if config.Demo && config.OfflineAfter == 0 {
		config.OfflineAfter = 365 * 24 * time.Hour
	} else if config.OfflineAfter < 15*time.Second {
		config.OfflineAfter = 45 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{config: config, store: stateStore, box: box, logger: logger, adminTokenHash: sha256.Sum256([]byte(config.AdminToken))}
	if config.Demo {
		if err := s.seedDemo(); err != nil {
			return nil, err
		}
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) ListenAndServe(ctx context.Context) error {
	httpServer := &http.Server{
		Addr: s.config.Address, Handler: s.handler,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second,
	}
	go s.runScheduler(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	s.logger.Info("controller listening", "address", s.config.Address)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /install.sh", s.handleInstaller)
	mux.HandleFunc("POST /api/v1/agent/enroll", s.handleAgentEnroll)
	mux.Handle("POST /api/v1/agent/poll", s.nodeAuth(http.HandlerFunc(s.handleAgentPoll)))
	mux.Handle("POST /api/v1/agent/jobs/{id}/result", s.nodeAuth(http.HandlerFunc(s.handleAgentJobResult)))

	mux.Handle("GET /api/v1/session", s.adminAuth(http.HandlerFunc(s.handleSession)))
	mux.Handle("GET /api/v1/dashboard", s.adminAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /api/v1/nodes", s.adminAuth(http.HandlerFunc(s.handleNodes)))
	mux.Handle("POST /api/v1/enrollments", s.adminAuth(http.HandlerFunc(s.handleCreateEnrollment)))
	mux.Handle("DELETE /api/v1/nodes/{id}", s.adminAuth(http.HandlerFunc(s.handleRevokeNode)))
	mux.Handle("GET /api/v1/domains", s.adminAuth(http.HandlerFunc(s.handleDomains)))
	mux.Handle("POST /api/v1/domains", s.adminAuth(http.HandlerFunc(s.handleCreateDomain)))
	mux.Handle("DELETE /api/v1/domains/{id}", s.adminAuth(http.HandlerFunc(s.handleDeleteDomain)))
	mux.Handle("GET /api/v1/certificates", s.adminAuth(http.HandlerFunc(s.handleCertificates)))
	mux.Handle("POST /api/v1/certificates/upload", s.adminAuth(http.HandlerFunc(s.handleUploadCertificate)))
	mux.Handle("POST /api/v1/certificates/{id}/renew", s.adminAuth(http.HandlerFunc(s.handleRenewCertificate)))
	mux.Handle("POST /api/v1/certificates/{id}/sync", s.adminAuth(http.HandlerFunc(s.handleSyncCertificate)))
	mux.Handle("GET /api/v1/dns-accounts", s.adminAuth(http.HandlerFunc(s.handleDNSAccounts)))
	mux.Handle("POST /api/v1/dns-accounts", s.adminAuth(http.HandlerFunc(s.handleCreateDNSAccount)))
	mux.Handle("PUT /api/v1/dns-accounts/{id}", s.adminAuth(http.HandlerFunc(s.handleUpdateDNSAccount)))
	mux.Handle("GET /api/v1/acme-accounts", s.adminAuth(http.HandlerFunc(s.handleACMEAccounts)))
	mux.Handle("POST /api/v1/acme-accounts", s.adminAuth(http.HandlerFunc(s.handleCreateACMEAccount)))
	mux.Handle("GET /api/v1/audit", s.adminAuth(http.HandlerFunc(s.handleAudit)))
	mux.Handle("/", s.frontendHandler())
	return s.securityHeaders(s.requestLog(mux))
}

func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		hash := sha256.Sum256([]byte(value))
		if value == "" || subtle.ConstantTimeCompare(hash[:], s.adminTokenHash[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "管理员令牌无效", "unauthorized", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type nodeContextKey struct{}

func (s *Server) nodeAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "AtlasNode"))
		parts := strings.SplitN(value, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			writeError(w, http.StatusUnauthorized, "节点凭据无效", "node_unauthorized", nil)
			return
		}
		state := s.store.Snapshot()
		node, ok := state.Nodes[parts[0]]
		if !ok || node.Status == model.NodeRevoked {
			writeError(w, http.StatusUnauthorized, "节点不存在或已撤销", "node_unauthorized", nil)
			return
		}
		hash := sha256.Sum256([]byte(parts[1]))
		expected, err := decodeHash(node.SecretHash)
		if err != nil || subtle.ConstantTimeCompare(hash[:], expected) != 1 {
			writeError(w, http.StatusUnauthorized, "节点凭据无效", "node_unauthorized", nil)
			return
		}
		ctx := context.WithValue(r.Context(), nodeContextKey{}, node.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/agent/poll" {
			s.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
		}
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) frontendHandler() http.Handler {
	dist, err := fs.Sub(ui.Files, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "接口不存在", "not_found", nil)
			return
		}
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "." || clean == "" {
			clean = "index.html"
		}
		if file, err := dist.Open(clean); err == nil {
			_ = file.Close()
			if contentType := mime.TypeByExtension(path.Ext(clean)); contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			files.ServeHTTP(w, r)
			return
		}
		index, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.Error(w, "frontend unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC()})
}

func (s *Server) handleInstaller(w http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(deploy.Assets, "install.sh")
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleSession(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "product": "Nginx Atlas"})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式无效", "invalid_json", map[string]string{"body": err.Error()})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "请求只能包含一个 JSON 对象", "invalid_json", nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message, code string, details map[string]string) {
	writeJSON(w, status, protocol.APIError{Error: message, Code: code, Details: details})
}

func nodeIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(nodeContextKey{}).(string)
	return value
}

func (s *Server) addAudit(state *model.State, level, action, message string, references ...string) {
	eventID, err := id.New("evt")
	if err != nil {
		eventID = fmt.Sprintf("evt_%d", time.Now().UTC().UnixNano())
	}
	event := model.AuditEvent{ID: eventID, Level: level, Action: action, Message: message, CreatedAt: time.Now().UTC()}
	if len(references) > 0 {
		event.NodeID = references[0]
	}
	if len(references) > 1 {
		event.DomainID = references[1]
	}
	if len(references) > 2 {
		event.JobID = references[2]
	}
	store.AppendAudit(state, event)
}

func (s *Server) seedDemo() error { return seedDemoState(s.store) }

func (s *Server) publicURL(r *http.Request) string {
	if s.config.PublicURL != "" {
		return s.config.PublicURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func wrapStoreError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusInternalServerError, "保存状态失败", "state_error", map[string]string{"reason": err.Error()})
}

func (s *Server) mustSeal(purpose string, data []byte) (string, error) {
	value, err := s.box.Seal(purpose, data)
	if err != nil {
		return "", fmt.Errorf("encrypt secret: %w", err)
	}
	return value, nil
}
