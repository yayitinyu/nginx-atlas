package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/yayitinyu/nginx-atlas/internal/id"
)

const (
	eventTicketTTL = 30 * time.Second
	eventWriteTTL  = 5 * time.Second
)

type stateEvent struct {
	Type     string `json:"type"`
	Revision uint64 `json:"revision"`
}

type eventAuthentication struct {
	Ticket string `json:"ticket"`
}

func (s *Server) handleEventTicket(w http.ResponseWriter, _ *http.Request) {
	ticket, expiresAt, err := s.createEventTicket()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法创建实时连接凭据", "event_ticket_failed", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expires_at": expiresAt})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	clientIP := s.clientIP(r)
	if !s.reservePendingEvent(clientIP) {
		writeError(w, http.StatusTooManyRequests, "实时连接握手过于频繁", "event_handshake_capacity", nil)
		return
	}
	pending := true
	defer func() {
		if pending {
			s.releasePendingEvent(clientIP)
		}
	}()
	connection, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(256)
	authenticationContext, cancelAuthentication := context.WithTimeout(context.Background(), eventWriteTTL)
	var authentication eventAuthentication
	err = wsjson.Read(authenticationContext, connection, &authentication)
	cancelAuthentication()
	if err != nil || !s.consumeEventTicket(authentication.Ticket) {
		_ = connection.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}
	s.releasePendingEvent(clientIP)
	pending = false
	select {
	case s.eventClients <- struct{}{}:
		defer func() { <-s.eventClients }()
	default:
		_ = connection.Close(websocket.StatusTryAgainLater, "event capacity reached")
		return
	}

	revision, changes, unsubscribe := s.store.Subscribe()
	defer unsubscribe()
	connection.SetReadLimit(1024)
	connectionContext := connection.CloseRead(context.Background())
	if err := writeStateEvent(connectionContext, connection, revision); err != nil {
		return
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-connectionContext.Done():
			return
		case revision = <-changes:
			if err := writeStateEvent(connectionContext, connection, revision); err != nil {
				return
			}
		case <-ping.C:
			ctx, cancel := context.WithTimeout(connectionContext, eventWriteTTL)
			err := connection.Ping(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) reservePendingEvent(clientIP string) bool {
	select {
	case s.eventPending <- struct{}{}:
	default:
		return false
	}
	s.eventPendingMu.Lock()
	defer s.eventPendingMu.Unlock()
	if s.eventPendingIP[clientIP] >= 2 {
		<-s.eventPending
		return false
	}
	s.eventPendingIP[clientIP]++
	return true
}

func (s *Server) releasePendingEvent(clientIP string) {
	s.eventPendingMu.Lock()
	if s.eventPendingIP[clientIP] <= 1 {
		delete(s.eventPendingIP, clientIP)
	} else {
		s.eventPendingIP[clientIP]--
	}
	s.eventPendingMu.Unlock()
	<-s.eventPending
}

func writeStateEvent(parent context.Context, connection *websocket.Conn, revision uint64) error {
	ctx, cancel := context.WithTimeout(parent, eventWriteTTL)
	defer cancel()
	return wsjson.Write(ctx, connection, stateEvent{Type: "state.changed", Revision: revision})
}

func (s *Server) createEventTicket() (string, time.Time, error) {
	ticket, err := id.Token(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(eventTicketTTL)
	hash := sha256.Sum256([]byte(ticket))
	s.eventTicketMu.Lock()
	for key, expiry := range s.eventTickets {
		if !time.Now().Before(expiry) {
			delete(s.eventTickets, key)
		}
	}
	s.eventTickets[hash] = expiresAt
	s.eventTicketMu.Unlock()
	return ticket, expiresAt, nil
}

func (s *Server) consumeEventTicket(ticket string) bool {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" || len(ticket) > 128 {
		return false
	}
	hash := sha256.Sum256([]byte(ticket))
	now := time.Now()
	s.eventTicketMu.Lock()
	expiresAt, ok := s.eventTickets[hash]
	delete(s.eventTickets, hash)
	s.eventTicketMu.Unlock()
	return ok && now.Before(expiresAt)
}
