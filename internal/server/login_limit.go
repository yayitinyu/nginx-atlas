package server

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	loginRateWindow             = time.Minute
	loginAttemptRetention       = 10 * time.Minute
	maxLoginAttemptsPerClient   = 6
	maxTrackedLoginClients      = 4096
	maxConcurrentLogins         = 8
	maxConcurrentPasswordChecks = 2
	passwordAttemptBurst        = 8
	passwordAttemptRefill       = time.Second
)

type loginAttemptWindow struct {
	StartedAt    time.Time
	LastSeenAt   time.Time
	BlockedUntil time.Time
	Attempts     int
}

func (s *Server) reserveLoginAttempt(clientIP string) (bool, time.Duration) {
	clientIP = normalizeLoginClientKey(clientIP)
	now := s.currentLoginTime()
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginCleanupAt.IsZero() || now.Sub(s.loginCleanupAt) >= time.Minute {
		for key, attempt := range s.loginAttempts {
			if now.Sub(attempt.LastSeenAt) >= loginAttemptRetention {
				delete(s.loginAttempts, key)
			}
		}
		s.loginCleanupAt = now
	}
	if _, exists := s.loginAttempts[clientIP]; !exists && len(s.loginAttempts) >= maxTrackedLoginClients {
		var oldestKey string
		var oldestTime time.Time
		for key, attempt := range s.loginAttempts {
			if oldestKey == "" || attempt.LastSeenAt.Before(oldestTime) {
				oldestKey, oldestTime = key, attempt.LastSeenAt
			}
		}
		delete(s.loginAttempts, oldestKey)
	}

	client := normalizeLoginWindow(s.loginAttempts[clientIP], now)
	if retry := loginRetryAfter(client, now); retry > 0 {
		return false, retry
	}
	if client.Attempts >= maxLoginAttemptsPerClient {
		client.BlockedUntil = now.Add(loginRateWindow)
		client.LastSeenAt = now
		s.loginAttempts[clientIP] = client
		return false, loginRateWindow
	}
	client.Attempts++
	client.LastSeenAt = now
	s.loginAttempts[clientIP] = client
	return true, 0
}

func (s *Server) clearLoginAttempt(clientIP string) {
	clientIP = normalizeLoginClientKey(clientIP)
	s.loginMu.Lock()
	delete(s.loginAttempts, clientIP)
	s.loginMu.Unlock()
}

func (s *Server) reservePasswordAttempt() (bool, time.Duration) {
	now := s.currentLoginTime()
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.passwordTokenAt.IsZero() {
		s.passwordTokens = passwordAttemptBurst
		s.passwordTokenAt = now
	} else if now.After(s.passwordTokenAt) {
		refill := float64(now.Sub(s.passwordTokenAt)) / float64(passwordAttemptRefill)
		s.passwordTokens = min(float64(passwordAttemptBurst), s.passwordTokens+refill)
		s.passwordTokenAt = now
	}
	if s.passwordTokens >= 1 {
		s.passwordTokens--
		return true, 0
	}
	missing := 1 - s.passwordTokens
	retryAfter := time.Duration(missing * float64(passwordAttemptRefill))
	if retryAfter < time.Millisecond {
		retryAfter = time.Millisecond
	}
	return false, retryAfter
}

func normalizeLoginClientKey(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		if clientIP == "" {
			return "unknown"
		}
		return clientIP
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr.WithZone(""), 64).Masked().String()
	}
	return addr.String()
}

func (s *Server) currentLoginTime() time.Time {
	if s.loginNow != nil {
		return s.loginNow()
	}
	return time.Now()
}

func normalizeLoginWindow(attempt loginAttemptWindow, now time.Time) loginAttemptWindow {
	if attempt.StartedAt.IsZero() || now.Sub(attempt.StartedAt) >= loginRateWindow {
		return loginAttemptWindow{StartedAt: now, LastSeenAt: now}
	}
	return attempt
}

func loginRetryAfter(attempt loginAttemptWindow, now time.Time) time.Duration {
	if attempt.BlockedUntil.After(now) {
		return attempt.BlockedUntil.Sub(now)
	}
	return 0
}

func writeLoginRateLimit(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后重试", "login_rate_limited", nil)
}
