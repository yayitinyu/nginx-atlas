package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestEventWebSocketUsesSingleUseTicketAndStreamsStateChanges(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("e", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(controller.Handler())
	defer httpServer.Close()

	request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/events/ticket", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("ticket returned %d", response.StatusCode)
	}
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(response.Body).Decode(&ticket); err != nil {
		t.Fatal(err)
	}
	if ticket.Ticket == "" {
		t.Fatal("ticket response was empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	websocketURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/api/v1/events"
	connection, _, err := websocket.Dial(ctx, websocketURL, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{httpServer.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if err := wsjson.Write(ctx, connection, eventAuthentication{Ticket: ticket.Ticket}); err != nil {
		t.Fatal(err)
	}

	var event stateEvent
	if err := wsjson.Read(ctx, connection, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "state.changed" || event.Revision != 0 {
		t.Fatalf("unexpected initial event: %+v", event)
	}
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_live"] = model.Node{ID: "node_live", Name: "Live", CreatedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, connection, &event); err != nil {
		t.Fatal(err)
	}
	if event.Revision != 1 {
		t.Fatalf("change revision = %d, want 1", event.Revision)
	}

	second, _, err := websocket.Dial(ctx, websocketURL, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{httpServer.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer second.CloseNow()
	if err := wsjson.Write(ctx, second, eventAuthentication{Ticket: ticket.Ticket}); err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, second, &event); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("reused ticket close status = %v, error = %v", websocket.CloseStatus(err), err)
	}
}

func TestPendingEventHandshakesDoNotConsumeAuthenticatedCapacity(t *testing.T) {
	controller := &Server{
		eventPending: make(chan struct{}, 16), eventClients: make(chan struct{}, 128),
		eventPendingIP: make(map[string]int),
	}
	if !controller.reservePendingEvent("203.0.113.7") || !controller.reservePendingEvent("203.0.113.7") {
		t.Fatal("expected two pending handshakes per client")
	}
	if controller.reservePendingEvent("203.0.113.7") {
		t.Fatal("third unauthenticated handshake for one client was accepted")
	}
	if len(controller.eventClients) != 0 {
		t.Fatal("unauthenticated handshakes consumed authenticated client capacity")
	}
	controller.releasePendingEvent("203.0.113.7")
	controller.releasePendingEvent("203.0.113.7")
}
