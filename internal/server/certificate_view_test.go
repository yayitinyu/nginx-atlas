package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

func TestCertificateViewUsesEmptyArraysForUnassignedCertificate(t *testing.T) {
	view := makeCertificateView(model.Certificate{
		ID:       "crt_upload",
		Domain:   "upload.example.com",
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
	}, time.Now())
	data, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dns_names", "requested_dns_names", "deployed_node_ids"} {
		values, ok := fields[key].([]any)
		if !ok || len(values) != 0 {
			t.Errorf("%s = %v; want an empty array", key, fields[key])
		}
	}
}
