package deploy

import (
	"strings"
	"testing"
)

func TestInstallerProtectsLocalControlPlaneAndWebSocketProxy(t *testing.T) {
	data, err := Assets.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`CONTROLLER_ADDR="127.0.0.1:909"`,
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"location = /api/v1/events",
		`proxy_set_header Upgrade \$http_upgrade;`,
		"Authorization: AtlasLocal",
		"ATLAS_PROXY_TOKEN=",
		"include $PROXY_HEADER_CONFIG;",
		"ATLAS_PROXY_HEADER_INCLUDE=",
		"--token-stdin",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("installer is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`return 308 https://\$host\$request_uri;`,
		`Authorization: AtlasAdmin $ADMIN_TOKEN`,
		`--token $ENROLLMENT_TOKEN`,
		`--token TOKEN`,
		`--token)`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("installer still contains unsafe pattern %q", forbidden)
		}
	}
	if !strings.Contains(script, `if [[ "$server_url" == "http://127.0.0.1:9090" ]]`) || !strings.Contains(script, `server_url="$CONTROLLER_URL"`) {
		t.Fatal("legacy local uninstall can still send node credentials to the unprotected 9090 endpoint")
	}
	if strings.Count(script, "preserve_takeover_backups") < 3 {
		t.Fatal("one uninstall mode can still purge takeover restoration backups")
	}
	if !strings.Contains(script, `proxy_pass http://127\.0\.0\.1:(909|9090)`) {
		t.Fatal("agent-managed panel detection does not bind proxy credentials to the local controller upstream")
	}
}
