package deploy

import "embed"

// Assets contains the installer served by the controller.
//
//go:embed install.sh
var Assets embed.FS
