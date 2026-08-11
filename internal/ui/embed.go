package ui

import "embed"

// Files contains the production frontend built by web/package.json.
//
//go:embed all:dist
var Files embed.FS
