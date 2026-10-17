package lnta

import "embed"

// EmbeddedPacks contains the default instruction packs embedded at build time
// from the packs/ directory.
//
//go:embed packs/*.md
var EmbeddedPacks embed.FS
