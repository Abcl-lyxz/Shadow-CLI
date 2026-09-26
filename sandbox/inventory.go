package inventory

import _ "embed"

// Manifest is the audited command list bundled with the CLI.
//
//go:embed tools.txt
var Manifest string
