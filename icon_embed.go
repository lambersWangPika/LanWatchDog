package main

import _ "embed"

//go:embed icon.ico
var iconData []byte

func init() {
	_ = iconData
}
