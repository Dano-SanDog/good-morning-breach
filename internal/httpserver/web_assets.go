package httpserver

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var clientAssets embed.FS

func EmbeddedAssets() (fs.FS, error) {
	return fs.Sub(clientAssets, "static/build")
}
