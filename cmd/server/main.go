package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/Dano-SanDog/good-morning-breach/internal/httpserver"
)

func main() {
	certFile := os.Getenv("GB_TLS_CERT_FILE")
	keyFile := os.Getenv("GB_TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		slog.Error("GB_TLS_CERT_FILE and GB_TLS_KEY_FILE are required")
		os.Exit(1)
	}

	server, err := httpserver.New()
	if err != nil {
		slog.Error("configure HTTPS server", "error", err)
		os.Exit(1)
	}

	slog.Info("starting local HTTPS server", "address", server.Addr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTPS server stopped", "error", err)
		os.Exit(1)
	}
}
