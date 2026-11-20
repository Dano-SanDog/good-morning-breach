package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/applog"
	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
	"golang.org/x/term"
)

const defaultDatabaseURL = "host=127.0.0.1 dbname=good_morning_breach sslmode=disable"

func main() {
	if err := applog.Configure(); err != nil {
		fmt.Fprintf(os.Stderr, "configure application logs: %v\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		slog.Error("administrator setup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("administrator setup must run from an interactive terminal")
	}

	fmt.Fprint(os.Stdout, "Administrator email: ")
	var email string
	if _, err := fmt.Fscanln(os.Stdin, &email); err != nil {
		return errors.New("read administrator email")
	}
	if len(email) > 254 {
		return errors.New("administrator email is too long")
	}
	email = strings.TrimSpace(email)

	fmt.Fprint(os.Stdout, "Administrator password (input hidden): ")
	passwordBytes, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return errors.New("read administrator password")
	}
	defer func() {
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	databaseURL := os.Getenv("GB_MIGRATION_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}
	pool, err := postgres.OpenLocalPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	store := postgres.NewIdentityStore(pool)
	service, err := identity.NewService(store, egress.NewHTTPClient())
	if err != nil {
		return err
	}
	if err := service.CreateInitialAdmin(ctx, email, string(passwordBytes)); err != nil {
		return err
	}
	fmt.Println("Administrator created. Sign in with this email address and password.")
	return nil
}
