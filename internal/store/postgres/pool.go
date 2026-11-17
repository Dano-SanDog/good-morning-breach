package postgres

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func OpenLocalPool(ctx context.Context, connectionString string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	if err := validateLocalHost(config.ConnConfig.Host); err != nil {
		return nil, err
	}
	if config.ConnConfig.Password != "" {
		return nil, errors.New("database passwords must not be supplied in the connection string or environment")
	}
	config.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("could not configure the local PostgreSQL connection")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func validateLocalHost(host string) error {
	if host == "" || strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("database host must be localhost, a loopback address, or a Unix socket")
}

func databaseContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 15*time.Second)
}
