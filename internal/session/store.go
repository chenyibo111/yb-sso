package session

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists revoked Hydra login session IDs.
type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("missing SSO database URL")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sso_revoked_sessions (
		sid text PRIMARY KEY,
		revoked_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sso_verified_identities (
		subject text PRIMARY KEY,
		claims jsonb NOT NULL,
		updated_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Revoke(ctx context.Context, sid string) error {
	if sid == "" {
		return errors.New("missing session ID")
	}
	_, err := s.pool.Exec(ctx, "INSERT INTO sso_revoked_sessions (sid) VALUES ($1) ON CONFLICT (sid) DO NOTHING", sid)
	return err
}

func (s *Store) Revoked(ctx context.Context, sid string) (bool, error) {
	if sid == "" {
		return false, errors.New("missing session ID")
	}
	var revoked bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sso_revoked_sessions WHERE sid=$1)", sid).Scan(&revoked)
	return revoked, err
}

func (s *Store) Save(ctx context.Context, subject string, claims map[string]string) error {
	if subject == "" || len(claims) == 0 {
		return errors.New("missing verified identity")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO sso_verified_identities (subject, claims) VALUES ($1, $2)
		ON CONFLICT (subject) DO UPDATE SET claims = EXCLUDED.claims, updated_at = now()`, subject, claims)
	return err
}

func (s *Store) Load(ctx context.Context, subject string) (map[string]string, error) {
	if subject == "" {
		return nil, errors.New("missing subject")
	}
	var claims map[string]string
	err := s.pool.QueryRow(ctx, "SELECT claims FROM sso_verified_identities WHERE subject=$1", subject).Scan(&claims)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return claims, err
}
