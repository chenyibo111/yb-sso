package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists shared browser sessions, revocations, and verified identities.
type Store struct {
	pool *pgxpool.Pool
}

const (
	absoluteSessionTimeout = 8 * time.Hour
	idleSessionTimeout     = 30 * time.Minute
)

func sessionWithinDeadline(startedAt, lastActivityAt, now time.Time) bool {
	return now.Before(startedAt.Add(absoluteSessionTimeout)) && now.Before(lastActivityAt.Add(idleSessionTimeout))
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
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sso_browser_sessions (
		sid text PRIMARY KEY,
		started_at timestamptz NOT NULL DEFAULT now(),
		last_activity_at timestamptz NOT NULL DEFAULT now()
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

// Active checks both deadlines. Only an explicit user activity report locks
// the session row and moves the idle deadline; status checks do not extend it.
func (s *Store) Active(ctx context.Context, sid string, activity bool) (bool, error) {
	if sid == "" {
		return false, errors.New("missing session ID")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO sso_browser_sessions (sid) VALUES ($1) ON CONFLICT DO NOTHING`, sid); err != nil {
		return false, err
	}
	var startedAt, lastActivityAt, now time.Time
	var revoked bool
	query := `SELECT started_at, last_activity_at FROM sso_browser_sessions WHERE sid=$1`
	if activity {
		query += ` FOR UPDATE`
	}
	if err = tx.QueryRow(ctx, query, sid).Scan(&startedAt, &lastActivityAt); err != nil {
		return false, err
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sso_revoked_sessions WHERE sid=$1), clock_timestamp()`, sid).Scan(&revoked, &now); err != nil {
		return false, err
	}
	active := !revoked && sessionWithinDeadline(startedAt, lastActivityAt, now)
	if active && activity {
		if _, err = tx.Exec(ctx, `UPDATE sso_browser_sessions SET last_activity_at=$2 WHERE sid=$1`, sid, now); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return active, nil
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
