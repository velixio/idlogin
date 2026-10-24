package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// PG is the Postgres store.
type PG struct{ pool *pgxpool.Pool }

// NewPG wraps a pool.
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// Migrate applies the embedded migrations once each, under an advisory lock
// so concurrent starts do not race.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7234001)`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7234001)`)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS login_schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM login_schema_migrations WHERE version = $1)`, name).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO login_schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Allow implements Store.
func (p *PG) Allow(ctx context.Context, limits ...Limit) (bool, error) {
	keys := make([]string, 0, len(limits))
	for _, l := range limits {
		keys = append(keys, l.Key)
	}
	sort.Strings(keys) // lock in a stable order to avoid deadlocks
	ok := true
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		for _, k := range keys {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, k); err != nil {
				return err
			}
		}
		for _, l := range limits {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM login_rate_events WHERE key = $1 AND at > now() - make_interval(secs => $2)`,
				l.Key, l.Window.Seconds()).Scan(&n); err != nil {
				return err
			}
			if n >= l.Max {
				ok = false
				return nil
			}
		}
		for _, l := range limits {
			if _, err := tx.Exec(ctx, `INSERT INTO login_rate_events (key, expires_at) VALUES ($1, now() + make_interval(secs => $2))`,
				l.Key, l.Window.Seconds()); err != nil {
				return err
			}
		}
		return nil
	})
	return ok && err == nil, err
}

// PutCode implements Store.
func (p *PG) PutCode(ctx context.Context, c Code) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE login_codes SET consumed_at = now()
			WHERE brand = $1 AND purpose = $2 AND email = $3 AND consumed_at IS NULL`, c.Brand, c.Purpose, c.Email); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO login_codes (id, brand, purpose, email, user_id, code_hash, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, c.ID, c.Brand, c.Purpose, c.Email, c.UserID, c.Hash, c.ExpiresAt)
		return err
	})
}

// CheckCode implements Store. The attempt counter is incremented before the
// comparison in the same row lock, so parallel guesses cannot exceed the limit.
func (p *PG) CheckCode(ctx context.Context, id string, match func([]byte) bool, maxAttempts int) (CheckResult, *Code, error) {
	result := CodeUnknown
	var code Code
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var attempts int
		var consumed *time.Time
		var expired bool
		err := tx.QueryRow(ctx, `SELECT brand, purpose, email, user_id, code_hash, attempts, consumed_at, expires_at <= now(), expires_at
			FROM login_codes WHERE id = $1 FOR UPDATE`, id).Scan(
			&code.Brand, &code.Purpose, &code.Email, &code.UserID, &code.Hash, &attempts, &consumed, &expired, &code.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		code.ID = id
		switch {
		case consumed != nil:
			if attempts >= maxAttempts {
				result = CodeLocked
			}
			return nil
		case attempts >= maxAttempts:
			result = CodeLocked
			return nil
		case expired:
			result = CodeExpired
			return nil
		}
		attempts++
		if match(code.Hash) {
			result = CodeOK
			_, err = tx.Exec(ctx, `UPDATE login_codes SET attempts = $2, consumed_at = now() WHERE id = $1`, id, attempts)
			return err
		}
		result = CodeWrong
		if attempts >= maxAttempts {
			result = CodeLocked
		}
		_, err = tx.Exec(ctx, `UPDATE login_codes SET attempts = $2 WHERE id = $1`, id, attempts)
		return err
	})
	if err != nil {
		return CodeUnknown, nil, err
	}
	return result, &code, nil
}

// Cleanup implements Store.
func (p *PG) Cleanup(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `DELETE FROM login_rate_events WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `DELETE FROM login_codes WHERE expires_at < now() - interval '1 day'`)
	return err
}
