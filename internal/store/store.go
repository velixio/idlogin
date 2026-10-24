// Package store keeps the state that must not live in a cookie because it
// must not be replayable: one-time codes with their attempt counters, and the
// event windows behind rate limits. Postgres in production (PG), memory in
// tests (Mem).
package store

import (
	"context"
	"time"
)

// Code is a one-time code. Only an HMAC of the code is stored.
type Code struct {
	ID        string
	Brand     string
	Purpose   string // signin, signup, reset, verify
	Email     string
	UserID    string
	Hash      []byte
	ExpiresAt time.Time
}

// CheckResult is the outcome of a code attempt.
type CheckResult int

const (
	// CodeOK means the code matched and is now used up.
	CodeOK CheckResult = iota
	// CodeWrong means it did not match; more attempts remain.
	CodeWrong
	// CodeLocked means too many wrong attempts (this one included); the code is dead.
	CodeLocked
	// CodeExpired means the code is past its lifetime.
	CodeExpired
	// CodeUnknown means no usable code (never issued, used, or replaced).
	CodeUnknown
)

// Limit is one rate-limit window: at most Max events per Window for Key.
type Limit struct {
	Key    string
	Max    int
	Window time.Duration
}

// Store is the server-side state.
type Store interface {
	// Allow records one event for every limit if all of them are below their
	// maximum, atomically; otherwise it records nothing and returns false.
	Allow(ctx context.Context, limits ...Limit) (bool, error)
	// PutCode stores a new code and retires older live codes for the same
	// brand, purpose and email.
	PutCode(ctx context.Context, c Code) error
	// CheckCode spends one attempt on the code. match tells whether the
	// candidate's hash equals the stored one (compared in constant time).
	CheckCode(ctx context.Context, id string, match func(stored []byte) bool, maxAttempts int) (CheckResult, *Code, error)
	// Cleanup removes expired rows.
	Cleanup(ctx context.Context) error
}
