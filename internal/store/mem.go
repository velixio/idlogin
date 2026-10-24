package store

import (
	"context"
	"sync"
	"time"
)

// Mem is an in-memory Store for tests and single-process development.
type Mem struct {
	mu     sync.Mutex
	Now    func() time.Time
	codes  map[string]*memCode
	events map[string][]time.Time
}

type memCode struct {
	Code
	attempts int
	consumed bool
}

// NewMem returns an empty memory store.
func NewMem(now func() time.Time) *Mem {
	if now == nil {
		now = time.Now
	}
	return &Mem{Now: now, codes: map[string]*memCode{}, events: map[string][]time.Time{}}
}

// Allow implements Store.
func (m *Mem) Allow(_ context.Context, limits ...Limit) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	for _, l := range limits {
		n := 0
		for _, t := range m.events[l.Key] {
			if t.After(now.Add(-l.Window)) {
				n++
			}
		}
		if n >= l.Max {
			return false, nil
		}
	}
	for _, l := range limits {
		m.events[l.Key] = append(m.events[l.Key], now)
	}
	return true, nil
}

// PutCode implements Store.
func (m *Mem) PutCode(_ context.Context, c Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.codes {
		if o.Brand == c.Brand && o.Purpose == c.Purpose && o.Email == c.Email {
			o.consumed = true
		}
	}
	m.codes[c.ID] = &memCode{Code: c}
	return nil
}

// CheckCode implements Store.
func (m *Mem) CheckCode(_ context.Context, id string, match func([]byte) bool, maxAttempts int) (CheckResult, *Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[id]
	if !ok {
		return CodeUnknown, nil, nil
	}
	cp := c.Code
	switch {
	case c.attempts >= maxAttempts:
		return CodeLocked, &cp, nil
	case c.consumed:
		return CodeUnknown, &cp, nil
	case !m.Now().Before(c.ExpiresAt):
		return CodeExpired, &cp, nil
	}
	c.attempts++
	if match(c.Hash) {
		c.consumed = true
		return CodeOK, &cp, nil
	}
	if c.attempts >= maxAttempts {
		return CodeLocked, &cp, nil
	}
	return CodeWrong, &cp, nil
}

// Cleanup implements Store.
func (m *Mem) Cleanup(context.Context) error { return nil }
