package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// stores returns the memory store and, when LOGIN_TEST_DATABASE_URL is set,
// the Postgres store (e.g. the local idlogin database).
func stores(t *testing.T) map[string]Store {
	out := map[string]Store{"mem": NewMem(nil)}
	if dsn := os.Getenv("LOGIN_TEST_DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
		out["pg"] = NewPG(pool)
	}
	return out
}

func rnd() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func eq(h []byte) func([]byte) bool { return func(s []byte) bool { return bytes.Equal(s, h) } }

func TestCodes(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			email := rnd() + "@x.test"
			c := Code{ID: rnd(), Brand: "b", Purpose: "signin", Email: email, Hash: []byte("good"), ExpiresAt: time.Now().Add(10 * time.Minute)}
			if err := s.PutCode(ctx, c); err != nil {
				t.Fatal(err)
			}
			if r, _, _ := s.CheckCode(ctx, c.ID, eq([]byte("bad")), 5); r != CodeWrong {
				t.Fatalf("wrong code: %v", r)
			}
			if r, got, _ := s.CheckCode(ctx, c.ID, eq([]byte("good")), 5); r != CodeOK || got.Email != email {
				t.Fatalf("good code: %v", r)
			}
			if r, _, _ := s.CheckCode(ctx, c.ID, eq([]byte("good")), 5); r == CodeOK {
				t.Fatal("code used twice")
			}

			// Five wrong attempts kill the code, even the right one afterwards.
			c2 := Code{ID: rnd(), Brand: "b", Purpose: "signin", Email: email, Hash: []byte("good"), ExpiresAt: time.Now().Add(10 * time.Minute)}
			_ = s.PutCode(ctx, c2)
			for i := 1; i <= 5; i++ {
				r, _, _ := s.CheckCode(ctx, c2.ID, eq([]byte("bad")), 5)
				if (i < 5 && r != CodeWrong) || (i == 5 && r != CodeLocked) {
					t.Fatalf("attempt %d: %v", i, r)
				}
			}
			if r, _, _ := s.CheckCode(ctx, c2.ID, eq([]byte("good")), 5); r != CodeLocked {
				t.Fatalf("after lock: %v", r)
			}

			// A new code retires the previous one.
			c3 := Code{ID: rnd(), Brand: "b", Purpose: "signin", Email: email, Hash: []byte("c3"), ExpiresAt: time.Now().Add(10 * time.Minute)}
			c4 := Code{ID: rnd(), Brand: "b", Purpose: "signin", Email: email, Hash: []byte("c4"), ExpiresAt: time.Now().Add(10 * time.Minute)}
			_ = s.PutCode(ctx, c3)
			_ = s.PutCode(ctx, c4)
			if r, _, _ := s.CheckCode(ctx, c3.ID, eq([]byte("c3")), 5); r == CodeOK {
				t.Fatal("replaced code still valid")
			}
			if r, _, _ := s.CheckCode(ctx, c4.ID, eq([]byte("c4")), 5); r != CodeOK {
				t.Fatalf("new code: %v", r)
			}

			// Expired.
			c5 := Code{ID: rnd(), Brand: "b", Purpose: "reset", Email: email, Hash: []byte("x"), ExpiresAt: time.Now().Add(-time.Second)}
			_ = s.PutCode(ctx, c5)
			if r, _, _ := s.CheckCode(ctx, c5.ID, eq([]byte("x")), 5); r != CodeExpired {
				t.Fatalf("expired: %v", r)
			}
			if r, _, _ := s.CheckCode(ctx, "nope", eq([]byte("x")), 5); r != CodeUnknown {
				t.Fatalf("unknown: %v", r)
			}
		})
	}
}

func TestParallelGuessesCannotExceedLimit(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := Code{ID: rnd(), Brand: "b", Purpose: "signin", Email: rnd(), Hash: []byte("good"), ExpiresAt: time.Now().Add(time.Minute)}
			_ = s.PutCode(ctx, c)
			var wg sync.WaitGroup
			var mu sync.Mutex
			counted := 0
			for range 20 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r, _, err := s.CheckCode(ctx, c.ID, eq([]byte("bad")), 5)
					if err != nil {
						t.Error(err)
					}
					if r == CodeWrong || (r == CodeLocked) {
						mu.Lock()
						counted++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if r, _, _ := s.CheckCode(ctx, c.ID, eq([]byte("good")), 5); r != CodeLocked {
				t.Fatalf("code alive after 20 parallel wrong guesses: %v", r)
			}
		})
	}
}

func TestAllow(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			addr, ip := Limit{Key: "a:" + rnd(), Max: 5, Window: time.Hour}, Limit{Key: "i:" + rnd(), Max: 7, Window: time.Hour}
			for i := 0; i < 5; i++ {
				if ok, err := s.Allow(ctx, addr, ip); !ok || err != nil {
					t.Fatalf("send %d refused: %v", i+1, err)
				}
			}
			if ok, _ := s.Allow(ctx, addr, ip); ok {
				t.Fatal("6th send allowed")
			}
			// The refused attempt did not count against the IP.
			other := Limit{Key: "a:" + rnd(), Max: 5, Window: time.Hour}
			for i := 0; i < 2; i++ {
				if ok, _ := s.Allow(ctx, other, ip); !ok {
					t.Fatalf("ip send %d refused", i+6)
				}
			}
			if ok, _ := s.Allow(ctx, other, ip); ok {
				t.Fatal("ip limit not enforced")
			}
			if err := s.Cleanup(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
