// Package seal encrypts small JSON values for cookies with AES-256-GCM. The
// cookie name is bound as additional data, so a value sealed for one cookie
// cannot be replayed as another, and every value carries an expiry.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// ErrInvalid means the value was tampered with, sealed with another key, or
// has expired.
var ErrInvalid = errors.New("seal: invalid or expired value")

// Sealer seals and opens values.
type Sealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

// DeriveKey derives an independent 32-byte key for a purpose from a master key.
func DeriveKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("idlogin/" + purpose))
	return m.Sum(nil)
}

// New returns a Sealer for a 32-byte key.
func New(key []byte, now func() time.Time) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("seal: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Sealer{aead: aead, now: now}, nil
}

type envelope struct {
	Exp  int64           `json:"e"`
	Data json.RawMessage `json:"d"`
}

// Seal encrypts v for the named cookie, valid for ttl.
func (s *Sealer) Seal(name string, v any, ttl time.Duration) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(envelope{Exp: s.now().Add(ttl).Unix(), Data: data})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, []byte(name))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value sealed for the named cookie into v.
func (s *Sealer) Open(name, value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return ErrInvalid
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return ErrInvalid
	}
	if s.now().Unix() >= env.Exp {
		return ErrInvalid
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return ErrInvalid
	}
	return nil
}
