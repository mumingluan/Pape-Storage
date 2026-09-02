package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrMalformed = errors.New("malformed upload token")
	ErrSignature = errors.New("invalid upload token signature")
	ErrExpired   = errors.New("upload token expired")
)

type Claims struct {
	Version  int    `json:"v"`
	Key      string `json:"key"`
	Expires  int64  `json:"exp"`
	MaxBytes int64  `json:"max_bytes"`
}

type Signer struct {
	key []byte
	now func() time.Time
}

func New(signingKey string) *Signer {
	return &Signer{key: []byte(signingKey), now: time.Now}
}

func (s *Signer) Sign(claims Claims) (string, error) {
	claims.Version = 1
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(s.mac(encoded)), nil
}

func (s *Signer) Verify(value string) (Claims, error) {
	var claims Claims
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return claims, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, s.mac(parts[0])) {
		return claims, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Version != 1 || claims.Key == "" || claims.MaxBytes < 1 {
		return Claims{}, ErrMalformed
	}
	if claims.Expires <= s.now().Unix() {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

func (s *Signer) mac(payload string) []byte {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}
