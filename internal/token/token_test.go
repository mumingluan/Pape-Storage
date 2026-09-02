package token

import (
	"errors"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	signer := New("0123456789abcdef0123456789abcdef")
	signer.now = func() time.Time { return time.Unix(100, 0) }
	encoded, err := signer.Sign(Claims{Key: "photo/a.bin", Expires: 200, MaxBytes: 99})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Verify(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Key != "photo/a.bin" || claims.MaxBytes != 99 {
		t.Fatalf("claims = %+v", claims)
	}
	if _, err := signer.Verify(encoded + "x"); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered error = %v", err)
	}
	signer.now = func() time.Time { return time.Unix(200, 0) }
	if _, err := signer.Verify(encoded); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired error = %v", err)
	}
}
