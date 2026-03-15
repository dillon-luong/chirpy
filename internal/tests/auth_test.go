package tests

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/dillon-luong/chirpy/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// creates a hashed password and checks that it can be matched
func TestHashMatching(t *testing.T) {
	password := "example"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error doing hash: %v", err)
		return
	}

	match, err := auth.CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("unexpected error comparing password and hash: %v", err)
		return
	}

	if !match {
		t.Error("password and hash do not match")
	}
}

func TestHashNotMatching(t *testing.T) {
	password := "example"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error doing hash: %v", err)
		return
	}

	match, err := auth.CheckPasswordHash("not example", hash)
	if err != nil {
		t.Fatalf("unexpected error comparing password and hash: %v", err)
		return
	}

	if match {
		t.Error("password and hash should not match")
	}
}

func TestJWTSuccess(t *testing.T) {
	id := uuid.New()
	secret := "secret"
	token, err := auth.MakeJWT(id, secret, 5 * time.Minute)
	if err != nil {
		t.Fatalf("unexpected error creating token: %v", err)
	}

	if retId, err := auth.ValidateJWT(token, secret); err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	} else if id != retId {
		t.Error("input and output id don't match")
	}
}

func TestJWTFail(t *testing.T) {
	id := uuid.New()
	secret := "secret"
	token, err := auth.MakeJWT(id, secret, 5 * time.Minute)
	if err != nil {
		t.Fatalf("unexpected error creating token: %v", err)
	}

	_, err = auth.ValidateJWT(token, "not secret")
	if err == nil {
		t.Fatalf("expected error invalid key, but no error was returned")
	} else if !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Errorf("expected %v, got error %v", jwt.ErrSignatureInvalid, err)
	}
}

func TestJWTExpired(t *testing.T) {
	id := uuid.New()
	secret := "secret"
	token, err := auth.MakeJWT(id, secret, 0 * time.Second)
	if err != nil {
		t.Fatalf("unexpected error creating token: %v", err)
	}

	_, err = auth.ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error invalid key, but no error was returned")
	} else if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("expected %v, got error %v", jwt.ErrTokenExpired, err)
	}
}

func TestParseHeaderAuthSuccess(t *testing.T) {
	token := "test"
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatalf("unexpected error creating fake request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer " + token)

	retToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		t.Fatalf("unexpected error parsing token")
	} else if retToken != token {
		t.Error("returned token not the same as input token")
	}
}

func TestParseHeaderAuthEmpty(t *testing.T) {
	token := ""
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatalf("unexpected error creating fake request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer " + token)

	_, err = auth.GetBearerToken(req.Header)
	if !errors.Is(err, auth.NoAuth) {
		t.Errorf("expected no auth token, got %v", err)
	}
}