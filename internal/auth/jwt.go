package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"crypto/rand"
	"encoding/hex"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "chirpy-access",
		Subject: userID.String(),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
	})

	jwt, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// checks if og signature in tokenString matches generated signature from payload
	// can fail if:
	// payload was changed but sig wasn't, so recreated sig will be diff
	// payload and sig was changed, but since they dont have secret they cant recreate the proper sig
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return 	[]byte(tokenSecret), nil
	})

	// could be invalid bc expired
	if err != nil {
		return uuid.Nil, err
	}

	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	stringID, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}
	
	if id, err := uuid.Parse(stringID); err != nil {
		return uuid.Nil, err
	} else {
		return id, nil
	}
}

var NoAuth = errors.New("no auth header")
func GetBearerToken(headers http.Header) (string, error) {
	token := headers.Get("Authorization")

	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		return "", NoAuth
	}

	return token, nil
}

func MakeRefreshToken() string {
	key := make([]byte, 32)
	rand.Read(key)

	return hex.EncodeToString(key)
}