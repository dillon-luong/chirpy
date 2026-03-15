package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
		return "", fmt.Errorf("Error signing JWT: %v", err)
	}

	return jwt, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
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
		return uuid.Nil, fmt.Errorf("error parsing uuid: %v", err)
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