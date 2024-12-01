package core

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

type Author interface {
	AuthString(id, info string) (string, error)
	Verify(token string) (string, string, error)
}

type JWTAuthor struct {
	ExpirationTime time.Duration
	Secret         string
}

func NewJWTAuthor(expirationTime time.Duration, secret string) Author {
	return &JWTAuthor{
		ExpirationTime: expirationTime,
		Secret:         secret,
	}
}

func (g *JWTAuthor) AuthString(id, unEncryptedInfo string) (string, error) {
	claim := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(g.ExpirationTime).Unix(),
		Id:        id,
		Subject:   unEncryptedInfo,
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	tokenString, err := token.SignedString([]byte(g.Secret))
	if err != nil {
		return "", fmt.Errorf("JWT Author: signing failed: %v", err)
	}
	return tokenString, nil
}

func (g *JWTAuthor) Verify(token string) (string, string, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(g.Secret), nil
	})

	if err != nil {

		return "", "", fmt.Errorf("JWT Author: Parser Error: %v", err)
	}

	if !jwtToken.Valid {
		return "", "", fmt.Errorf("JWT Author: Invalid token")
	}

	claims := jwtToken.Claims.(*jwt.StandardClaims)

	return claims.Id, claims.Subject, nil
}
