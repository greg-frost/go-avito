package model

import (
	"errors"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type Token struct {
	Role Role
	jwt.StandardClaims
}

func ParseToken(tokenHeader string) (*Token, error) {
	if tokenHeader == "" {
		return nil, errors.New("empty auth token")
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return nil, errors.New("malformed auth token")
	}

	tk := new(Token)
	tokenPart := tokenParts[1]
	token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, errors.New("malformed jwt token")
	}

	if !token.Valid {
		return nil, errors.New("invalid jwt token")
	}

	return tk, nil
}

func (tk *Token) SignedString() (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return tokenString, err
}
