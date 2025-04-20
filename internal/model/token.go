package model

import (
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

type Token struct {
	Role Role
	jwt.StandardClaims
}

func (tk *Token) SignedString() (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return tokenString, err
}
