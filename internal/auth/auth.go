package auth

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/greg-frost/go-avito/internal/model"
	u "github.com/greg-frost/go-avito/internal/utils"

	"github.com/dgrijalva/jwt-go"
)

var JwtAuthentication = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skipAuth := []string{"/dummyLogin", "/register", "/login"}
		requestPath := r.URL.Path
		for _, path := range skipAuth {
			if path == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		token, err := ParseToken(r.Header.Get("Authorization"))
		if err != nil {
			u.RespondWithError(w, model.Error{
				Code:    http.StatusForbidden,
				Message: err.Error(),
			})
			return
		}

		ctx := u.PutRoleIntoContext(r.Context(), token.Role)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func ParseToken(tokenHeader string) (*model.Token, error) {
	if tokenHeader == "" {
		return nil, errors.New("empty auth token")
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return nil, errors.New("malformed auth token")
	}

	tk := new(model.Token)
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
