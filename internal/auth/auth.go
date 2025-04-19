package auth

import (
	"net/http"

	"github.com/greg-frost/go-avito/internal/model"
	u "github.com/greg-frost/go-avito/internal/utils"
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

		token, err := model.ParseToken(r.Header.Get("Authorization"))
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
