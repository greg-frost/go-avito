package util

import (
	"context"

	"github.com/greg-frost/go-avito/internal/model"
)

type roleCtx string

var roleKey roleCtx = "role"

func PutRoleIntoContext(ctx context.Context, role model.Role) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

func GetRoleFromContext(ctx context.Context) model.Role {
	return ctx.Value(roleKey).(model.Role)
}
