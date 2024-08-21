// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const addRefreshToken = `-- name: AddRefreshToken :exec
INSERT INTO users (id, ip, token)
VALUES ($1, $2, $3)
`

type AddRefreshTokenParams struct {
	ID    uuid.UUID
	Ip    string
	Token string
}

func (q *Queries) AddRefreshToken(ctx context.Context, arg AddRefreshTokenParams) error {
	_, err := q.db.ExecContext(ctx, addRefreshToken, arg.ID, arg.Ip, arg.Token)
	return err
}
