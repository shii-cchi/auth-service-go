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
UPDATE users
SET token = $2
WHERE id = $1
`

type AddRefreshTokenParams struct {
	ID    uuid.UUID
	Token string
}

func (q *Queries) AddRefreshToken(ctx context.Context, arg AddRefreshTokenParams) error {
	_, err := q.db.ExecContext(ctx, addRefreshToken, arg.ID, arg.Token)
	return err
}
