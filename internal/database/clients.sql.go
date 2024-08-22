// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: clients.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const addRefreshToken = `-- name: AddRefreshToken :exec
INSERT INTO clients (id, token)
VALUES ($1, $2)
`

type AddRefreshTokenParams struct {
	ID    uuid.UUID
	Token string
}

func (q *Queries) AddRefreshToken(ctx context.Context, arg AddRefreshTokenParams) error {
	_, err := q.db.ExecContext(ctx, addRefreshToken, arg.ID, arg.Token)
	return err
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT token
FROM clients
WHERE id = $1
`

func (q *Queries) GetRefreshToken(ctx context.Context, id uuid.UUID) (string, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, id)
	var token string
	err := row.Scan(&token)
	return token, err
}

const updateRefreshToken = `-- name: UpdateRefreshToken :exec
UPDATE clients
SET token = $2
WHERE id = $1
`

type UpdateRefreshTokenParams struct {
	ID    uuid.UUID
	Token string
}

func (q *Queries) UpdateRefreshToken(ctx context.Context, arg UpdateRefreshTokenParams) error {
	_, err := q.db.ExecContext(ctx, updateRefreshToken, arg.ID, arg.Token)
	return err
}
