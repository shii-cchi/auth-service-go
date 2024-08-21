-- name: AddRefreshToken :exec
INSERT INTO users (id, token)
VALUES ($1, $2);