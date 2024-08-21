-- name: AddRefreshToken :exec
INSERT INTO users (id, ip, token)
VALUES ($1, $2, $3);