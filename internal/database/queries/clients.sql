-- name: AddRefreshToken :exec
INSERT INTO clients (id, token)
VALUES ($1, $2);

-- name: GetRefreshToken :one
SELECT token
FROM clients
WHERE id = $1;

-- name: UpdateRefreshToken :exec
UPDATE clients
SET token = $2
WHERE id = $1;