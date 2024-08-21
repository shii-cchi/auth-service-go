-- +goose Up

CREATE TABLE users (
    id uuid NOT NULL PRIMARY KEY,
    ip TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL
);

-- +goose Down

DROP TABLE users;