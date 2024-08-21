-- +goose Up

CREATE TABLE users (
    id uuid NOT NULL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL
);

-- +goose Down

DROP TABLE users;