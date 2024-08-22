-- +goose Up

CREATE TABLE clients (
    id uuid NOT NULL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL
);

-- +goose Down

DROP TABLE clients;