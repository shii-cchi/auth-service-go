package model

import "github.com/google/uuid"

type Tokens struct {
	AccessToken        string
	RefreshToken       string
	HashedRefreshToken string
}

type Client struct {
	ClientID    uuid.UUID `json:"client_id"`
	AccessToken string    `json:"access_token"`
}
