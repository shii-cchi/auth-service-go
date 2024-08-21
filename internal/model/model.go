package model

import "github.com/google/uuid"

type Tokens struct {
	AccessToken        string
	RefreshToken       string
	HashedRefreshToken string
}

type User struct {
	UserID      uuid.UUID `json:"user_id"`
	AccessToken string    `json:"access_token"`
}
