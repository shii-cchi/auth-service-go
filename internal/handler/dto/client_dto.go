package dto

import "github.com/google/uuid"

type ClientDTO struct {
	ClientID    uuid.UUID `json:"client_id"`
	AccessToken string    `json:"access_token"`
}
