// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package database

import (
	"github.com/google/uuid"
)

type User struct {
	ID    uuid.UUID
	Ip    string
	Token string
}
