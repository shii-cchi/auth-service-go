package service

import (
	"auth-service-go/internal/config"
	"auth-service-go/internal/database"
	"auth-service-go/internal/model"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthService struct {
	queries *database.Queries
	config  *config.Config
}

func NewAuthService(q *database.Queries, cfg *config.Config) *AuthService {
	return &AuthService{
		queries: q,
		config:  cfg,
	}
}

type tokenClaims struct {
	jwt.StandardClaims
	UserIP int `json:"user_ip"`
}

func (s AuthService) CreateTokens(userID uuid.UUID, userIP int) (model.Tokens, error) {
	ttl, err := time.ParseDuration(s.config.AccessTTL)

	if err != nil {
		return model.Tokens{}, fmt.Errorf("error parsing access ttl: %s\n", err)
	}

	accessToken, err := s.newAccessToken(userID, userIP, ttl)

	if err != nil {
		return model.Tokens{}, fmt.Errorf("error creating access token: %s\n", err)
	}

	refreshToken, hashedRefreshToken, err := s.newRefreshToken()

	if err != nil {
		return model.Tokens{}, fmt.Errorf("error creating refresh token: %s\n", err)
	}

	if err = s.queries.AddRefreshToken(context.Background(), database.AddRefreshTokenParams{Token: hashedRefreshToken, ID: userID}); err != nil {
		return model.Tokens{}, fmt.Errorf("error adding refresh token to db: %s\n", err)
	}

	return model.Tokens{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s AuthService) newAccessToken(userID uuid.UUID, userIP int, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &tokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ttl).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   userID.String(),
		},
		userIP,
	})

	return token.SignedString([]byte(s.config.AccessSigningKey))
}

func (s AuthService) newRefreshToken() (string, string, error) {
	refreshToken := make([]byte, 32)

	_, err := rand.Read(refreshToken)

	if err != nil {
		return "", "", err
	}

	refreshTokenStr := base64.StdEncoding.EncodeToString(refreshToken)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshTokenStr), bcrypt.DefaultCost)

	if err != nil {
		return "", "", err
	}

	return refreshTokenStr, string(hashedToken), nil
}
