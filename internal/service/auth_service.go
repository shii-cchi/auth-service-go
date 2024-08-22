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
	ClientIP string `json:"client_ip"`
}

func (s AuthService) CreateTokens(clientID uuid.UUID, clientIP string) (model.Tokens, error) {
	accessToken, err := s.newAccessToken(clientID, clientIP, s.config.AccessTTL)

	if err != nil {
		return model.Tokens{}, fmt.Errorf("error creating access token: %s\n", err)
	}

	refreshToken, hashedRefreshToken, err := s.newRefreshToken()

	if err != nil {
		return model.Tokens{}, fmt.Errorf("error creating refresh token: %s\n", err)
	}

	return model.Tokens{AccessToken: accessToken, RefreshToken: refreshToken, HashedRefreshToken: hashedRefreshToken}, nil
}

func (s AuthService) newAccessToken(clientID uuid.UUID, clientIP string, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &tokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ttl).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   clientID.String(),
		},
		clientIP,
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

func (s AuthService) SaveRefreshToken(clientID uuid.UUID, hashedRefreshToken string) error {
	return s.queries.AddRefreshToken(context.Background(), database.AddRefreshTokenParams{ID: clientID, Token: hashedRefreshToken})
}

func (s AuthService) UpdateRefreshToken(clientID uuid.UUID, hashedRefreshToken string) error {
	return s.queries.UpdateRefreshToken(context.Background(), database.UpdateRefreshTokenParams{ID: clientID, Token: hashedRefreshToken})
}

func (s AuthService) IsValidRefreshToken(clientID uuid.UUID, refreshToken string) error {
	storedHashedRefreshToken, err := s.queries.GetRefreshToken(context.Background(), clientID)

	if err != nil {
		return fmt.Errorf("error getting refresh token from db: %s\n", err)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedHashedRefreshToken), []byte(refreshToken)); err != nil {
		return fmt.Errorf("invalid refresh token: %s\n", err)
	}

	return nil
}

func (s AuthService) GetIDAndIPFromToken(accessToken string) (uuid.UUID, string, error) {
	token, err := jwt.ParseWithClaims(accessToken, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(s.config.AccessSigningKey), nil
	})

	if claims, ok := token.Claims.(*tokenClaims); ok && token.Valid {
		clientID, err := uuid.Parse(claims.Subject)

		if err != nil {
			return uuid.Nil, "", err
		}

		return clientID, claims.ClientIP, nil
	}

	return uuid.Nil, "", err
}
