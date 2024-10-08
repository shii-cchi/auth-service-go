package config

import (
	"errors"
	"github.com/joho/godotenv"
	"os"
	"time"
)

type Config struct {
	Port             string
	DbUser           string
	DbPassword       string
	DbHost           string
	DbPort           string
	DbName           string
	AccessTTL        time.Duration
	AccessSigningKey string
	RefreshTTL       time.Duration
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load(".env")

	if err != nil {
		return nil, err
	}

	port := os.Getenv("PORT")

	if port == "" {
		return nil, errors.New("PORT parameter is not defined")
	}

	dbUser := os.Getenv("DB_USER")

	if dbUser == "" {
		return nil, errors.New("DB_USER parameter is not defined")
	}

	dbPassword := os.Getenv("DB_PASSWORD")

	if dbPassword == "" {
		return nil, errors.New("DB_PASSWORD parameter is not defined")
	}

	dbHost := os.Getenv("DB_HOST")

	if dbHost == "" {
		return nil, errors.New("DB_HOST parameter is not defined")
	}

	dbPort := os.Getenv("DB_PORT")

	if dbPort == "" {
		return nil, errors.New("DB_PORT parameter is not defined")
	}

	dbName := os.Getenv("DB_NAME")

	if dbName == "" {
		return nil, errors.New("DB_NAME parameter is not defined")
	}

	accessTTLStr := os.Getenv("ACCESS_TTL")

	if accessTTLStr == "" {
		return nil, errors.New("ACCESS_TTL parameter is not defined")
	}

	accessTTL, err := time.ParseDuration(accessTTLStr)

	if err != nil {
		return nil, errors.New("error parsing access ttl")
	}

	accessSigningKey := os.Getenv("ACCESS_SIGNING_KEY")

	if accessSigningKey == "" {
		return nil, errors.New("ACCESS_SIGNING_KEY parameter is not defined")
	}

	refreshTTLStr := os.Getenv("REFRESH_TTL")

	if refreshTTLStr == "" {
		return nil, errors.New("REFRESH_TTL parameter is not defined")
	}

	refreshTTL, err := time.ParseDuration(refreshTTLStr)

	if err != nil {
		return nil, errors.New("error parsing refresh ttl")
	}

	return &Config{
		Port:             port,
		DbUser:           dbUser,
		DbPassword:       dbPassword,
		DbHost:           dbHost,
		DbPort:           dbPort,
		DbName:           dbName,
		AccessTTL:        accessTTL,
		AccessSigningKey: accessSigningKey,
		RefreshTTL:       refreshTTL,
	}, nil
}
