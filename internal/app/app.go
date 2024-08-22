package app

import (
	"auth-service-go/internal/config"
	"auth-service-go/internal/database"
	"auth-service-go/internal/handler"
	"database/sql"
	"fmt"
	"github.com/go-chi/chi"
	_ "github.com/lib/pq"
	"log"
	"net/http"
)

func Run() {
	cfg, err := config.LoadConfig()

	if err != nil {
		log.Fatalf("error loading config: %s\n", err)
	}

	log.Println("config has been loaded successfully")

	conn, err := sql.Open("postgres", fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable", cfg.DbUser, cfg.DbPassword, cfg.DbHost, cfg.DbPort, cfg.DbName))

	if err != nil {
		log.Fatalf("error connecting to db: %s\n", err)
	}

	log.Println("successful connection to db")

	queries := database.New(conn)

	r := chi.NewRouter()

	authHandler := handler.NewAuthHandler(queries, cfg)

	authHandler.RegisterEndpoints(r)

	log.Printf("server starting on port %s", cfg.Port)

	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}
