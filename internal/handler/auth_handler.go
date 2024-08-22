package handler

import (
	"auth-service-go/internal/config"
	"auth-service-go/internal/database"
	"auth-service-go/internal/model"
	"auth-service-go/internal/service"
	"fmt"
	"github.com/go-chi/chi"
	"log"
	"net/http"
	"time"
)

type AuthHandler struct {
	authService *service.AuthService
	config      *config.Config
}

func NewAuthHandler(q *database.Queries, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: service.NewAuthService(q, cfg),
		config:      cfg,
	}
}

func (h *AuthHandler) RegisterEndpoints(r chi.Router) {
	r.Mount("/auth", h.authHandlers())
}

func (h *AuthHandler) authHandlers() http.Handler {
	rg := chi.NewRouter()
	rg.Group(func(r chi.Router) {
		r.Get("/token", h.getTokenHandler)
		r.Get("/token/refresh", h.refreshHandler)
	})

	return rg
}

func (h *AuthHandler) getTokenHandler(w http.ResponseWriter, r *http.Request) {
	clientID, err := getIDFromRequest(r)

	if err != nil {
		log.Printf("error getting client id: %s\n", err)
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	clientIP := getIPFromRequest(r)

	tokens, err := h.authService.CreateTokens(clientID, clientIP)

	if err != nil {
		log.Printf("error creating tokens: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error creating tokens")
		return
	}

	if err = h.authService.SaveRefreshToken(clientID, tokens.HashedRefreshToken); err != nil {
		log.Printf("error saving refresh token to db: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error saving refresh token to db")
		return
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Expires:  time.Now().Add(h.config.RefreshTTL * time.Hour),
	}

	http.SetCookie(w, &cookie)

	respondWithJSON(w, http.StatusOK, model.Client{ClientID: clientID, AccessToken: tokens.AccessToken})
}

func (h *AuthHandler) refreshHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")

	if err != nil {
		if err == http.ErrNoCookie {
			respondWithError(w, http.StatusBadRequest, fmt.Sprintf("cookie not found %s\n", err))
			return
		}

		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("%v", err))
		return
	}

	refreshToken := cookie.Value

	accessToken := r.Header.Get("Authorization")

	if accessToken == "" {
		respondWithError(w, http.StatusUnauthorized, "access token not found")
		return
	}

	clientID, clientIP, err := h.authService.GetIDAndIPFromToken(accessToken)

	if err != nil {
		log.Printf("error getting id and ip from token: %s\n", err)
		respondWithError(w, http.StatusUnauthorized, "invalid access token")
		return
	}

	if clientIP != getIPFromRequest(r) {
		log.Println("send warning to client mail")
		return
	}

	if err = h.authService.IsValidRefreshToken(clientID, refreshToken); err != nil {
		log.Printf("invalid refresh token: %s\n", err)
		respondWithError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	tokens, err := h.authService.CreateTokens(clientID, clientIP)

	if err != nil {
		log.Printf("error creating tokens: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error creating tokens")
		return
	}

	if err = h.authService.UpdateRefreshToken(clientID, tokens.HashedRefreshToken); err != nil {
		log.Printf("error updating refresh token in db: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error updating refresh token in db")
		return
	}

	*cookie = http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Expires:  time.Now().Add(h.config.RefreshTTL * time.Hour),
	}

	http.SetCookie(w, cookie)

	respondWithJSON(w, http.StatusOK, model.Client{ClientID: clientID, AccessToken: tokens.AccessToken})
}
