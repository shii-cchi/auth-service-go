package handler

import (
	"auth-service-go/internal/config"
	"auth-service-go/internal/constants"
	"auth-service-go/internal/database"
	"auth-service-go/internal/handler/dto"
	"auth-service-go/internal/service"
	"github.com/go-chi/chi"
	"log"
	"net/http"
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
		r.Get("/token/{client_id}", h.getTokenHandler)
		r.Get("/token/refresh", h.refreshHandler)
	})

	return rg
}

func (h *AuthHandler) getTokenHandler(w http.ResponseWriter, r *http.Request) {
	clientIDStr := chi.URLParam(r, "client_id")

	clientID, err := getID(clientIDStr)

	if err != nil {
		log.Printf(constants.ErrInvalidClientID+"%s\n", err)
		respondWithError(w, http.StatusBadRequest, constants.ErrInvalidClientID)
		return
	}

	clientIP := getIPFromRequest(r)

	tokens, err := h.authService.CreateTokens(clientID, clientIP)

	if err != nil {
		log.Printf(constants.ErrCreatingTokens+"%s\n", err)
		respondWithError(w, http.StatusInternalServerError, constants.ErrCreatingTokens)
		return
	}

	setCookie(w, tokens.RefreshToken, h.config.RefreshTTL)

	respondWithJSON(w, http.StatusOK, dto.ClientDTO{ClientID: clientID, AccessToken: tokens.AccessToken})
}

func (h *AuthHandler) refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := getRefreshToken(r)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, constants.ErrRefreshTokenNotFound)
		return
	}

	accessToken := r.Header.Get("Authorization")

	if accessToken == "" {
		respondWithError(w, http.StatusUnauthorized, constants.ErrAccessTokenNotFound)
		return
	}

	tokens, clientID, clientIP, err := h.authService.Refresh(refreshToken, accessToken)

	if err != nil {
		log.Printf(constants.ErrRefreshingTokens+"%s\n", err)

		if err.Error() == constants.ErrInvalidAccessToken || err.Error() == constants.ErrInvalidRefreshToken {
			respondWithError(w, http.StatusUnauthorized, err.Error())
			return
		}

		respondWithError(w, http.StatusInternalServerError, constants.ErrRefreshingTokens)
		return
	}

	if clientIP != getIPFromRequest(r) {
		log.Println("send warning to client mail about IP change")
	}

	setCookie(w, tokens.RefreshToken, h.config.RefreshTTL)

	respondWithJSON(w, http.StatusOK, dto.ClientDTO{ClientID: clientID, AccessToken: tokens.AccessToken})
}
