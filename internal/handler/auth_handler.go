package handler

import (
	"auth-service-go/internal/model"
	"auth-service-go/internal/service"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
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
	userIDStr := r.URL.Query().Get("user_id")

	if err := uuid.Validate(userIDStr); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid uuid format")
		return
	}

	userID, err := uuid.Parse(userIDStr)

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error parsing user id")
		return
	}

	userIP := r.RemoteAddr

	if strings.Contains(userIP, ":") {
		userIP, _, err = net.SplitHostPort(userIP)

		if err != nil {
			respondWithError(w, http.StatusBadRequest, "error parsing user ip")
			return
		}
	}

	tokens, err := h.authService.CreateTokens(userID, userIP)

	if err != nil {
		log.Printf("error creating tokens: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error creating tokens")
		return
	}

	if err = h.authService.SaveRefreshToken(userID, tokens.HashedRefreshToken); err != nil {
		log.Printf("error saving refresh token to db: %s\n", err)
		respondWithError(w, http.StatusInternalServerError, "error saving refresh token to db")
		return
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	}

	http.SetCookie(w, &cookie)

	respondWithJSON(w, http.StatusOK, model.User{UserID: userID, AccessToken: tokens.AccessToken})
}

func (h *AuthHandler) refreshHandler(w http.ResponseWriter, r *http.Request) {

}
