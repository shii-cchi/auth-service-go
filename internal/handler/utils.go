package handler

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"log"
	"net"
	"net/http"
	"strings"
)

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)

	if err != nil {
		log.Printf("Failed to marshal JSON responce: %v", payload)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errResponse struct {
		Error string `json:"error"`
	}

	respondWithJSON(w, code, errResponse{
		Error: msg,
	})
}

func getIDFromRequest(r *http.Request) (uuid.UUID, error) {
	clientIDStr := r.URL.Query().Get("client_id")

	if err := uuid.Validate(clientIDStr); err != nil {
		return uuid.Nil, errors.New("invalid uuid format")
	}

	clientID, err := uuid.Parse(clientIDStr)

	if err != nil {
		return uuid.Nil, errors.New("error parsing client id")
	}

	return clientID, nil
}

func getIPFromRequest(r *http.Request) string {
	if clientIP := r.Header.Get("X-Forwarded-For"); clientIP != "" {
		clientIPs := strings.Split(clientIP, ",")
		return strings.TrimSpace(clientIPs[0])
	}

	if clientIP := r.Header.Get("X-Real-IP"); clientIP != "" {
		return clientIP
	}

	clientIP := r.RemoteAddr

	if strings.Contains(clientIP, ":") {
		clientIP, _, _ = net.SplitHostPort(clientIP)
	}

	return clientIP
}
