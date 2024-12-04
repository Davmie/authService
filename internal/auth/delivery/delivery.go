package delivery

import (
	authUseCase "db_cp/internal/auth/usecase"
	"db_cp/models"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"

	"db_cp/pkg/logger"
)

type AuthHandler struct {
	AuthUseCase authUseCase.AuthUseCaseI
	Logger      logger.Logger
}

func (ah *AuthHandler) GetTokens(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("GUID")
	if userID == "" {
		ah.Logger.Errorw("no user id (GUID) provided")
		http.Error(w, "no user id provided", http.StatusBadRequest)
		return
	}

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	accessToken, err := ah.AuthUseCase.CreateAccessToken(userID, clientIP)
	if err != nil {
		ah.Logger.Errorw("error creating access token", "error", err)
		http.Error(w, "error creating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := ah.AuthUseCase.CreateRefreshToken()
	if err != nil {
		ah.Logger.Errorw("error creating refresh token", "error", err)
		http.Error(w, "error creating refresh token", http.StatusInternalServerError)
		return
	}

	err = ah.AuthUseCase.KeepRefreshToken(refreshToken, userID, clientIP)
	if err != nil {
		ah.Logger.Errorw("error keeping refresh token", "error", err)
		http.Error(w, "error keeping refresh token", http.StatusInternalServerError)
		return
	}

	authResponse := models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	resp, err := json.Marshal(authResponse)

	if err != nil {
		ah.Logger.Errorw("can`t marshal auth response",
			"err:", err.Error())
		http.Error(w, "can`t make auth response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)

	_, err = w.Write(resp)
	if err != nil {
		ah.Logger.Errorw("can`t write response",
			"err:", err.Error())
		http.Error(w, "can`t write response", http.StatusInternalServerError)
		return
	}
}

func (ah *AuthHandler) sendEmailWarning(userID string, clientIP string, storedIP string) {
	ah.Logger.Infow("WARNING: IP mismatch for user %s. NewIP: %s, oldIP: %s", userID, clientIP, storedIP)
}

func (ah *AuthHandler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	accessToken := r.URL.Query().Get("access_token")
	refreshToken := r.URL.Query().Get("refresh_token")

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	claims, err := ah.AuthUseCase.ParseAccessToken(accessToken)
	if err != nil {
		ah.Logger.Errorw("can`t parse access token", "error", err)
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	storedRefreshToken, storedClientIP, err := ah.AuthUseCase.GetRefreshToken(claims.UserID)
	if err != nil {
		ah.Logger.Errorw("can`t get refresh token", "error", err)
		http.Error(w, "can`t get refresh token", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(storedRefreshToken), []byte(refreshToken)) == nil {
		ah.Logger.Errorw("stored and actual refresh token mismatch")
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	if clientIP != storedClientIP {
		ah.sendEmailWarning(claims.UserID, clientIP, storedClientIP)
	}

	newAccessToken, err := ah.AuthUseCase.CreateAccessToken(claims.UserID, clientIP)
	if err != nil {
		ah.Logger.Errorw("error creating access token", "error", err)
		http.Error(w, "error creating access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := ah.AuthUseCase.CreateRefreshToken()
	if err != nil {
		ah.Logger.Errorw("error creating refresh token", "error", err)
		http.Error(w, "error creating refresh token", http.StatusInternalServerError)
		return
	}

	err = ah.AuthUseCase.UpdateRefreshToken(newRefreshToken, claims.UserID, clientIP)

	authResponse := models.AuthResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}

	resp, err := json.Marshal(authResponse)

	if err != nil {
		ah.Logger.Errorw("can`t marshal auth response",
			"err:", err.Error())
		http.Error(w, "can`t make auth response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	_, err = w.Write(resp)
	if err != nil {
		ah.Logger.Errorw("can`t write response",
			"err:", err.Error())
		http.Error(w, "can`t write response", http.StatusInternalServerError)
		return
	}
}
