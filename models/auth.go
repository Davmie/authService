package models

import "github.com/golang-jwt/jwt/v5"

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	UserID   string `json:"GUID"`
	ClientIP string `json:"client_ip"`
	jwt.RegisteredClaims
}
