package usecase

import (
	"crypto/rand"
	authRep "db_cp/internal/auth/repository"
	"db_cp/models"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	accessTokenSecret  = []byte("access_token_secret")
	refreshTokenSecret = []byte("refresh_token_secret")
)

type AuthUseCaseI interface {
	CreateAccessToken(userID, clientIP string) (string, error)
	CreateRefreshToken() (string, error)
	KeepRefreshToken(refreshToken string, userID string, clientIP string) error
	GetRefreshToken(userID string) (string, string, error)
	UpdateRefreshToken(refreshToken string, userID string, clientIP string) error
	ParseAccessToken(accessToken string) (*models.Claims, error)
}

type useCase struct {
	authRepository authRep.AuthRepositoryI
}

func New(uRep authRep.AuthRepositoryI) AuthUseCaseI {
	return &useCase{
		authRepository: uRep,
	}
}

func (u *useCase) CreateAccessToken(userID, clientIP string) (string, error) {
	claims := models.Claims{
		UserID:           userID,
		ClientIP:         clientIP,
		RegisteredClaims: jwt.RegisteredClaims{},
	}
	signedString, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(accessTokenSecret)

	return signedString, err
}

func (u *useCase) CreateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(b)

	return refreshToken, nil
}

func (u *useCase) KeepRefreshToken(refreshToken string, userID string, clientIP string) error {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	err = u.authRepository.Create(string(hashedToken), userID, clientIP)
	if err != nil {
		return err
	}

	return nil
}

func (u *useCase) GetRefreshToken(userID string) (string, string, error) {
	token, clientIP, err := u.authRepository.Get(userID)
	if err != nil {
		return "", "", err
	}

	return token, clientIP, err
}

func (u *useCase) UpdateRefreshToken(refreshToken string, userID string, clientIP string) error {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	err = u.authRepository.Update(string(hashedToken), userID, clientIP)
	if err != nil {
		return err
	}

	return nil
}

func (u *useCase) ParseAccessToken(accessToken string) (*models.Claims, error) {
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return accessTokenSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}
