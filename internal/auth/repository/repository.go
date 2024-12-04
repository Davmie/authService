package repository

type AuthRepositoryI interface {
	Create(refreshToken, userID, clientIP string) error
	Get(userID string) (string, string, error)
	Update(refreshToken, userID, clientIP string) error
}
