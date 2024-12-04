package repo

import (
	"db_cp/internal/auth/repository"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

type pgAuthRepo struct {
	DB *sqlx.DB
}

type pgToken struct {
	RefreshToken string `db:"refresh_token"`
	UserID       string `db:"userid"`
	ClientIP     string `db:"client_ip"`
}

func New(db *sqlx.DB) repository.AuthRepositoryI {
	return &pgAuthRepo{
		DB: db,
	}
}

func (pur *pgAuthRepo) Create(refreshToken, userID, clientIP string) error {
	_, err := pur.DB.Exec(
		"insert into Tokens values (default, $1, $2, $3)",
		userID,
		refreshToken,
		clientIP,
	)

	if err != nil {
		return errors.Wrap(err, "can`t insert to db")
	}

	return nil
}

func (pur *pgAuthRepo) Get(userID string) (string, string, error) {
	token := pgToken{}

	err := pur.DB.Get(&token,
		"select refresh_token, userid, client_ip from Tokens where userid = $1", userID)

	if err != nil {
		return "", "", errors.Wrap(err, "can`t get from db")
	}

	return token.RefreshToken, token.ClientIP, nil
}

func (pur *pgAuthRepo) Update(refreshToken, userID, clientIP string) error {
	_, err := pur.DB.Exec(
		"update Tokens set refresh_token = $1, client_ip = $2 where userid = $3",
		refreshToken, clientIP, userID)

	if err != nil {
		return errors.Wrap(err, "can`t update db")
	}

	return nil
}
