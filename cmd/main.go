package main

import (
	authUseCase "db_cp/internal/auth/usecase"
	"fmt"
	"net/http"

	authDel "db_cp/internal/auth/delivery"
	authRepoPg "db_cp/internal/auth/repository/postgres"
	"db_cp/pkg/middleware"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

const port = ":8080"

func main() {
	zapLogger := zap.Must(zap.NewDevelopment())
	logger := zapLogger.Sugar()

	params := "user=postgres dbname=postgres password=postgres host=test_postgres port=5432 sslmode=disable"
	db, err := sqlx.Connect("postgres", params)
	if err != nil {
		logger.Fatal(err)
	}
	defer func(db *sqlx.DB) {
		err := db.Close()
		if err != nil {
			logger.Fatal(err)
		}
	}(db)

	authHandler := authDel.AuthHandler{
		Logger:      logger,
		AuthUseCase: authUseCase.New(authRepoPg.New(db)),
	}

	r := mux.NewRouter()

	r.HandleFunc("/getTokens", authHandler.GetTokens)
	r.HandleFunc("/refreshTokens", authHandler.RefreshTokens)

	muxx := middleware.AccessLog(logger, r)
	muxx = middleware.Panic(logger, muxx)

	logger.Infow("starting server",
		"type", "START",
		"port", port,
	)

	logger.Errorln(http.ListenAndServe(port, muxx))

	err = zapLogger.Sync()
	if err != nil {
		fmt.Println(err)
	}
}
