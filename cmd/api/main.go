package main

import (
	"flag"
	"fmt"
	"log"
	"movies/internal/repository"
	"movies/internal/repository/dbrepo"
	"net/http"
	"time"
)

const port = 8080

type application struct {
	Domain       string
	DSN          string // data source name
	DB           repository.DatabaseRepo
	auth         Auth
	JWTSecret    string
	JWTIssuer    string
	JWTAudience  string
	CookieDomain string
}

func main() {
	// set an appication
	var app application
	log.Println("Starting an application on port", port)

	// read from command line
	flag.StringVar(
		&app.DSN,
		"dsn",
		"host=localhost port=5432 user=postgres password=postgres dbname=movies sslmode=disable timezone=UTC connect_timeout=5", "Postgres connection string")

	flag.StringVar(
		&app.JWTSecret,
		"jwt-secret",
		"veryverysecret",
		"signing secret",
	)

	flag.StringVar(
		&app.JWTIssuer,
		"jwt-issuer",
		"example.com",
		"signing-issuer",
	)

	flag.StringVar(
		&app.JWTAudience,
		"jwt-audience",
		"example.com",
		"signing audience ",
	)

	flag.StringVar(
		&app.CookieDomain,
		"cookie-domain",
		"localhost",
		"cookie domain",
	)

	flag.StringVar(
		&app.Domain,
		"domain",
		"example.com",
		"sdomain",
	)
	flag.Parse()

	// connect to the database
	conn, err := app.ConnectToDB()
	if err != nil {
		log.Fatal(err)
	}

	app.Domain = "example.com"
	app.DB = &dbrepo.PostgresDBRepo{DB: conn}
	defer app.DB.Connection().Close()

	app.auth = Auth{
		Issuer:        app.JWTIssuer,
		Audience:      app.JWTAudience,
		Secret:        app.JWTSecret,
		TokenExpiry:   time.Minute * 15,
		RefreshExpiry: time.Hour * 24,
		CookiePath:    "/",
		CookieDomain:  app.CookieDomain,
		CookieName:    "__Host-refresh-token",
	}

	// start a web server
	// Default serve Mux is slower than other 3rd-party handlers
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), app.routes())

	if err != nil {
		log.Fatal(err)
	}

}
