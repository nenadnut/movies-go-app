package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (app *application) routes() http.Handler {
	// create router mux
	mux := chi.NewRouter()

	// if the app panics, this will catch it, recover, log the stacktrace and return 500 status code, the app will go on
	mux.Use(middleware.Recoverer)
	// add middleware
	mux.Use(app.enableCORS)

	mux.Get("/", app.Home)
	mux.Get("/movies", app.AllMovies)
	mux.Post("/authenticate", app.authenticate)
	mux.Get("/refresh", app.refreshToken)
	mux.Get("/logout", app.logout)

	mux.Route("/admin", func(mux chi.Router) {
		mux.Use(app.authRequired)

		mux.Get("/movies", app.MovieCatalog)
	})

	return mux
}
