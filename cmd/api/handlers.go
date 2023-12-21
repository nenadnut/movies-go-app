package main

import (
	"errors"
	"movies/internal/models"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func (app *application) Home(w http.ResponseWriter, r *http.Request) {
	var payload = struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Version string `json:"version"`
	}{
		Status:  "active",
		Message: "Go Movies up and running",
		Version: "1.0.0",
	}

	_ = app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) AllMovies(w http.ResponseWriter, r *http.Request) {
	movies, err := app.DB.AllMovies()

	if err != nil {
		app.errorJSON(w, err)
		return
	}

	_ = app.writeJSON(w, http.StatusOK, movies)
}

func (app *application) AllMoviesDummy(w http.ResponseWriter, r *http.Request) {
	var movies []models.Movie

	rd, _ := time.Parse("2006-01-02", "1996-03-07")

	highlander := models.Movie{
		ID:          1,
		Title:       "Highlander",
		ReleaseDate: rd,
		MPAARating:  "R",
		Runtime:     116,
		Description: "A very nice movie",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	rd, _ = time.Parse("2006-01-02", "1981-06-12")

	raidersOfTheLostArk := models.Movie{
		ID:          2,
		Title:       "Raiders of the Lost Ark",
		ReleaseDate: rd,
		MPAARating:  "PG-13",
		Runtime:     115,
		Description: "Another very nice movie",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	movies = append(movies, highlander)
	movies = append(movies, raidersOfTheLostArk)
	_ = app.writeJSON(w, http.StatusOK, movies)
}

func (app *application) authenticate(w http.ResponseWriter, r *http.Request) {
	// read a JSON payload
	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate user against database
	user, err := app.DB.GetUserByEmail(requestPayload.Email)
	if err != nil {
		app.errorJSON(w, errors.New("Invalid credentials"), http.StatusBadRequest)
	}

	// check password
	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		app.errorJSON(w, errors.New("Invalid credentials"), http.StatusBadRequest)
		return
	}

	// create a JWT user
	u := JWTUser{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	// generate tokens
	tokens, err := app.auth.GenerateTokenPair(&u)
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	// JWT were used to be stored in local storage years back, but upon many security issues that raised up, so we are moving it to a cookie
	// The only secure way to do it is to store it as a variable in JavaScript
	refreshCookie := app.auth.GetRefreshCookie(tokens.RefreshToken)
	http.SetCookie(w, refreshCookie)

	app.writeJSON(w, http.StatusAccepted, tokens)
}

// call this endpoint when the user comes to the page and it doesn't have a jwt token in their JS code
func (app *application) refreshToken(w http.ResponseWriter, r *http.Request) {
	// we need to go through cookies and find the refresh token cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name == app.auth.CookieName {
			claims := &Claims{}
			refreshToken := cookie.Value

			// parse the token to get the claims
			_, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(app.JWTSecret), nil
			})

			if err != nil {
				app.errorJSON(w, errors.New("Unauthorized"), http.StatusUnauthorized)
				return
			}

			// get the user ID from the token claims
			userID, err := strconv.Atoi(claims.Subject)
			if err != nil {
				app.errorJSON(w, err, http.StatusUnauthorized)
				return
			}

			user, err := app.DB.GetUserById(userID)
			if err != nil {
				app.errorJSON(w, errors.New("unkknown user"), http.StatusUnauthorized)
				return
			}

			u := JWTUser{
				ID:        user.ID,
				FirstName: user.FirstName,
				LastName:  user.LastName,
			}

			tokenPair, err := app.auth.GenerateTokenPair(&u)
			if err != nil {
				app.errorJSON(w, errors.New("Error generating tokens"), http.StatusUnauthorized)
				return
			}

			http.SetCookie(w, app.auth.GetRefreshCookie(tokenPair.RefreshToken))
			app.writeJSON(w, http.StatusOK, tokenPair)
		}
	}
}

func (app *application) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, app.auth.GetExpiredRefreshCookie())
	w.WriteHeader(http.StatusAccepted)
}


func (app *application) MovieCatalog (w http.ResponseWriter, r *http.Request))