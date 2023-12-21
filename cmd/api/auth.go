package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Auth struct {
	Issuer      string
	Audience    string
	Secret      string
	TokenExpiry time.Duration
	// not part of JWT standard
	RefreshExpiry time.Duration
	CookieDomain  string
	CookiePath    string
	CookieName    string
}

type JWTUser struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type TokenPairs struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	jwt.RegisteredClaims
}

func (j *Auth) GenerateTokenPair(user *JWTUser) (TokenPairs, error) {
	// create a token
	token := jwt.New(jwt.SigningMethodHS256)

	// set the claims
	claims := token.Claims.(jwt.MapClaims) // cast to jwt.MapClaims
	claims["name"] = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	claims["sub"] = fmt.Sprint(user.ID)
	claims["aud"] = j.Audience
	claims["iss"] = j.Issuer
	claims["iat"] = time.Now().UTC().Unix()
	claims["type"] = "JWT"

	// set the expiry for jwt token - short time
	claims["exp"] = time.Now().UTC().Add(j.TokenExpiry).Unix()

	// create a signed token
	signedAccessToken, err := token.SignedString([]byte(j.Secret))
	if err != nil {
		return TokenPairs{}, err
	}

	// create a refresh token and set claims
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshTokenClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshTokenClaims["sub"] = fmt.Sprint(user.ID)
	refreshTokenClaims["iat"] = time.Now().UTC().Unix()

	// set the expiry for the refresh token - long time
	refreshTokenClaims["exp"] = time.Now().UTC().Add(j.RefreshExpiry).Unix()

	// create signed refresh token
	signedRefreshToken, err := refreshToken.SignedString([]byte(j.Secret))
	if err != nil {
		return TokenPairs{}, err
	}

	// create token pairs and populate it
	tokenPairs := TokenPairs{
		Token:        signedAccessToken,
		RefreshToken: signedRefreshToken,
	}

	// return token pairs
	return tokenPairs, nil
}

// GetRefreshCookie - creates a refresh cookie based on refresh token
func (j *Auth) GetRefreshCookie(refreshToken string) *http.Cookie {
	return &http.Cookie{
		Name:     j.CookieName,
		Path:     j.CookiePath,
		Value:    refreshToken,
		Expires:  time.Now().Add(j.RefreshExpiry),
		MaxAge:   int(j.RefreshExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode, // cookie limited only to this site
		Domain:   j.CookieDomain,
		HttpOnly: true, // JS won't he able to access this cookie in browser
		Secure:   true, // secure cookie in production
	}
}

// GetExpiredRefreshCookie - delete a cookie
func (j *Auth) GetExpiredRefreshCookie() *http.Cookie {
	return &http.Cookie{
		Name:     j.CookieName,
		Path:     j.CookiePath,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode, // cookie limited only to this site
		Domain:   j.CookieDomain,
		HttpOnly: true, // JS won't he able to access this cookie in browser
		Secure:   true, // secure cookie in production
	}
}

func (j *Auth) GetTokenFromHeader(w http.ResponseWriter, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return "", errors.New("No auth header")
	}

	// Bearer <token>
	headerParts := strings.Split(authHeader, " ")
	if len(headerParts) != 2 {
		return "", errors.New("Invalid auth header")
	}

	if headerParts[0] != "Bearer" {
		return "", errors.New("Invalid auth header")
	}

	return headerParts[1], nil
}

func (j *Auth) VerifyToken(w http.ResponseWriter, r *http.Request) (string, *Claims, error) {
	w.Header().Add("Vary", "Authorization")

	token, err := j.GetTokenFromHeader(w, r)
	if err != nil {
		return "", nil, err
	}

	claims := &Claims{}

	_, parseError := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(j.Secret), nil
	})

	if parseError != nil {
		if strings.HasPrefix(err.Error(), "token is expired by") {
			return "", nil, errors.New("Expired token")
		}

		return "", nil, parseError
	}

	if claims.Issuer != j.Issuer {
		return "", nil, errors.New("Invalid issuer")
	}

	return token, claims, nil

}
