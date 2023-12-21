package repository

import (
	"database/sql"
	"movies/internal/models"
)

type DatabaseRepo interface {
	AllMovies() ([]*models.Movie, error)
	Connection() *sql.DB
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(id int) (*models.User, error)
}
