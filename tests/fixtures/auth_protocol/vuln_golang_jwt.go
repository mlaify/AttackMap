package auth

import (
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("my_secret_key")

func Check(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return os.ReadFile("keys/" + t.Header["kid"].(string) + ".pem")
	})
}

func Lenient(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, keyFunc, jwt.WithoutClaimsValidation())
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	return jwtKey, nil
}
