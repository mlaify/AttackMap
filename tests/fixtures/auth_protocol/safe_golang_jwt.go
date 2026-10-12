package auth

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var publicKey = mustLoad(os.Getenv("JWT_PUBLIC_KEY"))

func Check(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return publicKey, nil
	})
}

func CheckPinned(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	return publicKey, nil
}
