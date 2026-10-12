package auth

import "github.com/golang-jwt/jwt/v5"

func Subject(tokenString string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	return token.Claims.GetSubject()
}
