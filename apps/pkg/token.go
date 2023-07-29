package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type PayloadToken struct {
	AuthId  int
	Expired time.Time
}

const SecretKey = "secret"

func GenerateToken(tok *PayloadToken) (string, error) {
	tok.Expired = time.Now().Add(10 * 60 * time.Second)
	claims := jwt.MapClaims{
		"payload": tok,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokString string) (*PayloadToken, error) {
	tok, err := jwt.Parse(tokString, func(token *jwt.Token)(interface{}, error){
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %w", token.Header["alg"])
		}

		return SecretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("unauthorized")
	}
	payload := claims["payload"]
	var payloadToken = PayloadToken{}
	payloadByte, _ := json.Marshal(payload)
	err = json.Unmarshal(payloadByte, &payloadToken)
	if err != nil {
		return nil, err
	}
	// PayloadToken := payload.(PayloadToken)
	// if !ok {
	// 	return nil, errors.New("invalid payload type")
	// }

	return &payloadToken, nil
}