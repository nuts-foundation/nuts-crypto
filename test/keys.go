package test

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenerateRSAKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return privateKey
}