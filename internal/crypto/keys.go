package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"loginserver/internal/models"
)

type KeyManager struct {
	db         *gorm.DB
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

func NewKeyManager(db *gorm.DB) *KeyManager {
	km := &KeyManager{db: db}
	km.loadOrGenerateKey()
	return km
}

func (km *KeyManager) loadOrGenerateKey() {
	var kp models.KeyPair
	result := km.db.Order("created_at DESC").First(&kp)

	if result.Error != nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
		}

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			panic(fmt.Sprintf("Failed to marshal public key: %v", err))
		}
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		kp = models.KeyPair{
			ID:            uuid.New().String(),
			PrivateKeyPEM: string(privateKeyPEM),
			PublicKeyPEM:  string(publicKeyPEM),
			Algorithm:     "RS256",
			CreatedAt:     time.Now(),
		}
		km.db.Create(&kp)

		km.privateKey = privateKey
		km.publicKey = &privateKey.PublicKey
		km.keyID = kp.ID
	} else {
		block, _ := pem.Decode([]byte(kp.PrivateKeyPEM))
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse private key: %v", err))
		}

		km.privateKey = privateKey
		km.publicKey = &privateKey.PublicKey
		km.keyID = kp.ID
	}
}

func (km *KeyManager) SignIDToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = km.keyID
	return token.SignedString(km.privateKey)
}

func (km *KeyManager) SignAccessToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = km.keyID
	return token.SignedString(km.privateKey)
}

func (km *KeyManager) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return km.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func (km *KeyManager) JWKS() map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": km.keyID,
				"n":   base64.RawURLEncoding.EncodeToString(km.publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(km.publicKey.E)).Bytes()),
			},
		},
	}
}

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func VerifyCodeChallenge(method, challenge, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain", "":
		return challenge == verifier
	default:
		return false
	}
}
