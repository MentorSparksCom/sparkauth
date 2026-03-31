package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

// StringArray is a custom type for storing string slices as JSON text in PostgreSQL.
type StringArray []string

func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = StringArray{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return errors.New("failed to scan StringArray")
	}
	return json.Unmarshal(bytes, s)
}

type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Email     string         `gorm:"uniqueIndex;not null" json:"email"`
	Name      string         `json:"name"`
	AvatarURL string         `json:"avatar_url"`
	GitHubID  string         `gorm:"index" json:"github_id"`
	IsAdmin   bool           `gorm:"default:false" json:"is_admin"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Application struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	ClientID      string         `gorm:"uniqueIndex;not null" json:"client_id"`
	ClientSecret  string         `gorm:"not null" json:"-"`
	Name          string         `gorm:"not null" json:"name"`
	Description   string         `json:"description"`
	LogoURL       string         `json:"logo_url"`
	RedirectURIs  StringArray    `gorm:"type:text" json:"redirect_uris"`
	AllowedScopes string         `gorm:"default:'openid profile email'" json:"allowed_scopes"`
	Trusted       bool           `gorm:"default:false" json:"trusted"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

type Session struct {
	ID        string    `gorm:"primaryKey"`
	UserID    uint      `gorm:"index;not null"`
	User      User      `gorm:"foreignKey:UserID"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

type AuthRequest struct {
	ID                  string `gorm:"primaryKey"`
	ClientID            string `gorm:"not null"`
	RedirectURI         string `gorm:"not null"`
	ResponseType        string `gorm:"not null"`
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	Approved            bool `gorm:"default:false"`
	CreatedAt           time.Time
	ExpiresAt           time.Time `gorm:"not null"`
}

type AuthorizationCode struct {
	ID                  string `gorm:"primaryKey"`
	Code                string `gorm:"uniqueIndex;not null"`
	ClientID            string `gorm:"not null"`
	UserID              uint   `gorm:"not null"`
	RedirectURI         string `gorm:"not null"`
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Used                bool      `gorm:"default:false"`
	ExpiresAt           time.Time `gorm:"not null"`
	CreatedAt           time.Time
}

type RefreshToken struct {
	ID        string `gorm:"primaryKey"`
	Token     string `gorm:"uniqueIndex;not null"`
	ClientID  string `gorm:"not null"`
	UserID    uint   `gorm:"not null"`
	Scope     string
	Revoked   bool      `gorm:"default:false"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

type MagicLink struct {
	ID            string `gorm:"primaryKey"`
	Email         string `gorm:"not null"`
	Token         string `gorm:"uniqueIndex;not null"`
	AuthRequestID string
	Redirect      string
	Used          bool      `gorm:"default:false"`
	ExpiresAt     time.Time `gorm:"not null"`
	CreatedAt     time.Time
}

type OAuthState struct {
	State         string `gorm:"primaryKey"`
	AuthRequestID string
	Redirect      string
	ExpiresAt     time.Time `gorm:"not null"`
	CreatedAt     time.Time
}

type KeyPair struct {
	ID            string `gorm:"primaryKey"`
	PrivateKeyPEM string `gorm:"type:text;not null"`
	PublicKeyPEM  string `gorm:"type:text;not null"`
	Algorithm     string `gorm:"not null;default:'RS256'"`
	CreatedAt     time.Time
}

type Setting struct {
	Key   string `gorm:"primaryKey"`
	Value string `gorm:"type:text"`
}
