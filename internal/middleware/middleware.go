package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"loginserver/internal/models"
)

const SessionCookie = "sso_session"

func GetSession(db *gorm.DB, c *gin.Context) (*models.Session, *models.User) {
	cookie, err := c.Cookie(SessionCookie)
	if err != nil || cookie == "" {
		return nil, nil
	}

	var session models.Session
	result := db.Preload("User").Where("id = ? AND expires_at > ?", cookie, time.Now()).First(&session)
	if result.Error != nil {
		return nil, nil
	}

	return &session, &session.User
}

func RequireAdmin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, user := GetSession(db, c)
		if session == nil || user == nil {
			c.Redirect(http.StatusFound, "/login?redirect=/admin")
			c.Abort()
			return
		}
		if !user.IsAdmin {
			c.String(http.StatusForbidden, "Access denied: admin privileges required")
			c.Abort()
			return
		}
		c.Set("session", session)
		c.Set("user", user)
		c.Next()
	}
}

func GenerateCSRFToken(sessionID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

func ValidateCSRFToken(sessionID, secret, token string) bool {
	expected := GenerateCSRFToken(sessionID, secret)
	return hmac.Equal([]byte(expected), []byte(token))
}
