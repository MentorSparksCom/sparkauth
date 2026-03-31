package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"
	"gorm.io/gorm"

	"loginserver/internal/config"
	"loginserver/internal/crypto"
	"loginserver/internal/email"
	"loginserver/internal/middleware"
	"loginserver/internal/models"
	"loginserver/internal/render"
)

type LoginHandler struct {
	db       *gorm.DB
	cfg      *config.Config
	renderer *render.Renderer
	email    *email.Sender
}

func NewLoginHandler(db *gorm.DB, cfg *config.Config, renderer *render.Renderer, emailSender *email.Sender) *LoginHandler {
	return &LoginHandler{db: db, cfg: cfg, renderer: renderer, email: emailSender}
}

func (h *LoginHandler) githubOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.cfg.GitHubClientID,
		ClientSecret: h.cfg.GitHubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     githubOAuth.Endpoint,
		RedirectURL:  h.cfg.IssuerURL + "/login/github/callback",
	}
}

func (h *LoginHandler) LoginPage(c *gin.Context) {
	authRequestID := c.Query("auth_request_id")
	redirect := c.Query("redirect")

	// Check if already logged in
	session, _ := middleware.GetSession(h.db, c)
	if session != nil {
		if authRequestID != "" {
			c.Redirect(http.StatusFound, "/authorize?auth_request_id="+authRequestID)
			return
		}
		if redirect != "" && strings.HasPrefix(redirect, "/") {
			c.Redirect(http.StatusFound, redirect)
			return
		}
		c.Redirect(http.StatusFound, "/admin")
		return
	}

	appName := ""
	if authRequestID != "" {
		var authReq models.AuthRequest
		if err := h.db.First(&authReq, "id = ?", authRequestID).Error; err == nil {
			var app models.Application
			if err := h.db.Where("client_id = ?", authReq.ClientID).First(&app).Error; err == nil {
				appName = app.Name
			}
		}
	}

	githubEnabled := h.cfg.GitHubClientID != ""
	emailEnabled := true

	var settings []models.Setting
	h.db.Where("key IN ?", []string{"github_enabled", "email_enabled"}).Find(&settings)
	for _, s := range settings {
		switch s.Key {
		case "github_enabled":
			if s.Value == "false" {
				githubEnabled = false
			}
		case "email_enabled":
			if s.Value == "false" {
				emailEnabled = false
			}
		}
	}

	h.renderer.Render(c, http.StatusOK, "auth_login", gin.H{
		"AuthRequestID": authRequestID,
		"Redirect":      redirect,
		"AppName":       appName,
		"GitHubEnabled": githubEnabled,
		"EmailEnabled":  emailEnabled,
	})
}

func (h *LoginHandler) SendMagicLink(c *gin.Context) {
	emailAddr := strings.TrimSpace(c.PostForm("email"))
	authRequestID := c.PostForm("auth_request_id")
	redirect := c.PostForm("redirect")

	if emailAddr == "" {
		h.renderer.Render(c, http.StatusBadRequest, "auth_login", gin.H{
			"Error":         "Email address is required",
			"AuthRequestID": authRequestID,
			"Redirect":      redirect,
			"EmailEnabled":  true,
			"GitHubEnabled": h.cfg.GitHubClientID != "",
		})
		return
	}

	token := crypto.GenerateRandomString(32)
	magicLink := models.MagicLink{
		ID:            uuid.New().String(),
		Email:         emailAddr,
		Token:         token,
		AuthRequestID: authRequestID,
		Redirect:      redirect,
		ExpiresAt:     time.Now().Add(15 * time.Minute),
	}
	h.db.Create(&magicLink)

	link := fmt.Sprintf("%s/login/verify?token=%s", h.cfg.IssuerURL, token)
	if err := h.email.SendMagicLink(emailAddr, link); err != nil {
		h.renderer.Render(c, http.StatusInternalServerError, "auth_login", gin.H{
			"Error":         "Failed to send email. Please try again.",
			"AuthRequestID": authRequestID,
			"Redirect":      redirect,
			"EmailEnabled":  true,
			"GitHubEnabled": h.cfg.GitHubClientID != "",
		})
		return
	}

	h.renderer.Render(c, http.StatusOK, "auth_email_sent", gin.H{
		"Email": emailAddr,
	})
}

func (h *LoginHandler) VerifyMagicLink(c *gin.Context) {
	token := c.Query("token")

	var magicLink models.MagicLink
	if err := h.db.Where("token = ? AND used = false AND expires_at > ?", token, time.Now()).First(&magicLink).Error; err != nil {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Invalid or expired magic link. Please request a new one.",
		})
		return
	}

	h.db.Model(&magicLink).Update("used", true)

	var user models.User
	result := h.db.Where("email = ?", magicLink.Email).First(&user)
	if result.Error != nil {
		user = models.User{
			Email: magicLink.Email,
			Name:  strings.Split(magicLink.Email, "@")[0],
		}
		h.db.Create(&user)
	}

	h.createSessionAndRedirect(c, &user, magicLink.AuthRequestID, magicLink.Redirect)
}

func (h *LoginHandler) GitHubRedirect(c *gin.Context) {
	authRequestID := c.Query("auth_request_id")
	redirect := c.Query("redirect")

	if h.cfg.GitHubClientID == "" {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "GitHub login is not configured",
		})
		return
	}

	state := crypto.GenerateRandomString(16)
	oauthState := models.OAuthState{
		State:         state,
		AuthRequestID: authRequestID,
		Redirect:      redirect,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	h.db.Create(&oauthState)

	authURL := h.githubOAuthConfig().AuthCodeURL(state)
	c.Redirect(http.StatusFound, authURL)
}

func (h *LoginHandler) GitHubCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	var oauthState models.OAuthState
	if err := h.db.Where("state = ? AND expires_at > ?", state, time.Now()).First(&oauthState).Error; err != nil {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Invalid OAuth state. Please try again.",
		})
		return
	}
	h.db.Delete(&oauthState)

	token, err := h.githubOAuthConfig().Exchange(context.Background(), code)
	if err != nil {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Failed to exchange code with GitHub",
		})
		return
	}

	client := h.githubOAuthConfig().Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		h.renderer.Render(c, http.StatusInternalServerError, "auth_error", gin.H{
			"Error": "Failed to get user info from GitHub",
		})
		return
	}
	defer resp.Body.Close()

	var ghUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	json.NewDecoder(resp.Body).Decode(&ghUser)

	if ghUser.Email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err == nil {
			defer emailResp.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			json.NewDecoder(emailResp.Body).Decode(&emails)
			for _, e := range emails {
				if e.Primary && e.Verified {
					ghUser.Email = e.Email
					break
				}
			}
		}
	}

	if ghUser.Email == "" {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Could not get email from GitHub. Please ensure your email is public or verified.",
		})
		return
	}

	githubID := fmt.Sprintf("%d", ghUser.ID)
	var user models.User
	result := h.db.Where("github_id = ?", githubID).First(&user)
	if result.Error != nil {
		result = h.db.Where("email = ?", ghUser.Email).First(&user)
		if result.Error != nil {
			user = models.User{
				Email:     ghUser.Email,
				Name:      ghUser.Name,
				AvatarURL: ghUser.AvatarURL,
				GitHubID:  githubID,
			}
			h.db.Create(&user)
		} else {
			h.db.Model(&user).Updates(map[string]interface{}{
				"github_id":  githubID,
				"avatar_url": ghUser.AvatarURL,
				"name":       ghUser.Name,
			})
		}
	} else {
		h.db.Model(&user).Updates(map[string]interface{}{
			"avatar_url": ghUser.AvatarURL,
			"name":       ghUser.Name,
			"email":      ghUser.Email,
		})
	}

	h.createSessionAndRedirect(c, &user, oauthState.AuthRequestID, oauthState.Redirect)
}

func (h *LoginHandler) createSessionAndRedirect(c *gin.Context, user *models.User, authRequestID, redirect string) {
	sessionID := crypto.GenerateRandomString(32)
	session := models.Session{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	h.db.Create(&session)

	secure := strings.HasPrefix(h.cfg.IssuerURL, "https://")
	c.SetCookie(middleware.SessionCookie, sessionID, 86400, "/", "", secure, true)

	if authRequestID != "" {
		c.Redirect(http.StatusFound, "/authorize?auth_request_id="+authRequestID)
		return
	}
	if redirect != "" && strings.HasPrefix(redirect, "/") {
		c.Redirect(http.StatusFound, redirect)
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

func (h *LoginHandler) ConsentPage(c *gin.Context) {
	authRequestID := c.Query("auth_request_id")

	session, user := middleware.GetSession(h.db, c)
	if session == nil || user == nil {
		c.Redirect(http.StatusFound, "/login?auth_request_id="+authRequestID)
		return
	}

	var authReq models.AuthRequest
	if err := h.db.First(&authReq, "id = ?", authRequestID).Error; err != nil {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Invalid authorization request",
		})
		return
	}

	var app models.Application
	h.db.Where("client_id = ?", authReq.ClientID).First(&app)

	scopes := strings.Split(authReq.Scope, " ")
	scopeDescriptions := []map[string]string{}
	for _, s := range scopes {
		switch s {
		case "openid":
			scopeDescriptions = append(scopeDescriptions, map[string]string{"name": "OpenID", "description": "Verify your identity"})
		case "profile":
			scopeDescriptions = append(scopeDescriptions, map[string]string{"name": "Profile", "description": "Access your name and avatar"})
		case "email":
			scopeDescriptions = append(scopeDescriptions, map[string]string{"name": "Email", "description": "Access your email address"})
		}
	}

	csrfToken := middleware.GenerateCSRFToken(session.ID, h.cfg.SessionSecret)

	h.renderer.Render(c, http.StatusOK, "auth_consent", gin.H{
		"AppName":        app.Name,
		"AppDescription": app.Description,
		"Scopes":         scopeDescriptions,
		"AuthRequestID":  authRequestID,
		"UserEmail":      user.Email,
		"CSRFToken":      csrfToken,
	})
}

func (h *LoginHandler) ConsentSubmit(c *gin.Context) {
	authRequestID := c.PostForm("auth_request_id")
	csrfToken := c.PostForm("csrf_token")
	action := c.PostForm("action")

	session, _ := middleware.GetSession(h.db, c)
	if session == nil {
		c.Redirect(http.StatusFound, "/login?auth_request_id="+authRequestID)
		return
	}

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		h.renderer.Render(c, http.StatusForbidden, "auth_error", gin.H{
			"Error": "Invalid CSRF token. Please try again.",
		})
		return
	}

	var authReq models.AuthRequest
	if err := h.db.First(&authReq, "id = ?", authRequestID).Error; err != nil {
		h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
			"Error": "Invalid authorization request",
		})
		return
	}

	if action == "deny" {
		u, _ := url.Parse(authReq.RedirectURI)
		q := u.Query()
		q.Set("error", "access_denied")
		if authReq.State != "" {
			q.Set("state", authReq.State)
		}
		u.RawQuery = q.Encode()
		h.db.Delete(&authReq)
		c.Redirect(http.StatusFound, u.String())
		return
	}

	h.db.Model(&authReq).Update("approved", true)
	c.Redirect(http.StatusFound, "/authorize?auth_request_id="+authRequestID)
}

func (h *LoginHandler) Logout(c *gin.Context) {
	cookie, err := c.Cookie(middleware.SessionCookie)
	if err == nil && cookie != "" {
		h.db.Delete(&models.Session{}, "id = ?", cookie)
	}
	c.SetCookie(middleware.SessionCookie, "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}
