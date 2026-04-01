package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"loginserver/internal/config"
	"loginserver/internal/crypto"
	"loginserver/internal/middleware"
	"loginserver/internal/models"
	"loginserver/internal/render"
)

type OIDCHandler struct {
	db       *gorm.DB
	cfg      *config.Config
	keys     *crypto.KeyManager
	renderer *render.Renderer
}

func NewOIDCHandler(db *gorm.DB, cfg *config.Config, keys *crypto.KeyManager, renderer *render.Renderer) *OIDCHandler {
	return &OIDCHandler{db: db, cfg: cfg, keys: keys, renderer: renderer}
}

func (h *OIDCHandler) Discovery(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                h.cfg.IssuerURL,
		"authorization_endpoint":                h.cfg.IssuerURL + "/authorize",
		"token_endpoint":                        h.cfg.IssuerURL + "/token",
		"userinfo_endpoint":                     h.cfg.IssuerURL + "/userinfo",
		"jwks_uri":                              h.cfg.IssuerURL + "/jwks",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	})
}

func (h *OIDCHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.keys.JWKS())
}

func (h *OIDCHandler) Authorize(c *gin.Context) {
	authRequestID := c.Query("auth_request_id")

	// Resume an existing auth request (user just logged in or returning from consent)
	if authRequestID != "" {
		var authReq models.AuthRequest
		if err := h.db.First(&authReq, "id = ? AND expires_at > ?", authRequestID, time.Now()).Error; err != nil {
			h.renderError(c, "Invalid or expired authorization request")
			return
		}

		session, user := middleware.GetSession(h.db, c)
		if session == nil || user == nil {
			c.Redirect(http.StatusFound, "/login?auth_request_id="+authRequestID)
			return
		}

		h.db.Model(&authReq).Update("session_id", session.ID)

		var app models.Application
		h.db.Where("client_id = ?", authReq.ClientID).First(&app)

		if app.Trusted || authReq.Approved {
			h.issueAuthorizationCode(c, &authReq, user)
			return
		}

		c.Redirect(http.StatusFound, "/consent?auth_request_id="+authRequestID)
		return
	}

	// New authorization request
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	prompt := c.Query("prompt")

	if responseType != "code" {
		h.renderError(c, "Unsupported response_type. Only 'code' is supported.")
		return
	}

	var app models.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		h.renderError(c, "Unknown client_id")
		return
	}

	validRedirect := false
	for _, uri := range app.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		h.renderError(c, "Invalid redirect_uri")
		return
	}

	authReq := models.AuthRequest{
		ID:                  uuid.New().String(),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Prompt:              prompt,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	h.db.Create(&authReq)

	// Check if prompt=login forces re-authentication
	if prompt == "login" {
		c.Redirect(http.StatusFound, "/login?auth_request_id="+authReq.ID)
		return
	}

	session, user := middleware.GetSession(h.db, c)
	if session != nil && user != nil {
		h.db.Model(&authReq).Update("session_id", session.ID)

		if app.Trusted {
			h.issueAuthorizationCode(c, &authReq, user)
			return
		}

		c.Redirect(http.StatusFound, "/consent?auth_request_id="+authReq.ID)
		return
	}

	c.Redirect(http.StatusFound, "/login?auth_request_id="+authReq.ID)
}

func (h *OIDCHandler) issueAuthorizationCode(c *gin.Context, authReq *models.AuthRequest, user *models.User) {
	code := crypto.GenerateRandomString(32)

	authCode := models.AuthorizationCode{
		ID:                  uuid.New().String(),
		Code:                code,
		ClientID:            authReq.ClientID,
		UserID:              user.ID,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
	h.db.Create(&authCode)

	h.db.Delete(&models.AuthRequest{}, "id = ?", authReq.ID)

	u, _ := url.Parse(authReq.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if authReq.State != "" {
		q.Set("state", authReq.State)
	}
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, u.String())
}

func (h *OIDCHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthCodeExchange(c)
	case "refresh_token":
		h.handleRefreshToken(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (h *OIDCHandler) getClientCredentials(c *gin.Context) (string, string) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if ok {
		return clientID, clientSecret
	}
	return c.PostForm("client_id"), c.PostForm("client_secret")
}

func (h *OIDCHandler) handleAuthCodeExchange(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")
	clientID, clientSecret := h.getClientCredentials(c)

	var authCode models.AuthorizationCode
	if err := h.db.Where("code = ? AND used = false AND expires_at > ?", code, time.Now()).First(&authCode).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
		return
	}

	h.db.Model(&authCode).Update("used", true)

	var app models.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if authCode.ClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Code was not issued to this client"})
		return
	}

	if authCode.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Redirect URI mismatch"})
		return
	}

	if authCode.CodeChallenge != "" {
		if !crypto.VerifyCodeChallenge(authCode.CodeChallengeMethod, authCode.CodeChallenge, codeVerifier) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid code_verifier"})
			return
		}
	} else {
		if app.ClientSecret != clientSecret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	var user models.User
	h.db.First(&user, authCode.UserID)

	h.issueTokens(c, &app, &user, authCode.Scope, authCode.Nonce)
}

func (h *OIDCHandler) handleRefreshToken(c *gin.Context) {
	refreshTokenStr := c.PostForm("refresh_token")
	clientID, clientSecret := h.getClientCredentials(c)

	var app models.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if app.ClientSecret != clientSecret {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	var refreshToken models.RefreshToken
	if err := h.db.Where("token = ? AND client_id = ? AND revoked = false AND expires_at > ?",
		refreshTokenStr, clientID, time.Now()).First(&refreshToken).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	h.db.Model(&refreshToken).Update("revoked", true)

	var user models.User
	h.db.First(&user, refreshToken.UserID)

	h.issueTokens(c, &app, &user, refreshToken.Scope, "")
}

func (h *OIDCHandler) issueTokens(c *gin.Context, app *models.Application, user *models.User, scope, nonce string) {
	now := time.Now()

	accessClaims := jwt.MapClaims{
		"iss":   h.cfg.IssuerURL,
		"sub":   fmt.Sprintf("%d", user.ID),
		"aud":   app.ClientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": scope,
	}

	accessToken, err := h.keys.SignAccessToken(accessClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	idClaims := jwt.MapClaims{
		"iss": h.cfg.IssuerURL,
		"sub": fmt.Sprintf("%d", user.ID),
		"aud": app.ClientID,
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
	}

	if nonce != "" {
		idClaims["nonce"] = nonce
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		switch s {
		case "profile":
			idClaims["name"] = user.Name
			idClaims["picture"] = user.AvatarURL
		case "email":
			idClaims["email"] = user.Email
			idClaims["email_verified"] = true
		}
	}

	idToken, err := h.keys.SignIDToken(idClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	refreshTokenStr := crypto.GenerateRandomString(32)
	refreshToken := models.RefreshToken{
		ID:        uuid.New().String(),
		Token:     refreshTokenStr,
		ClientID:  app.ClientID,
		UserID:    user.ID,
		Scope:     scope,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
	h.db.Create(&refreshToken)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idToken,
		"refresh_token": refreshTokenStr,
		"scope":         scope,
	})
}

func (h *OIDCHandler) UserInfo(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	tokenStr := strings.TrimPrefix(auth, "Bearer ")
	claims, err := h.keys.VerifyToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	var user models.User
	if err := h.db.Where("id = ?", sub).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}

	response := gin.H{
		"sub": fmt.Sprintf("%d", user.ID),
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		switch s {
		case "profile":
			response["name"] = user.Name
			response["picture"] = user.AvatarURL
		case "email":
			response["email"] = user.Email
			response["email_verified"] = true
		}
	}

	c.JSON(http.StatusOK, response)
}

func (h *OIDCHandler) renderError(c *gin.Context, message string) {
	h.renderer.Render(c, http.StatusBadRequest, "auth_error", gin.H{
		"Error": message,
	})
}
