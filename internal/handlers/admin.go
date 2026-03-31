package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"loginserver/internal/config"
	"loginserver/internal/crypto"
	"loginserver/internal/middleware"
	"loginserver/internal/models"
	"loginserver/internal/render"
)

type AdminHandler struct {
	db       *gorm.DB
	cfg      *config.Config
	renderer *render.Renderer
}

func NewAdminHandler(db *gorm.DB, cfg *config.Config, renderer *render.Renderer) *AdminHandler {
	return &AdminHandler{db: db, cfg: cfg, renderer: renderer}
}

func (h *AdminHandler) csrfToken(c *gin.Context) string {
	session := c.MustGet("session").(*models.Session)
	return middleware.GenerateCSRFToken(session.ID, h.cfg.SessionSecret)
}

func (h *AdminHandler) Dashboard(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	var appCount, userCount int64
	h.db.Model(&models.Application{}).Count(&appCount)
	h.db.Model(&models.User{}).Count(&userCount)

	h.renderer.Render(c, http.StatusOK, "admin_dashboard", gin.H{
		"User":      user,
		"AppCount":  appCount,
		"UserCount": userCount,
		"IssuerURL": h.cfg.IssuerURL,
	})
}

func (h *AdminHandler) Applications(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	var apps []models.Application
	h.db.Order("created_at DESC").Find(&apps)

	h.renderer.Render(c, http.StatusOK, "admin_applications", gin.H{
		"User":         user,
		"Applications": apps,
		"CSRFToken":    h.csrfToken(c),
	})
}

func (h *AdminHandler) ApplicationNew(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	h.renderer.Render(c, http.StatusOK, "admin_application_form", gin.H{
		"User":      user,
		"IsNew":     true,
		"CSRFToken": h.csrfToken(c),
	})
}

func (h *AdminHandler) ApplicationCreate(c *gin.Context) {
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	description := strings.TrimSpace(c.PostForm("description"))
	redirectURIs := strings.TrimSpace(c.PostForm("redirect_uris"))
	trusted := c.PostForm("trusted") == "on"

	if name == "" {
		user := c.MustGet("user").(*models.User)
		h.renderer.Render(c, http.StatusBadRequest, "admin_application_form", gin.H{
			"User":      user,
			"IsNew":     true,
			"Error":     "Application name is required",
			"CSRFToken": h.csrfToken(c),
		})
		return
	}

	clientID := uuid.New().String()
	clientSecret := crypto.GenerateRandomString(32)

	uris := models.StringArray{}
	for _, uri := range strings.Split(redirectURIs, "\n") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			uris = append(uris, uri)
		}
	}

	app := models.Application{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         name,
		Description:  description,
		RedirectURIs: uris,
		Trusted:      trusted,
	}
	h.db.Create(&app)

	user := c.MustGet("user").(*models.User)
	h.renderer.Render(c, http.StatusOK, "admin_application_form", gin.H{
		"User":         user,
		"App":          app,
		"ClientSecret": clientSecret,
		"IsNew":        false,
		"JustCreated":  true,
		"Success":      "Application created! Copy the client secret now — it won't be shown again.",
		"RedirectURIs": strings.Join([]string(uris), "\n"),
		"CSRFToken":    h.csrfToken(c),
	})
}

func (h *AdminHandler) ApplicationEdit(c *gin.Context) {
	id := c.Param("id")
	user := c.MustGet("user").(*models.User)

	var app models.Application
	if err := h.db.First(&app, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/admin/applications")
		return
	}

	h.renderer.Render(c, http.StatusOK, "admin_application_form", gin.H{
		"User":         user,
		"App":          app,
		"IsNew":        false,
		"RedirectURIs": strings.Join([]string(app.RedirectURIs), "\n"),
		"CSRFToken":    h.csrfToken(c),
	})
}

func (h *AdminHandler) ApplicationUpdate(c *gin.Context) {
	id := c.Param("id")
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	var app models.Application
	if err := h.db.First(&app, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/admin/applications")
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	description := strings.TrimSpace(c.PostForm("description"))
	redirectURIs := strings.TrimSpace(c.PostForm("redirect_uris"))
	trusted := c.PostForm("trusted") == "on"

	uris := models.StringArray{}
	for _, uri := range strings.Split(redirectURIs, "\n") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			uris = append(uris, uri)
		}
	}

	app.Name = name
	app.Description = description
	app.RedirectURIs = uris
	app.Trusted = trusted
	h.db.Save(&app)

	user := c.MustGet("user").(*models.User)
	h.renderer.Render(c, http.StatusOK, "admin_application_form", gin.H{
		"User":         user,
		"App":          app,
		"IsNew":        false,
		"Success":      "Application updated successfully",
		"RedirectURIs": strings.Join([]string(uris), "\n"),
		"CSRFToken":    h.csrfToken(c),
	})
}

func (h *AdminHandler) ApplicationDelete(c *gin.Context) {
	id := c.Param("id")
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	h.db.Delete(&models.Application{}, id)
	c.Redirect(http.StatusFound, "/admin/applications")
}

func (h *AdminHandler) ApplicationRegenerateSecret(c *gin.Context) {
	id := c.Param("id")
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	newSecret := crypto.GenerateRandomString(32)
	h.db.Model(&models.Application{}).Where("id = ?", id).Update("client_secret", newSecret)

	var app models.Application
	h.db.First(&app, id)
	user := c.MustGet("user").(*models.User)

	h.renderer.Render(c, http.StatusOK, "admin_application_form", gin.H{
		"User":         user,
		"App":          app,
		"ClientSecret": newSecret,
		"IsNew":        false,
		"Success":      "Client secret regenerated. Copy it now — it won't be shown again!",
		"RedirectURIs": strings.Join([]string(app.RedirectURIs), "\n"),
		"CSRFToken":    h.csrfToken(c),
	})
}

func (h *AdminHandler) Users(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	var users []models.User
	h.db.Order("created_at DESC").Find(&users)

	h.renderer.Render(c, http.StatusOK, "admin_users", gin.H{
		"User":      user,
		"Users":     users,
		"CSRFToken": h.csrfToken(c),
	})
}

func (h *AdminHandler) ToggleAdmin(c *gin.Context) {
	id := c.Param("id")
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	var targetUser models.User
	if err := h.db.First(&targetUser, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/admin/users")
		return
	}

	h.db.Model(&targetUser).Update("is_admin", !targetUser.IsAdmin)
	c.Redirect(http.StatusFound, "/admin/users")
}

func (h *AdminHandler) Settings(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	settings := map[string]string{}
	var allSettings []models.Setting
	h.db.Find(&allSettings)
	for _, s := range allSettings {
		settings[s.Key] = s.Value
	}

	h.renderer.Render(c, http.StatusOK, "admin_settings", gin.H{
		"User":      user,
		"Settings":  settings,
		"Config":    h.cfg,
		"CSRFToken": h.csrfToken(c),
	})
}

func (h *AdminHandler) SettingsSave(c *gin.Context) {
	csrfToken := c.PostForm("csrf_token")
	session := c.MustGet("session").(*models.Session)

	if !middleware.ValidateCSRFToken(session.ID, h.cfg.SessionSecret, csrfToken) {
		c.String(http.StatusForbidden, "Invalid CSRF token")
		return
	}

	settingKeys := []string{
		"github_enabled", "github_client_id", "github_client_secret",
		"email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from",
	}

	for _, key := range settingKeys {
		value := c.PostForm(key)
		result := h.db.Model(&models.Setting{}).Where("key = ?", key).Update("value", value)
		if result.RowsAffected == 0 {
			h.db.Create(&models.Setting{Key: key, Value: value})
		}
	}

	// Update runtime config from saved settings
	if v := c.PostForm("github_client_id"); v != "" {
		h.cfg.GitHubClientID = v
	}
	if v := c.PostForm("github_client_secret"); v != "" {
		h.cfg.GitHubClientSecret = v
	}
	if v := c.PostForm("smtp_host"); v != "" {
		h.cfg.SMTPHost = v
	}
	if v := c.PostForm("smtp_port"); v != "" {
		h.cfg.SMTPPort = v
	}
	if v := c.PostForm("smtp_username"); v != "" {
		h.cfg.SMTPUsername = v
	}
	if v := c.PostForm("smtp_password"); v != "" {
		h.cfg.SMTPPassword = v
	}
	if v := c.PostForm("smtp_from"); v != "" {
		h.cfg.SMTPFrom = v
	}

	user := c.MustGet("user").(*models.User)

	settings := map[string]string{}
	var allSettings []models.Setting
	h.db.Find(&allSettings)
	for _, s := range allSettings {
		settings[s.Key] = s.Value
	}

	h.renderer.Render(c, http.StatusOK, "admin_settings", gin.H{
		"User":      user,
		"Settings":  settings,
		"Config":    h.cfg,
		"CSRFToken": h.csrfToken(c),
		"Success":   "Settings saved successfully",
	})
}
