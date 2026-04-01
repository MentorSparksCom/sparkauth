package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"loginserver/internal/config"
	"loginserver/internal/crypto"
	"loginserver/internal/database"
	"loginserver/internal/email"
	"loginserver/internal/handlers"
	"loginserver/internal/middleware"
	"loginserver/internal/render"
)

func main() {
	_ = godotenv.Load() // load .env if present
	cfg := config.Load()
	db := database.Connect(cfg)
	keys := crypto.NewKeyManager(db)
	emailSender := email.NewSender(cfg)

	// Template renderer
	renderer := render.New()

	// Admin templates (admin layout + page)
	renderer.Add("admin_dashboard", "templates/admin/layout.html", "templates/admin/dashboard.html")
	renderer.Add("admin_applications", "templates/admin/layout.html", "templates/admin/applications.html")
	renderer.Add("admin_application_form", "templates/admin/layout.html", "templates/admin/application_form.html")
	renderer.Add("admin_users", "templates/admin/layout.html", "templates/admin/users.html")
	renderer.Add("admin_settings", "templates/admin/layout.html", "templates/admin/settings.html")

	// Auth templates (auth layout + page)
	renderer.Add("auth_login", "templates/auth/layout.html", "templates/auth/login.html")
	renderer.Add("auth_email_sent", "templates/auth/layout.html", "templates/auth/email_sent.html")
	renderer.Add("auth_consent", "templates/auth/layout.html", "templates/auth/consent.html")
	renderer.Add("auth_error", "templates/auth/layout.html", "templates/auth/error.html")

	// Handlers
	oidcHandler := handlers.NewOIDCHandler(db, cfg, keys, renderer)
	loginHandler := handlers.NewLoginHandler(db, cfg, renderer, emailSender)
	adminHandler := handlers.NewAdminHandler(db, cfg, renderer)

	// Router
	r := gin.Default()
	r.Static("/static", "./static")

	// OIDC endpoints
	r.GET("/.well-known/openid-configuration", oidcHandler.Discovery)
	r.GET("/jwks", oidcHandler.JWKS)
	r.GET("/authorize", oidcHandler.Authorize)
	r.POST("/token", oidcHandler.Token)
	r.GET("/userinfo", oidcHandler.UserInfo)
	r.POST("/userinfo", oidcHandler.UserInfo)

	// Login & consent
	r.GET("/login", loginHandler.LoginPage)
	r.POST("/login/email", loginHandler.SendMagicLink)
	r.GET("/login/verify", loginHandler.VerifyMagicLink)
	r.GET("/login/github", loginHandler.GitHubRedirect)
	r.GET("/login/github/callback", loginHandler.GitHubCallback)
	r.GET("/consent", loginHandler.ConsentPage)
	r.POST("/consent", loginHandler.ConsentSubmit)
	r.GET("/logout", loginHandler.Logout)

	// Admin (protected)
	admin := r.Group("/admin")
	admin.Use(middleware.RequireAdmin(db))
	{
		admin.GET("", adminHandler.Dashboard)
		admin.GET("/applications", adminHandler.Applications)
		admin.GET("/applications/new", adminHandler.ApplicationNew)
		admin.POST("/applications", adminHandler.ApplicationCreate)
		admin.GET("/applications/:id", adminHandler.ApplicationEdit)
		admin.POST("/applications/:id", adminHandler.ApplicationUpdate)
		admin.POST("/applications/:id/delete", adminHandler.ApplicationDelete)
		admin.POST("/applications/:id/regenerate-secret", adminHandler.ApplicationRegenerateSecret)
		admin.GET("/users", adminHandler.Users)
		admin.POST("/users/:id/toggle-admin", adminHandler.ToggleAdmin)
		admin.GET("/settings", adminHandler.Settings)
		admin.POST("/settings", adminHandler.SettingsSave)
	}

	log.Printf("SparkAuth starting on :%s", cfg.Port)
	log.Printf("Issuer URL: %s", cfg.IssuerURL)
	log.Printf("Discovery:  %s/.well-known/openid-configuration", cfg.IssuerURL)

	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
