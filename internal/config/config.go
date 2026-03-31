package config

import "os"

type Config struct {
	DatabaseURL        string
	IssuerURL          string
	SessionSecret      string
	AdminEmail         string
	SMTPHost           string
	SMTPPort           string
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	GitHubClientID     string
	GitHubClientSecret string
	Port               string
}

func Load() *Config {
	return &Config{
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/sso?sslmode=disable"),
		IssuerURL:          getEnv("ISSUER_URL", "http://localhost:8080"),
		SessionSecret:      getEnv("SESSION_SECRET", "default-secret-change-me"),
		AdminEmail:         getEnv("ADMIN_EMAIL", ""),
		SMTPHost:           getEnv("SMTP_HOST", ""),
		SMTPPort:           getEnv("SMTP_PORT", "587"),
		SMTPUsername:       getEnv("SMTP_USERNAME", ""),
		SMTPPassword:       getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:           getEnv("SMTP_FROM", "noreply@example.com"),
		GitHubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		Port:               getEnv("PORT", "8080"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
