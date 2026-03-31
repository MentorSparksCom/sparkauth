package database

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"loginserver/internal/config"
	"loginserver/internal/models"
)

func Connect(cfg *config.Config) *gorm.DB {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.Application{},
		&models.Session{},
		&models.AuthRequest{},
		&models.AuthorizationCode{},
		&models.RefreshToken{},
		&models.MagicLink{},
		&models.OAuthState{},
		&models.KeyPair{},
		&models.Setting{},
	)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	if cfg.AdminEmail != "" {
		var user models.User
		result := db.Where("email = ?", cfg.AdminEmail).First(&user)
		if result.Error != nil {
			user = models.User{
				Email:   cfg.AdminEmail,
				Name:    "Admin",
				IsAdmin: true,
			}
			db.Create(&user)
			log.Printf("Created admin user: %s", cfg.AdminEmail)
		} else if !user.IsAdmin {
			db.Model(&user).Update("is_admin", true)
			log.Printf("Promoted existing user to admin: %s", cfg.AdminEmail)
		}
	}

	return db
}
