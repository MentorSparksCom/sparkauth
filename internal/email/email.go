package email

import (
	"fmt"
	"net/smtp"

	"loginserver/internal/config"
)

type Sender struct {
	cfg *config.Config
}

func NewSender(cfg *config.Config) *Sender {
	return &Sender{cfg: cfg}
}

func (s *Sender) SendMagicLink(to, link string) error {
	if s.cfg.SMTPHost == "" {
		fmt.Printf("\n========== MAGIC LINK ==========\n")
		fmt.Printf("To:   %s\n", to)
		fmt.Printf("Link: %s\n", link)
		fmt.Printf("================================\n\n")
		return nil
	}

	subject := "Sign in to your account"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family: 'Manrope', sans-serif; padding: 40px; background: #111827; color: #F9FAFB;">
<div style="max-width: 480px; margin: 0 auto; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px;">
    <h2 style="margin: 0 0 16px 0;">Sign in to your account</h2>
    <p style="color: #D1D5DB;">Click the button below to sign in. This link expires in 15 minutes.</p>
    <p style="text-align: center; margin: 30px 0;">
        <a href="%s" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #C850C0, #4158D0); color: white; text-decoration: none; border-radius: 10px; font-weight: 700;">Sign In</a>
    </p>
    <p style="color: #6B7280; font-size: 13px;">If you didn't request this link, you can safely ignore this email.</p>
</div>
</body></html>`, link)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.cfg.SMTPFrom, to, subject, body)

	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)

	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg))
}
