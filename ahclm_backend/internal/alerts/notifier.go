// Package alerts delivers certificate lifecycle notifications to logs, webhooks
// and email.
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"ahclm/internal/database"
	"ahclm/internal/models"
)

// Notifier dispatches alert payloads to the configured channels.
type Notifier struct {
	cfg    *models.AlertsConfig
	db     *database.Database
	client *http.Client
}

// NewNotifier creates a Notifier.
func NewNotifier(cfg *models.AlertsConfig, db *database.Database) *Notifier {
	return &Notifier{
		cfg:    cfg,
		db:     db,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Handle is wired as the scheduler's alert callback. It always logs, then
// fans out to webhook / email channels (best effort, non-blocking).
func (n *Notifier) Handle(p *models.WebhookPayload) {
	log.Printf("ALERT [%s] %s", p.Type, p.Message)
	if n.cfg == nil || !n.cfg.Enabled {
		return
	}

	// Global webhook.
	if n.cfg.WebhookEnabled && n.cfg.WebhookURL != "" {
		go n.sendWebhook(n.cfg.WebhookURL, p)
	}

	// Per-rule webhooks configured via the API.
	if n.db != nil {
		if rules, err := n.db.GetEnabledAlerts(); err == nil {
			for _, r := range rules {
				if r.WebhookURL != "" {
					go n.sendWebhook(r.WebhookURL, p)
				}
			}
		}
	}

	// Email.
	if n.cfg.SMTPHost != "" && n.cfg.EmailTo != "" && n.cfg.EmailFrom != "" {
		go n.sendEmail(p)
	}
}

func (n *Notifier) sendWebhook(url string, p *models.WebhookPayload) {
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("alert webhook %s failed: %v", url, err)
		return
	}
	resp.Body.Close()
}

func (n *Notifier) sendEmail(p *models.WebhookPayload) {
	addr := fmt.Sprintf("%s:%d", n.cfg.SMTPHost, n.cfg.SMTPPort)

	subject := fmt.Sprintf("[AHCLM] %s: %s", p.Type, p.Domain)
	msg := bytes.Buffer{}
	fmt.Fprintf(&msg, "From: %s\r\n", n.cfg.EmailFrom)
	fmt.Fprintf(&msg, "To: %s\r\n", n.cfg.EmailTo)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	fmt.Fprintf(&msg, "%s\r\n\r\n", p.Message)
	if p.Certificate != nil {
		fmt.Fprintf(&msg, "Domain:      %s\r\n", p.Domain)
		fmt.Fprintf(&msg, "Issuer:      %s\r\n", p.Certificate.Issuer)
		fmt.Fprintf(&msg, "Not After:   %s\r\n", p.Certificate.NotAfter.Format(time.RFC3339))
		fmt.Fprintf(&msg, "Fingerprint: %s\r\n", p.Certificate.Fingerprint)
	}
	if p.Milestone != "" {
		fmt.Fprintf(&msg, "Milestone:   %s\r\n", p.Milestone)
	}

	var auth smtp.Auth
	if n.cfg.EmailUser != "" {
		auth = smtp.PlainAuth("", n.cfg.EmailUser, n.cfg.EmailPassword, n.cfg.SMTPHost)
	}
	if err := smtp.SendMail(addr, auth, n.cfg.EmailFrom, []string{n.cfg.EmailTo}, msg.Bytes()); err != nil {
		log.Printf("alert email failed: %v", err)
	}
}
