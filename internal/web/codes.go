package web

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/mailer"
)

var mailHTML = template.Must(template.New("mail").Parse(`<!doctype html>
<html lang="en"><body style="margin:0;padding:32px 16px;background:#0a0a0a;color:#f5f5f4;font-family:ui-sans-serif,system-ui,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="440" cellpadding="0" cellspacing="0" style="max-width:440px;border:1px solid #2b2b2b;border-radius:16px;background:#151515">
<tr><td style="padding:28px 28px 8px;font-size:20px;font-weight:650">{{.Brand}}</td></tr>
<tr><td style="padding:8px 28px;font-size:15px;line-height:1.55;color:#d6d6d4">{{.Lead}}</td></tr>
<tr><td style="padding:16px 28px"><div style="font-size:30px;font-weight:700;letter-spacing:8px;font-variant-numeric:tabular-nums">{{.Code}}</div></td></tr>
<tr><td style="padding:8px 28px 28px;font-size:13px;line-height:1.5;color:#a3a3a1">{{.Foot}}</td></tr>
</table></td></tr></table></body></html>`))

// codeMessage builds the branded email for a code.
func codeMessage(b *config.Brand, kind, to, code string) mailer.Message {
	minutes := int(CodeTTL.Minutes())
	subject := b.MailSubject(kindSignin, "Your {name} sign-in code")
	lead := "Your " + b.Name + " sign-in code is below."
	foot := fmt.Sprintf("It works once and expires in %d minutes. If you did not try to sign in, ignore this email.", minutes)
	switch kind {
	case kindSignup:
		subject = b.MailSubject(kindSignup, "Your {name} code")
		lead = "Use this code to create your " + b.Name + " account."
		foot = fmt.Sprintf("It works once and expires in %d minutes. If you did not ask for an account, ignore this email.", minutes)
	case kindReset:
		subject = b.MailSubject(kindReset, "Reset your {name} password")
		lead = "Use this code to choose a new " + b.Name + " password."
		foot = fmt.Sprintf("It works once and expires in %d minutes. If you did not ask to reset your password, ignore this email; your password stays the same.", minutes)
	case kindVerify:
		subject = b.MailSubject(kindVerify, "Confirm your email for {name}")
		lead = "Use this code to confirm your email address."
		foot = fmt.Sprintf("It works once and expires in %d minutes. If you did not try to sign in, ignore this email.", minutes)
	}
	text := fmt.Sprintf("%s\n\n    %s\n\n%s\n", lead, code, foot)
	var html bytes.Buffer
	_ = mailHTML.Execute(&html, map[string]string{"Brand": b.Name, "Lead": lead, "Code": code, "Foot": foot})
	return mailer.Message{From: b.MailFrom, To: to, Subject: subject, Text: text, HTML: html.String(), Kind: kind}
}
