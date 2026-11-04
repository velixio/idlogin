package web

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/mailer"
)

// mailHTML is built for a phone first and for mail clients that drop the
// stylesheet: it fills the screen on one dark surface, the media query only adds
// the framed card on a wide screen, and nothing is loaded from a remote server.
var mailHTML = template.Must(template.New("mail").Funcs(template.FuncMap{
	"outlookOpen": func() template.HTML {
		return `<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`
	},
	"outlookClose": func() template.HTML { return `<!--[if mso]></td></tr></table><![endif]-->` },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="format-detection" content="telephone=no,date=no,address=no,email=no">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<title>{{.Subject}}</title>
<style>
:root { color-scheme: dark; }
html, body { width: 100% !important; height: 100%; margin: 0 !important; padding: 0 !important; }
body { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
@media (min-width: 640px) {
  .page { padding: 36px 12px !important; }
  .head { padding: 0 4px 18px 4px !important; }
  .card { background-color: #141414 !important; border: 1px solid #2b2b2b !important; border-radius: 16px !important; padding: 36px !important; }
  .foot { padding: 18px 4px 0 4px !important; }
}
</style>
</head>
<body bgcolor="#0a0a0a" style="margin:0;padding:0;width:100%;background-color:#0a0a0a;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">{{.Preheader}}</div>
<div style="min-height:100vh;background-color:#0a0a0a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0a0a0a" style="width:100%;background-color:#0a0a0a;">
<tr><td align="center" valign="top" class="page" style="padding:0;">
{{outlookOpen}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;table-layout:fixed;">
<tr><td class="head" style="padding:20px 20px 14px 20px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
{{if .LogoID}}<td width="32" valign="middle" style="padding:0 10px 0 0;"><img src="cid:{{.LogoID}}" width="32" height="32" alt="" border="0" style="display:block;width:32px;height:32px;border:0;outline:none;text-decoration:none;"></td>
{{end}}<td valign="middle" style="font-family:Fraunces,'Iowan Old Style','Apple Garamond',Baskerville,Georgia,'Times New Roman',serif;font-size:20px;line-height:1.2;font-weight:600;letter-spacing:-0.3px;color:#f5f5f4;">{{.Brand}}</td>
</tr></table></td></tr>
<tr><td class="card" style="border-top:2px solid {{.Accent}};padding:24px 20px;font-family:Geist,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.6;color:#f5f5f4;">
<p style="margin:0 0 20px 0;">{{.Lead}}</p>
<div style="margin:0 0 20px 0;padding:18px 12px;background-color:#1c1c1c;border-radius:12px;text-align:center;font-family:'Geist Mono','SF Mono',Menlo,Consolas,'Liberation Mono',monospace;font-size:32px;line-height:1.2;font-weight:700;letter-spacing:8px;color:{{.Accent}};">{{.Code}}</div>
<p style="margin:0;font-size:14px;line-height:1.55;color:#a3a3a1;">{{.Foot}}</p>
</td></tr>
{{if or .Footer .Links}}<tr><td class="foot" style="padding:12px 20px 28px 20px;font-family:Geist,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:#8a8a88;">
{{if .Footer}}<p style="margin:0 0 6px 0;">{{.Footer}}</p>{{end}}
{{if .Links}}<p style="margin:0;">{{range $i, $l := .Links}}{{if $i}} &middot; {{end}}<a href="{{$l.URL}}" style="color:#8a8a88;text-decoration:underline;">{{$l.Label}}</a>{{end}}</p>{{end}}
</td></tr>{{end}}
</table>{{outlookClose}}
</td></tr>
</table>
</div>
</body>
</html>
`))

// mailLogoID names the logo inside a message; it is not a URL anyone can reach.
const mailLogoID = "logo@idlogin"

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
	if b.MailFooter != "" {
		text += "\n" + b.MailFooter + "\n"
	}
	accent := b.MailAccent
	if accent == "" {
		accent = "#ffffff"
	}
	message := mailer.Message{From: b.MailFrom, To: to, Subject: subject, Text: text, Kind: kind}
	logoID := ""
	if len(b.MailLogo) > 0 {
		logoID = mailLogoID
		message.Inline = []mailer.Inline{{ContentID: logoID, ContentType: b.MailLogoType, Data: b.MailLogo}}
	}
	var html bytes.Buffer
	_ = mailHTML.Execute(&html, struct {
		Subject, Preheader, Brand, Lead, Code, Foot, Accent, LogoID, Footer string
		Links                                                               []config.MailLink
	}{subject, lead, b.Name, lead, code, foot, accent, logoID, b.MailFooter, b.MailLinks})
	message.HTML = html.String()
	return message
}
