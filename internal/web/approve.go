package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/zitadel"
)

// approvable reports whether a browser session may be handed to a native app
// with an approval click: still valid, signed in (any factor) within
// NativeApprovalWindow, and its user usable with a verified email. It returns
// the user's email for the approval page.
func (s *Server) approvable(ctx context.Context, b *config.Brand, e browserSession) (string, bool) {
	sess, err := s.api.GetSession(ctx, instance(b), e.ID)
	if err != nil {
		return "", false
	}
	now := s.now()
	if sess.Expired(now) || sess.UserID() != e.UserID || now.Sub(sess.AuthTime()) > NativeApprovalWindow {
		return "", false
	}
	user, err := s.api.GetUser(ctx, instance(b), e.UserID)
	if err != nil || !user.Usable() || !user.Human.Email.IsVerified {
		return "", false
	}
	return strings.ToLower(user.Email()), true
}

func (s *Server) approveView(f *flow, b *config.Brand) view {
	return view{
		Title:       "Approve sign-in",
		Description: fmt.Sprintf("An app on this device wants to sign in to %s as %s.", b.Name, f.Email),
		CSRF:        f.CSRF, AuthRequest: f.AuthRequest, Email: f.Email,
	}
}

func (s *Server) handleApprovePage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.pageFlow(w, r, stepApprove)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "approve", s.approveView(f, brandOf(r)))
}

// handleApprove finalises the native app's auth request with the browser
// session the approval page named, after checking again that it is still
// recent enough: the page may have been left open past the window.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	f, ok := s.formFlow(w, r)
	if !ok {
		return
	}
	b := brandOf(r)
	if f.Step != stepApprove {
		s.toStep(w, r, f)
		return
	}
	e := browserSession{ID: f.SessionID, Token: f.SessionTok, UserID: f.UserID}
	if _, ok := s.approvable(r.Context(), b, e); !ok {
		n := newFlow(f.AuthRequest)
		n.CSRF, n.Native, n.Email = f.CSRF, f.Native, f.Email
		s.saveFlow(w, b, n)
		s.toStep(w, r, n)
		return
	}
	cb, err := s.api.FinalizeAuthRequest(r.Context(), instance(b), f.AuthRequest, f.SessionID, f.SessionTok)
	if err != nil || !safeCallback(cb) {
		if err != nil && zitadel.IsRejected(err) {
			s.dropFlow(w, b, f)
			s.expired(w, r, f.AuthRequest)
			return
		}
		s.failure(w, r, err, "finalize auth request")
		return
	}
	if f.Remember {
		cb = withRememberMe(cb)
	}
	s.dropFlow(w, b, f)
	http.Redirect(w, r, cb, http.StatusSeeOther)
}
