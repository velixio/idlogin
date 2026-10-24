// Package setup holds the idempotent instance setup the login service needs
// besides what steps.yaml creates: the preaccesstoken action target and
// execution, and the OIDC token lifetimes. Run with an IAM owner token
// (the provisioner PAT), e.g. from scripts/dev-up.sh:
//
//	idlogin setup -pat-file $IDLOGIN_DEV_HOME/secrets/provisioner.pat -actions-endpoint http://localhost:8091/login/zitadel/preaccesstoken \
//	  -actions-key-file $IDLOGIN_DEV_HOME/secrets/login-actions.key
package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/velixio/idlogin/internal/zitadel"
)

// TargetName is the name of the action target this service registers.
const TargetName = "idlogin-preaccesstoken"

// Options for Run.
type Options struct {
	Client          *zitadel.Client
	Instance        zitadel.Instance // Host + IAM owner token
	ActionsEndpoint string           // "" skips the action setup
	ActionsKeyFile  string
	OIDCSettings    bool // apply the token lifetimes below
	Log             func(format string, args ...any)
}

// Token lifetimes (also DefaultInstance.OIDCSettings in deploy/zitadel/zitadel.yaml).
const (
	AccessTokenLifetime        = "300s"     // 5m
	IDTokenLifetime            = "3600s"    // 1h
	RefreshTokenIdleExpiration = "2592000s" // 720h
	RefreshTokenExpiration     = "7776000s" // 2160h
)

// Run applies the setup. Safe to repeat.
func Run(ctx context.Context, o Options) error {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.OIDCSettings {
		err := o.Client.Call(ctx, o.Instance, http.MethodPut, "/admin/v1/settings/oidc", map[string]string{
			"accessTokenLifetime": AccessTokenLifetime, "idTokenLifetime": IDTokenLifetime,
			"refreshTokenIdleExpiration": RefreshTokenIdleExpiration, "refreshTokenExpiration": RefreshTokenExpiration,
		}, nil)
		if err != nil && !strings.Contains(err.Error(), "No changes") && !strings.Contains(err.Error(), "COMMAND-8k2fs") {
			return fmt.Errorf("oidc settings: %w", err)
		}
		o.Log("oidc settings: access 5m, id 1h, refresh idle 720h, refresh 2160h")
	}
	if o.ActionsEndpoint == "" {
		return nil
	}
	return actions(ctx, o)
}

func actions(ctx context.Context, o Options) error {
	var found struct {
		Targets []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Endpoint string `json:"endpoint"`
		} `json:"targets"`
	}
	if err := o.Client.Call(ctx, o.Instance, http.MethodPost, "/v2/actions/targets/search", map[string]any{
		"filters": []any{map[string]any{"targetNameFilter": map[string]string{"targetName": TargetName, "method": "TEXT_FILTER_METHOD_EQUALS"}}},
	}, &found); err != nil {
		return fmt.Errorf("search targets: %w", err)
	}
	var id string
	for _, t := range found.Targets {
		if t.Name == TargetName {
			id = t.ID
		}
	}
	key := ""
	if b, err := os.ReadFile(o.ActionsKeyFile); err == nil {
		key = strings.TrimSpace(string(b))
	}
	body := map[string]any{
		"name":        TargetName,
		"restCall":    map[string]any{"interruptOnError": false},
		"endpoint":    o.ActionsEndpoint,
		"timeout":     "5s",
		"payloadType": "PAYLOAD_TYPE_JSON",
	}
	var out struct {
		ID         string `json:"id"`
		SigningKey string `json:"signingKey"`
	}
	switch {
	case id == "":
		if err := o.Client.Call(ctx, o.Instance, http.MethodPost, "/v2/actions/targets", body, &out); err != nil {
			return fmt.Errorf("create target: %w", err)
		}
		id = out.ID
		o.Log("action target %s created", id)
	default:
		if key == "" {
			// We lost the key: have Zitadel issue a new one now.
			body["expirationSigningKey"] = "0s"
		}
		err := o.Client.Call(ctx, o.Instance, http.MethodPost, "/v2/actions/targets/"+id, body, &out)
		if err != nil && !strings.Contains(err.Error(), "No changes") {
			return fmt.Errorf("update target: %w", err)
		}
	}
	if out.SigningKey != "" {
		if err := writeKey(o.ActionsKeyFile, out.SigningKey); err != nil {
			return err
		}
		o.Log("action signing key written to %s", o.ActionsKeyFile)
	} else if key == "" {
		return errors.New("zitadel returned no signing key for the action target")
	}
	if err := o.Client.Call(ctx, o.Instance, http.MethodPut, "/v2/actions/executions", map[string]any{
		"condition": map[string]any{"function": map[string]string{"name": "preaccesstoken"}},
		"targets":   []string{id},
	}, nil); err != nil {
		return fmt.Errorf("set execution: %w", err)
	}
	o.Log("execution function/preaccesstoken -> %s (%s)", TargetName, o.ActionsEndpoint)
	return nil
}

func writeKey(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(key+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
