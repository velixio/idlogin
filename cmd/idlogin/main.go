// Command idlogin is the customer-facing sign-in service in front of Zitadel
// (docs/idlogin.md).
//
//	idlogin            serve (configured by LOGIN_* environment variables)
//	idlogin setup ...  idempotent instance setup (action target, token lifetimes)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/velixio/idlogin/internal/actions"
	"github.com/velixio/idlogin/internal/config"
	"github.com/velixio/idlogin/internal/mailer"
	"github.com/velixio/idlogin/internal/setup"
	"github.com/velixio/idlogin/internal/store"
	"github.com/velixio/idlogin/internal/web"
	"github.com/velixio/idlogin/internal/zitadel"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := runSetup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "login setup:", err)
			os.Exit(1)
		}
		return
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "login:", err)
		os.Exit(1)
	}
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	api := fs.String("zitadel", envOr("LOGIN_ZITADEL_URL", "http://127.0.0.1:8090"), "Zitadel API base URL")
	host := fs.String("instance-host", "", "instance host (x-zitadel-instance-host), e.g. id.example.com; default: host of -zitadel")
	patFile := fs.String("pat-file", "", "IAM owner token file (provisioner.pat)")
	endpoint := fs.String("actions-endpoint", "", "URL Zitadel calls for function preaccesstoken (empty: skip)")
	keyFile := fs.String("actions-key-file", os.Getenv("LOGIN_ACTIONS_SIGNING_KEY_FILE"), "where the target's signing key is kept")
	oidc := fs.Bool("oidc-settings", true, "apply the OIDC token lifetimes")
	_ = fs.Parse(args)
	if *patFile == "" {
		return errors.New("-pat-file is required")
	}
	if *endpoint != "" && *keyFile == "" {
		return errors.New("-actions-key-file is required with -actions-endpoint")
	}
	pat, err := os.ReadFile(*patFile)
	if err != nil {
		return err
	}
	if *host == "" {
		*host = strings.TrimPrefix(strings.TrimPrefix(*api, "http://"), "https://")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return setup.Run(ctx, setup.Options{
		Client: zitadel.New(*api), Instance: zitadel.Instance{Host: *host, Token: strings.TrimSpace(string(pat))},
		ActionsEndpoint: *endpoint, ActionsKeyFile: *keyFile, OIDCSettings: *oidc,
		Log: func(f string, a ...any) { fmt.Printf("setup: "+f+"\n", a...) },
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func serve() error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	brands, err := config.LoadBrands(cfg.BrandsFile)
	if err != nil {
		return err
	}
	var current atomic.Pointer[config.Brands]
	current.Store(brands)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pcfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("LOGIN_DATABASE_URL: %w", err)
	}
	if cfg.DatabasePassword != "" {
		pcfg.ConnConfig.Password = cfg.DatabasePassword
	}
	pcfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	st := store.NewPG(pool)

	var m mailer.Mailer
	switch cfg.Mailer {
	case "smtp":
		m = &mailer.SMTP{Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Password: cfg.SMTPPassword, TLS: cfg.SMTPTLS}
	default:
		m = &mailer.Log{Dir: cfg.MailDir}
	}

	srv, err := web.New(web.Options{
		Brands: current.Load, API: zitadel.New(cfg.ZitadelURL), Store: st, Mailer: m,
		CookieKey: cfg.CookieKey, TrustProxy: cfg.TrustProxy, Logger: log,
	})
	if err != nil {
		return err
	}

	// SIGHUP reloads the brands file (and the login-client tokens it names).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			b, err := config.LoadBrands(cfg.BrandsFile)
			if err != nil {
				log.Error("reload brands", "error", err)
				continue
			}
			current.Store(b)
			log.Info("brands reloaded", "brands", len(b.All))
		}
	}()
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Cleanup(ctx); err != nil {
					log.Warn("cleanup", "error", err)
				}
			}
		}
	}()

	var handler http.Handler = srv
	if cfg.ActionsKeyFile != "" {
		// The action target shares the public listener (see package actions);
		// it sits outside the sign-in pages' CSRF and origin checks because
		// its caller is Zitadel, authenticated by the signature instead.
		mux := http.NewServeMux()
		mux.Handle("POST "+actions.Path, &actions.Handler{KeyFile: cfg.ActionsKeyFile, Log: log})
		mux.Handle("/", srv)
		handler = mux
	}
	servers := []*http.Server{{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			log.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	return err
}
