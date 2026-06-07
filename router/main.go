package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/handlers"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer func() { _ = logger.Sync() }()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("config load failed", zap.Error(err))
	}

	localSigner, err := signer.NewLocalSigner()
	if err != nil {
		logger.Fatal("signer init failed", zap.Error(err))
	}

	srv := &handlers.Server{
		Store: store.NewMemoryStore(),
		SAValidator: auth.NewGoogleSAValidator(
			auth.NewGoogleJWKSFetcher(),
			cfg.ApprovedSAPattern,
			cfg.SATokenAudience,
		),
		AttestValidator: auth.NewCSAttestationValidator(logger),
		Allowlist:       auth.NewAllowlist(cfg.ApprovedDigests),
		Signer:          localSigner,
		Logger:          logger,
		Config:          cfg,
	}

	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("router listening", zap.String("port", cfg.Port))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", zap.Error(err))
	}
}
