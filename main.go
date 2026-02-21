package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const moduleID = "opcua"
const serviceType = "opcua"

// natsLogger publishes log entries to NATS in addition to stdout.
type natsLogger struct {
	nc          *nats.Conn
	subject     string
	serviceType string
	moduleID    string
	mu          sync.Mutex
}

func (l *natsLogger) publish(level, logger, msg string) {
	if l.nc == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := ServiceLogEntry{
		Timestamp:   time.Now().UnixMilli(),
		Level:       level,
		Message:     msg,
		ServiceType: l.serviceType,
		ModuleID:    l.moduleID,
		Logger:      logger,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = l.nc.Publish(l.subject, data)
}

var natsLog *natsLogger

// logInfo logs to both stdout and NATS.
func logInfo(logger, msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	slog.Info(formatted, "logger", logger)
	if natsLog != nil {
		natsLog.publish("info", logger, formatted)
	}
}

func logWarn(logger, msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	slog.Warn(formatted, "logger", logger)
	if natsLog != nil {
		natsLog.publish("warn", logger, formatted)
	}
}

func logError(logger, msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	slog.Error(formatted, "logger", logger)
	if natsLog != nil {
		natsLog.publish("error", logger, formatted)
	}
}

func logDebug(logger, msg string, args ...interface{}) {
	formatted := fmt.Sprintf(msg, args...)
	slog.Debug(formatted, "logger", logger)
	if natsLog != nil {
		natsLog.publish("debug", logger, formatted)
	}
}

// connectToNats connects to NATS with infinite retry.
func connectToNats(servers string) (*nats.Conn, error) {
	for {
		slog.Info(fmt.Sprintf("Connecting to NATS at %s...", servers))
		nc, err := nats.Connect(servers,
			nats.MaxReconnects(-1),
			nats.ReconnectWait(5*time.Second),
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				if err != nil {
					slog.Warn(fmt.Sprintf("NATS disconnected: %v", err))
				}
			}),
			nats.ReconnectHandler(func(_ *nats.Conn) {
				slog.Info("NATS reconnected")
			}),
		)
		if err != nil {
			slog.Warn(fmt.Sprintf("Failed to connect to NATS: %v. Retrying in 5 seconds...", err))
			time.Sleep(5 * time.Second)
			continue
		}
		slog.Info("Connected to NATS")
		return nc, nil
	}
}

func main() {
	slog.Info("═══════════════════════════════════════════════════════════════")
	slog.Info("            tentacle-opcua Service (Go)")
	slog.Info("═══════════════════════════════════════════════════════════════")

	natsServers := os.Getenv("NATS_SERVERS")
	if natsServers == "" {
		natsServers = "nats://localhost:4222"
	}

	pkiDir := os.Getenv("OPCUA_PKI_DIR")
	if pkiDir == "" {
		pkiDir = "./pki"
	}

	autoAcceptCerts := os.Getenv("OPCUA_AUTO_ACCEPT_CERTS") != "false"

	slog.Info(fmt.Sprintf("Module ID: %s", moduleID))
	slog.Info(fmt.Sprintf("NATS Servers: %s", natsServers))
	slog.Info(fmt.Sprintf("PKI Directory: %s", pkiDir))
	slog.Info(fmt.Sprintf("Auto-accept certs: %v", autoAcceptCerts))

	// Generate/load certificate
	certFile, keyFile, err := ensureCertificate(pkiDir)
	if err != nil {
		slog.Error(fmt.Sprintf("Certificate setup failed: %v", err))
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("Certificate: %s", certFile))
	slog.Info(fmt.Sprintf("Private key: %s", keyFile))

	// Connect to NATS (retries forever)
	nc, err := connectToNats(natsServers)
	if err != nil {
		slog.Error(fmt.Sprintf("NATS connection failed: %v", err))
		os.Exit(1)
	}

	// Enable NATS log streaming
	natsLog = &natsLogger{
		nc:          nc,
		subject:     fmt.Sprintf("service.logs.%s.%s", serviceType, moduleID),
		serviceType: serviceType,
		moduleID:    moduleID,
	}

	// Create and start scanner
	logInfo("opcua", "Initializing OPC UA scanner...")
	scanner := NewScanner(nc, certFile, keyFile, pkiDir, autoAcceptCerts)
	scanner.Start()

	// ═══════════════════════════════════════════════════════════════════════════
	// Heartbeat publishing
	// ═══════════════════════════════════════════════════════════════════════════

	js, err := jetstream.New(nc)
	if err != nil {
		logError("opcua", "Failed to create JetStream context: %v", err)
		os.Exit(1)
	}

	ctx := context.Background()
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  "service_heartbeats",
		History: 1,
		TTL:     60 * time.Second,
	})
	if err != nil {
		logError("opcua", "Failed to create/open heartbeat KV: %v", err)
		os.Exit(1)
	}

	startedAt := time.Now().UnixMilli()

	publishHeartbeat := func() {
		hb := ServiceHeartbeat{
			ServiceType: serviceType,
			ModuleID:    moduleID,
			LastSeen:    time.Now().UnixMilli(),
			StartedAt:   startedAt,
			Metadata:    map[string]interface{}{},
		}
		data, err := json.Marshal(hb)
		if err != nil {
			logWarn("opcua", "Failed to marshal heartbeat: %v", err)
			return
		}
		if _, err := kv.Put(ctx, moduleID, data); err != nil {
			logWarn("opcua", "Failed to publish heartbeat: %v", err)
		}
	}

	// Publish initial heartbeat
	publishHeartbeat()
	logInfo("opcua", "Service heartbeat started (moduleId: %s)", moduleID)

	// Publish heartbeat every 10 seconds
	heartbeatTicker := time.NewTicker(10 * time.Second)
	go func() {
		for range heartbeatTicker.C {
			publishHeartbeat()
		}
	}()

	logInfo("opcua", "")
	logInfo("opcua", "Service running. Press Ctrl+C to stop.")
	logInfo("opcua", "Waiting for subscribe/browse requests...")
	logInfo("opcua", "")

	// ═══════════════════════════════════════════════════════════════════════════
	// Shutdown handling
	// ═══════════════════════════════════════════════════════════════════════════

	shutdown := func(reason string) {
		logInfo("opcua", "Received %s, shutting down...", reason)

		// Stop heartbeat
		heartbeatTicker.Stop()
		if err := kv.Delete(ctx, moduleID); err != nil {
			// Ignore — may already be expired
		}
		logInfo("opcua", "Removed service heartbeat")

		// Stop scanner
		scanner.Stop()

		// Drain NATS
		if err := nc.Drain(); err != nil {
			logWarn("opcua", "NATS drain error: %v", err)
		}

		logInfo("opcua", "Shutdown complete")
	}

	// Listen for NATS shutdown command
	shutdownSub, err := nc.Subscribe(moduleID+".shutdown", func(msg *nats.Msg) {
		logInfo("opcua", "Received shutdown command via NATS")
		shutdown("NATS shutdown")
		os.Exit(0)
	})
	if err != nil {
		logWarn("opcua", "Failed to subscribe to shutdown topic: %v", err)
	}
	_ = shutdownSub

	// Wait for OS signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	shutdown(sig.String())
}
