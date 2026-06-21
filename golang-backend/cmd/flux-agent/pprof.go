package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"sync"
	"time"
)

var agentPprofMu sync.Mutex
var agentPprofServer *http.Server
var agentPprofAddr string

func startAgentPprof(addr string) (string, error) {
	agentPprofMu.Lock()
	defer agentPprofMu.Unlock()

	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if agentPprofServer != nil {
		return agentPprofAddr, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	actual := ln.Addr().String()
	srv := &http.Server{Handler: http.DefaultServeMux}
	agentPprofServer = srv
	agentPprofAddr = actual
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logPrintfSafe("{\"event\":\"pprof_serve_err\",\"addr\":%q,\"error\":%q}", actual, err.Error())
		}
	}()
	return actual, nil
}

func stopAgentPprof() error {
	agentPprofMu.Lock()
	srv := agentPprofServer
	agentPprofServer = nil
	agentPprofAddr = ""
	agentPprofMu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

func agentPprofStatus() map[string]any {
	agentPprofMu.Lock()
	defer agentPprofMu.Unlock()
	return map[string]any{
		"enabled": agentPprofServer != nil,
		"addr":    agentPprofAddr,
	}
}

func fetchAgentPprofText(profile string, debug int) (string, string, error) {
	agentPprofMu.Lock()
	addr := agentPprofAddr
	enabled := agentPprofServer != nil
	agentPprofMu.Unlock()
	if !enabled || strings.TrimSpace(addr) == "" {
		return "", "", fmt.Errorf("pprof not enabled")
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		profile = "goroutine"
	}
	if strings.Contains(profile, "/") || strings.Contains(profile, "?") || strings.Contains(profile, "..") {
		return "", addr, fmt.Errorf("invalid pprof profile")
	}
	url := fmt.Sprintf("http://%s/debug/pprof/%s?debug=%d", addr, profile, debug)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", addr, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", addr, err
	}
	if resp.StatusCode/100 != 2 {
		return "", addr, fmt.Errorf("pprof fetch status %d: %s", resp.StatusCode, string(body))
	}
	return string(body), addr, nil
}

func logPrintfSafe(format string, args ...any) {
	defer func() { _ = recover() }()
	log.Printf(format, args...)
}
