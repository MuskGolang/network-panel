package controller

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"network-panel/golang-backend/internal/app/model"
	dbpkg "network-panel/golang-backend/internal/db"
)

func TestShouldSkipGostServiceForForward_AnyTLSTunnelUsesRuntimeOnly(t *testing.T) {
	setupForwardAnyTLSTestDB(t)
	protocol := "anytls"
	outNodeID := int64(116)
	outPort := 10087
	forward := model.Forward{InPort: 10087, OutPort: &outPort, RemoteAddr: "82.158.226.99:10087"}
	tunnel := model.Tunnel{Type: 1, InNodeID: 116, OutNodeID: &outNodeID, Protocol: &protocol}

	if !shouldSkipGostServiceForForward(tunnel, forward) {
		t.Fatalf("AnyTLS forwards should be served by flux-agent runtime only, not by a GOST :%d forward", forward.InPort)
	}
}

func TestShouldSkipGostServiceForForward_AnyTLSTunnelDifferentPortsStillUsesGost(t *testing.T) {
	setupForwardAnyTLSTestDB(t)
	protocol := "anytls"
	outNodeID := int64(116)
	outPort := 10088
	forward := model.Forward{InPort: 10087, OutPort: &outPort, RemoteAddr: "82.158.226.99:10087"}
	tunnel := model.Tunnel{Type: 1, InNodeID: 116, OutNodeID: &outNodeID, Protocol: &protocol}

	if shouldSkipGostServiceForForward(tunnel, forward) {
		t.Fatalf("different AnyTLS ports should still use GOST forwarding")
	}
}

func TestShouldSkipGostServiceForForward_AnyTLSDifferentEntryNodeStillUsesGost(t *testing.T) {
	setupForwardAnyTLSTestDB(t)
	protocol := "anytls"
	outNodeID := int64(116)
	outPort := 10087
	forward := model.Forward{InPort: 10087, OutPort: &outPort, RemoteAddr: "82.158.226.99:10087"}
	tunnel := model.Tunnel{Type: 1, InNodeID: 115, OutNodeID: &outNodeID, Protocol: &protocol}

	if shouldSkipGostServiceForForward(tunnel, forward) {
		t.Fatalf("different entry/exit nodes still need the entry GOST forward")
	}
}

func TestShouldSkipGostServiceForForward_NormalTCPForwardStillUsesGost(t *testing.T) {
	setupForwardAnyTLSTestDB(t)
	outPort := 10087
	forward := model.Forward{InPort: 10087, OutPort: &outPort, RemoteAddr: "82.158.226.99:10087"}
	tunnel := model.Tunnel{Type: 1, InNodeID: 116}

	if shouldSkipGostServiceForForward(tunnel, forward) {
		t.Fatalf("normal TCP forwards must still create GOST services")
	}
}

func setupForwardAnyTLSTestDB(t *testing.T) {
	t.Helper()
	oldDB := dbpkg.DB
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.ViteConfig{}, &model.AnyTLSSetting{}, &model.ExitSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dbpkg.DB = db
	t.Cleanup(func() { dbpkg.DB = oldDB })
}
