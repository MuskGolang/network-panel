package controller

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"network-panel/golang-backend/internal/app/model"
	"network-panel/golang-backend/internal/app/util"
	dbpkg "network-panel/golang-backend/internal/db"
)

func TestBuildAnyTLSURI_WithSNIAndEgressIP(t *testing.T) {
	it := subProxy{
		Name:   "node-a",
		Server: "example.com",
		Port:   443,
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"egress-ip":        "203.0.113.10",
		"skip-cert-verify": false,
	}
	got := buildAnyTLSURI("u1:Wangzai007..@@", it, params)
	want := "anytls://Wangzai007..%40%40@example.com:443/?sni=www.apple.com&egress-ip=203.0.113.10&insecure=0#node-a"
	if got != want {
		t.Fatalf("unexpected uri\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAnyTLSURI_InvalidEgressIPOmitted(t *testing.T) {
	it := subProxy{
		Name:   "node-a",
		Server: "example.com",
		Port:   443,
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"egress-ip":        "hinetkvm001.nmcloud.cc",
		"skip-cert-verify": false,
	}
	got := buildAnyTLSURI("u1:Wangzai007..@@", it, params)
	want := "anytls://Wangzai007..%40%40@example.com:443/?sni=www.apple.com&insecure=0#node-a"
	if got != want {
		t.Fatalf("unexpected uri\nwant: %s\ngot:  %s", want, got)
	}
}

func TestBuildAnyTLSURI_AliasParams(t *testing.T) {
	it := subProxy{
		Name:   "node-a",
		Server: "example.com",
		Port:   443,
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"egress_ip":        "2001:db8::1",
		"ca_cert_path":     "/etc/anytls/ca.crt",
		"skip-cert-verify": false,
	}
	got := buildAnyTLSURI("u1:Wangzai007..@@", it, params)
	if !strings.Contains(got, "egress-ip=2001%3Adb8%3A%3A1") {
		t.Fatalf("missing alias egress_ip normalization: %s", got)
	}
	if !strings.Contains(got, "ca-cert-path=%2Fetc%2Fanytls%2Fca.crt") {
		t.Fatalf("missing alias ca_cert_path normalization: %s", got)
	}
	if !strings.Contains(got, "insecure=0") {
		t.Fatalf("missing enforce verify flag: %s", got)
	}
}

func TestBuildSurgeAnyTLSLine_StripPrefixAndAppendEgress(t *testing.T) {
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"egress-ip":        "203.0.113.10",
		"skip-cert-verify": false,
	}
	got := buildSurgeAnyTLSLine("node-a", "1.2.3.4", 10086, "u2:abc123", params)
	if strings.Contains(got, "u2:") {
		t.Fatalf("password prefix should be stripped: %s", got)
	}
	if !strings.Contains(got, "password=abc123") {
		t.Fatalf("missing cleaned password: %s", got)
	}
	if !strings.Contains(got, "sni=www.apple.com") {
		t.Fatalf("missing sni: %s", got)
	}
	if !strings.Contains(got, "egress-ip=203.0.113.10") {
		t.Fatalf("missing egress-ip: %s", got)
	}
}

func TestBuildQXLine_AnyTLS_WithEgressIP(t *testing.T) {
	it := subProxy{
		Name:     "node-a",
		Server:   "1.2.3.4",
		Port:     10086,
		Password: "u1:abc123",
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"egress-ip":        "203.0.113.10",
		"skip-cert-verify": false,
	}
	got := buildQXLine("anytls", it, params)
	if strings.Contains(got, "u1:") {
		t.Fatalf("password prefix should be stripped: %s", got)
	}
	if !strings.Contains(got, "anytls=1.2.3.4:10086") {
		t.Fatalf("unexpected qx anytls line: %s", got)
	}
	if !strings.Contains(got, "sni=www.apple.com") {
		t.Fatalf("missing sni: %s", got)
	}
	if !strings.Contains(got, "egress-ip=203.0.113.10") {
		t.Fatalf("missing egress-ip: %s", got)
	}
}

func TestBuildAnyTLSURI_SkipVerify_OmitsSNI(t *testing.T) {
	it := subProxy{
		Name:   "node-a",
		Server: "example.com",
		Port:   443,
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"skip-cert-verify": true,
	}
	got := buildAnyTLSURI("u1:Wangzai007..@@", it, params)
	if strings.Contains(got, "sni=") {
		t.Fatalf("sni should be omitted when skip verify is true: %s", got)
	}
	if !strings.Contains(got, "insecure=1") {
		t.Fatalf("expected insecure=1 when skip verify is true: %s", got)
	}
}

func TestBuildSurgeAnyTLSLine_SkipVerify_OmitsSNI(t *testing.T) {
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"skip-cert-verify": true,
	}
	got := buildSurgeAnyTLSLine("node-a", "1.2.3.4", 10086, "u2:abc123", params)
	if strings.Contains(got, "sni=") {
		t.Fatalf("sni should be omitted when skip verify is true: %s", got)
	}
	if !strings.Contains(got, "skip-cert-verify=true") {
		t.Fatalf("missing skip-cert-verify=true: %s", got)
	}
}

func TestBuildQXLine_AnyTLS_SkipVerify_OmitsSNI(t *testing.T) {
	it := subProxy{
		Name:     "node-a",
		Server:   "1.2.3.4",
		Port:     10086,
		Password: "u1:abc123",
	}
	params := map[string]interface{}{
		"sni":              "www.apple.com",
		"skip-cert-verify": true,
	}
	got := buildQXLine("anytls", it, params)
	if strings.Contains(got, "sni=") {
		t.Fatalf("sni should be omitted when skip verify is true: %s", got)
	}
}

func TestNormalizeEgressIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "203.0.113.10", want: "203.0.113.10"},
		{in: " [2001:db8::1] ", want: "2001:db8::1"},
		{in: "[2001:db8::1]:443", want: "2001:db8::1"},
		{in: "hinetkvm001.nmcloud.cc", want: ""},
		{in: "", want: ""},
	}
	for _, c := range cases {
		got := normalizeEgressIP(c.in)
		if got != c.want {
			t.Fatalf("normalizeEgressIP(%q) want %q got %q", c.in, c.want, got)
		}
	}
}

func TestBuildClashConfig_AnyTLS_NoDuplicateVerifyAliasKeys(t *testing.T) {
	items := []subProxy{
		{
			ID:       1,
			Name:     "yxvm-anytls",
			Group:    "默认",
			Type:     "anytls",
			Server:   "87.83.105.138",
			Port:     10087,
			Password: "Wangzai007..@@",
			Params: map[string]interface{}{
				"sni":                         "18js.p2hbmwsa.docker.com",
				"udp":                         true,
				"skip_cert_verify":            true,
				"allow_insecure":              true,
				"insecure":                    true,
				"client-fingerprint":          "chrome",
				"idle-session-check-interval": 30,
				"idle-session-timeout":        30,
				"min-idle-session":            0,
			},
		},
	}
	got := buildClashConfigLegacy(items, nil)
	if strings.Count(got, "skip-cert-verify:") != 1 {
		t.Fatalf("skip-cert-verify should appear once, got:\n%s", got)
	}
	for _, bad := range []string{
		"skip_cert_verify:",
		"allow-insecure:",
		"allow_insecure:",
		"insecure:",
	} {
		if strings.Contains(got, bad) {
			t.Fatalf("unexpected alias key %q in clash meta output:\n%s", bad, got)
		}
	}
	if strings.Contains(got, "\n    sni:") {
		t.Fatalf("sni should be omitted for anytls when skip-cert-verify is true:\n%s", got)
	}
}

func TestForwardEgressItems_EncodeAndParse(t *testing.T) {
	raw := encodeForwardEgressItems([]forwardEgressItem{
		{IP: " 203.0.113.10 ", Suffix: " hk "},
		{IP: "[2001:db8::1]:443", Suffix: "v6"},
		{IP: "invalid-host", Suffix: "bad"},
		{IP: "203.0.113.10", Suffix: "hk"}, // duplicate after trim
	})
	got := parseForwardEgressItems(raw)
	if len(got) != 2 {
		t.Fatalf("unexpected egress count: %d raw=%s", len(got), raw)
	}
	if got[0].IP != "203.0.113.10" || got[0].Suffix != "hk" {
		t.Fatalf("unexpected first egress: %#v", got[0])
	}
	if got[1].IP != "2001:db8::1" || got[1].Suffix != "v6" {
		t.Fatalf("unexpected second egress: %#v", got[1])
	}
}

func TestAppendForwardNameSuffix(t *testing.T) {
	cases := []struct {
		base   string
		suffix string
		want   string
	}{
		{base: "node", suffix: "hk", want: "node-hk"},
		{base: "node", suffix: "-us", want: "node-us"},
		{base: "node", suffix: "", want: "node"},
		{base: "node", suffix: "  tw  ", want: "node-tw"},
	}
	for _, c := range cases {
		got := appendForwardNameSuffix(c.base, c.suffix)
		if got != c.want {
			t.Fatalf("appendForwardNameSuffix(%q,%q) want %q got %q", c.base, c.suffix, c.want, got)
		}
	}
}

func TestSubscriptionItems_AnyTLSExpandByForwardEgresses(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	gin.SetMode(gin.TestMode)

	oldDB := dbpkg.DB
	defer func() { dbpkg.DB = oldDB }()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{},
		&model.Node{},
		&model.Tunnel{},
		&model.Forward{},
		&model.AnyTLSSetting{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dbpkg.DB = db

	now := time.Now().UnixMilli()
	status := 1
	user := model.User{
		BaseEntity: model.BaseEntity{ID: 101, CreatedTime: now, UpdatedTime: now, Status: &status},
		User:       "u101",
		Pwd:        "x",
		RoleID:     1,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	node := model.Node{
		BaseEntity: model.BaseEntity{ID: 201, CreatedTime: now, UpdatedTime: now, Status: &status},
		Name:       "entry-exit",
		ServerIP:   "203.0.113.20",
		IP:         "203.0.113.20",
		PortSta:    1000,
		PortEnd:    65535,
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	outNodeID := int64(201)
	tunnel := model.Tunnel{
		BaseEntity: model.BaseEntity{ID: 301, CreatedTime: now, UpdatedTime: now, Status: &status},
		Name:       "tun-1",
		InNodeID:   201,
		InIP:       "198.51.100.9",
		OutNodeID:  &outNodeID,
		Type:       1,
		Flow:       1,
	}
	if err := db.Create(&tunnel).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	anytls := model.AnyTLSSetting{
		BaseEntity: model.BaseEntity{ID: 401, CreatedTime: now, UpdatedTime: now, Status: &status},
		NodeID:     201,
		Port:       10086,
		Password:   "pw-abc",
	}
	if err := db.Create(&anytls).Error; err != nil {
		t.Fatalf("create anytls setting: %v", err)
	}
	fwd := model.Forward{
		BaseEntity: model.BaseEntity{ID: 501, CreatedTime: now, UpdatedTime: now, Status: &status},
		UserID:     101,
		UserName:   "u101",
		Name:       "rare-aether",
		Group:      "G1",
		TunnelID:   301,
		InPort:     44006,
		RemoteAddr: "example.com:443",
		EgressesRaw: encodeForwardEgressItems([]forwardEgressItem{
			{IP: "2001:db8::10", Suffix: "hk"},
			{IP: "2001:db8::11", Suffix: "us"},
		}),
	}
	if err := db.Create(&fwd).Error; err != nil {
		t.Fatalf("create forward: %v", err)
	}

	token := util.GenerateToken(101, "u101", 1)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/subscription/clash?token="+token, nil)

	_, items, skipped, ok := subscriptionItems(c)
	if !ok {
		t.Fatalf("subscriptionItems not ok, response=%s", w.Body.String())
	}
	if len(skipped) != 0 {
		t.Fatalf("unexpected skipped: %#v", skipped)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}

	got := map[string]string{}
	for _, it := range items {
		if it.Type != "anytls" {
			t.Fatalf("want anytls type, got %s", it.Type)
		}
		if it.Server != "198.51.100.9" || it.Port != 44006 {
			t.Fatalf("unexpected endpoint: %s:%d", it.Server, it.Port)
		}
		eg, _ := it.Params["egress-ip"].(string)
		got[it.Name] = eg
	}
	if got["rare-aether-hk"] != "2001:db8::10" {
		t.Fatalf("rare-aether-hk egress mismatch: %#v", got)
	}
	if got["rare-aether-us"] != "2001:db8::11" {
		t.Fatalf("rare-aether-us egress mismatch: %#v", got)
	}
}

func TestSubscriptionItems_AnyTLSPortMappingEgressFallback(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	gin.SetMode(gin.TestMode)

	oldDB := dbpkg.DB
	defer func() { dbpkg.DB = oldDB }()

	db, err := gorm.Open(sqlite.Open("file:anytls_port_mapping?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{},
		&model.Node{},
		&model.Tunnel{},
		&model.Forward{},
		&model.AnyTLSSetting{},
		&model.AnyTLSPortEgress{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dbpkg.DB = db

	now := time.Now().UnixMilli()
	status := 1
	user := model.User{
		BaseEntity: model.BaseEntity{ID: 102, CreatedTime: now, UpdatedTime: now, Status: &status},
		User:       "u102",
		Pwd:        "x",
		RoleID:     1,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	node := model.Node{
		BaseEntity: model.BaseEntity{ID: 202, CreatedTime: now, UpdatedTime: now, Status: &status},
		Name:       "entry-exit",
		ServerIP:   "203.0.113.21",
		IP:         "203.0.113.21",
		PortSta:    1000,
		PortEnd:    65535,
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	outNodeID := int64(202)
	tunnelOutIP := "203.0.113.250"
	tunnel := model.Tunnel{
		BaseEntity: model.BaseEntity{ID: 302, CreatedTime: now, UpdatedTime: now, Status: &status},
		Name:       "tun-port-map",
		InNodeID:   202,
		InIP:       "198.51.100.10",
		OutNodeID:  &outNodeID,
		OutIP:      &tunnelOutIP,
		Type:       1,
		Flow:       1,
	}
	if err := db.Create(&tunnel).Error; err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	anytls := model.AnyTLSSetting{
		BaseEntity: model.BaseEntity{ID: 402, CreatedTime: now, UpdatedTime: now, Status: &status},
		NodeID:     202,
		Port:       10086,
		Password:   "pw-abc",
	}
	if err := db.Create(&anytls).Error; err != nil {
		t.Fatalf("create anytls setting: %v", err)
	}
	mappedEgress := "2001:db8::20"
	if err := db.Create(&model.AnyTLSPortEgress{
		BaseEntity: model.BaseEntity{ID: 602, CreatedTime: now, UpdatedTime: now, Status: &status},
		NodeID:     202,
		Port:       10087,
		EgressIP:   &mappedEgress,
	}).Error; err != nil {
		t.Fatalf("create anytls port egress: %v", err)
	}
	outPort := 10087
	fwd := model.Forward{
		BaseEntity: model.BaseEntity{ID: 502, CreatedTime: now, UpdatedTime: now, Status: &status},
		UserID:     102,
		UserName:   "u102",
		Name:       "mapped-egress",
		Group:      "G1",
		TunnelID:   302,
		InPort:     44007,
		OutPort:    &outPort,
		RemoteAddr: "example.com:443",
	}
	if err := db.Create(&fwd).Error; err != nil {
		t.Fatalf("create forward: %v", err)
	}

	token := util.GenerateToken(102, "u102", 1)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/subscription/clash?token="+token, nil)

	_, items, skipped, ok := subscriptionItems(c)
	if !ok {
		t.Fatalf("subscriptionItems not ok, response=%s", w.Body.String())
	}
	if len(skipped) != 0 {
		t.Fatalf("unexpected skipped: %#v", skipped)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	got, _ := items[0].Params["egress-ip"].(string)
	if got != mappedEgress {
		t.Fatalf("want mapped egress %q, got %q params=%#v", mappedEgress, got, items[0].Params)
	}
}
