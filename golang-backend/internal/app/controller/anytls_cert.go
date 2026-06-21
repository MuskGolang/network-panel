package controller

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"network-panel/golang-backend/internal/app/model"
	"network-panel/golang-backend/internal/app/response"
	"network-panel/golang-backend/internal/app/util"
	dbpkg "network-panel/golang-backend/internal/db"
)

const (
	anyTLSCertDirEnv        = "ANYTLS_CERT_DIR"
	anyTLSCertDirDefault    = "./data/anytls"
	anyTLSCACertFileName    = "ca_cert.pem"
	anyTLSCAKeyFileName     = "ca_key.pem"
	anyTLSLeafValidity      = 90 * 24 * time.Hour
	anyTLSCAValidity        = 5 * 365 * 24 * time.Hour
	anyTLSCARefreshBefore   = 7 * 24 * time.Hour
	anyTLSCertCommonName    = "E8"
	anyTLSCertOrganization  = "Let's Encrypt"
	anyTLSDomainSuffix      = "docker.com"
	anyTLSRandomPrefixSize  = 8
	anyTLSDomainLabelMaxLen = 63
	anyTLSAgentRefreshHours = 24
	anyTLSCACertDBKey       = "anytls_ca_cert_pem"
	anyTLSCAKeyDBKey        = "anytls_ca_key_pem"
	anyTLSCertEnabledDBKey  = "anytls_cert_enabled"
)

type anyTLSNodeCertBundle struct {
	Domain      string
	CertPEM     string
	KeyPEM      string
	CAPEM       string
	NotBeforeMS int64
	NotAfterMS  int64
}

func anyTLSCertDomainKey(nodeID int64) string {
	return fmt.Sprintf("anytls_cert_domain_%d", nodeID)
}

func anyTLSCertRevisionKey(nodeID int64) string {
	return fmt.Sprintf("anytls_cert_revision_%d", nodeID)
}

func anyTLSCertDir() string {
	p := strings.TrimSpace(os.Getenv(anyTLSCertDirEnv))
	if p == "" {
		p = anyTLSCertDirDefault
	}
	return p
}

func anyTLSCACertPath() string {
	return filepath.Join(anyTLSCertDir(), anyTLSCACertFileName)
}

func anyTLSCAKeyPath() string {
	return filepath.Join(anyTLSCertDir(), anyTLSCAKeyFileName)
}

func upsertViteConfigValue(name, value string) error {
	now := time.Now().UnixMilli()
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", name).First(&cfg).Error; err == nil {
		cfg.Value = value
		cfg.Time = now
		return dbpkg.DB.Save(&cfg).Error
	}
	return dbpkg.DB.Create(&model.ViteConfig{Name: name, Value: value, Time: now}).Error
}

func getViteConfigValue(name string) string {
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", name).First(&cfg).Error; err != nil {
		return ""
	}
	return cfg.Value
}

func isAnyTLSCertFeatureEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(getViteConfigValue(anyTLSCertEnabledDBKey)))
	switch v {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func saveAnyTLSCAToDB(certPEM, keyPEM string) error {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return fmt.Errorf("empty ca pem")
	}
	if err := upsertViteConfigValue(anyTLSCACertDBKey, certPEM); err != nil {
		return err
	}
	return upsertViteConfigValue(anyTLSCAKeyDBKey, keyPEM)
}

func loadAnyTLSCAFromDB() (string, string, bool) {
	certPEM := strings.TrimSpace(getViteConfigValue(anyTLSCACertDBKey))
	keyPEM := strings.TrimSpace(getViteConfigValue(anyTLSCAKeyDBKey))
	if certPEM == "" || keyPEM == "" {
		return "", "", false
	}
	return certPEM, keyPEM, true
}

func normalizeAnyTLSCertDomain(nodeID int64, raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw != "" {
		if u, err := url.Parse(raw); err == nil && strings.TrimSpace(u.Hostname()) != "" {
			raw = strings.TrimSpace(strings.ToLower(u.Hostname()))
		}
	}
	raw = strings.Trim(raw, ".")
	if raw == "" {
		raw = randomDNSLabel(anyTLSRandomPrefixSize)
	}

	var domain string
	if strings.Contains(raw, ".") {
		domain = raw
	} else {
		label := sanitizeDNSLabel(raw)
		if label == "" {
			label = randomDNSLabel(anyTLSRandomPrefixSize)
		}
		domain = fmt.Sprintf("%djs.%s.%s", nodeID, label, anyTLSDomainSuffix)
	}
	domain = strings.Trim(domain, ".")
	if !isValidDNSName(domain) {
		return "", fmt.Errorf("invalid cert domain")
	}
	return domain, nil
}

func sanitizeDNSLabel(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	b := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b = append(b, c)
		}
	}
	out := strings.Trim(string(b), "-")
	if len(out) > anyTLSDomainLabelMaxLen {
		out = out[:anyTLSDomainLabelMaxLen]
		out = strings.Trim(out, "-")
	}
	return out
}

func randomDNSLabel(n int) string {
	if n <= 0 {
		n = anyTLSRandomPrefixSize
	}
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 1)
		if _, err := rand.Read(buf); err != nil {
			out[i] = letters[int(time.Now().UnixNano()%int64(len(letters)))]
			continue
		}
		out[i] = letters[int(buf[0])%len(letters)]
	}
	out[0] = letters[(int(out[0])+1)%len(letters)]
	return strings.Trim(sanitizeDNSLabel(string(out)), "-")
}

func isValidDNSName(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(strings.Trim(domain, ".")))
	if domain == "" || len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lb := range labels {
		if lb == "" || len(lb) > anyTLSDomainLabelMaxLen {
			return false
		}
		if lb[0] == '-' || lb[len(lb)-1] == '-' {
			return false
		}
		for i := 0; i < len(lb); i++ {
			c := lb[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func setAnyTLSCertDomain(nodeID int64, raw string) (string, error) {
	if nodeID <= 0 {
		return "", fmt.Errorf("invalid node id")
	}
	domain, err := normalizeAnyTLSCertDomain(nodeID, raw)
	if err != nil {
		return "", err
	}
	key := anyTLSCertDomainKey(nodeID)
	now := time.Now().UnixMilli()
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).Order("id desc").First(&cfg).Error; err == nil {
		cfg.Value = domain
		cfg.Time = now
		if err := dbpkg.DB.Save(&cfg).Error; err != nil {
			return "", err
		}
		_ = dbpkg.DB.Where("name = ? AND id <> ?", key, cfg.ID).Delete(&model.ViteConfig{}).Error
		return domain, nil
	}
	return domain, dbpkg.DB.Create(&model.ViteConfig{Name: key, Value: domain, Time: now}).Error
}

func getAnyTLSCertDomain(nodeID int64) string {
	if nodeID <= 0 {
		return ""
	}
	key := anyTLSCertDomainKey(nodeID)
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).Order("id desc").First(&cfg).Error; err != nil {
		return ""
	}
	domain := strings.TrimSpace(cfg.Value)
	if domain == "" {
		return ""
	}
	domain, err := normalizeAnyTLSCertDomain(nodeID, domain)
	if err != nil {
		return ""
	}
	return domain
}

func ensureAnyTLSCertDomain(nodeID int64, raw string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return setAnyTLSCertDomain(nodeID, raw)
	}
	if existing := getAnyTLSCertDomain(nodeID); existing != "" {
		return existing, nil
	}
	return setAnyTLSCertDomain(nodeID, "")
}

func getAnyTLSCertRevision(nodeID int64) int64 {
	if nodeID <= 0 {
		return 0
	}
	key := anyTLSCertRevisionKey(nodeID)
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).Order("id desc").First(&cfg).Error; err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(cfg.Value), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func bumpAnyTLSCertRevision(nodeID int64) (int64, error) {
	if nodeID <= 0 {
		return 0, fmt.Errorf("invalid node id")
	}
	key := anyTLSCertRevisionKey(nodeID)
	now := time.Now().UnixMilli()
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).Order("id desc").First(&cfg).Error; err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(cfg.Value), 10, 64)
		if v < 0 {
			v = 0
		}
		// Use current epoch-ms as revision seed to guarantee each force reissue gets a new cert.
		v = now
		cfg.Value = strconv.FormatInt(v, 10)
		cfg.Time = now
		if err := dbpkg.DB.Save(&cfg).Error; err != nil {
			return 0, err
		}
		_ = dbpkg.DB.Where("name = ? AND id <> ?", key, cfg.ID).Delete(&model.ViteConfig{}).Error
		return v, nil
	}
	cfg = model.ViteConfig{
		Name:  key,
		Value: strconv.FormatInt(now, 10),
		Time:  now,
	}
	if err := dbpkg.DB.Create(&cfg).Error; err != nil {
		return 0, err
	}
	return now, nil
}

func currentAnyTLSLeafWindow(now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	// Use rolling validity window: each reissue starts from now.
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(anyTLSLeafValidity)
	return notBefore, notAfter
}

func anyTLSNodeCertStatus(nodeID int64, ensureDomain bool) (map[string]any, error) {
	if nodeID <= 0 {
		return nil, fmt.Errorf("invalid node id")
	}
	if !isAnyTLSCertFeatureEnabled() {
		return nil, nil
	}
	var (
		domain string
		err    error
	)
	if ensureDomain {
		domain, err = ensureAnyTLSCertDomain(nodeID, "")
		if err != nil {
			return nil, err
		}
	} else {
		domain = getAnyTLSCertDomain(nodeID)
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, nil
	}

	now := time.Now().UTC()
	if logDomain, logNotBefore, logNotAfter, logUpdatedAt, ok := latestAnyTLSCertMetaFromLogs(nodeID); ok && logNotAfter > 0 {
		if strings.TrimSpace(logDomain) != "" {
			domain = strings.TrimSpace(logDomain)
		}
		days := int64(time.Until(time.UnixMilli(logNotAfter)).Hours() / 24)
		state := "ok"
		if now.UnixMilli() > logNotAfter {
			state = "expired"
		} else if days <= 7 {
			state = "expiring"
		}
		return map[string]any{
			"domain":      domain,
			"notBeforeMs": logNotBefore,
			"notAfterMs":  logNotAfter,
			"daysLeft":    days,
			"state":       state,
			"revision":    getAnyTLSCertRevision(nodeID),
			"updatedAtMs": logUpdatedAt,
			"source":      "agent_log",
		}, nil
	}

	notBefore, notAfter := currentAnyTLSLeafWindow(now)
	days := int64(time.Until(notAfter).Hours() / 24)
	state := "ok"
	if now.After(notAfter) {
		state = "expired"
	} else if days <= 7 {
		state = "expiring"
	}
	return map[string]any{
		"domain":      domain,
		"notBeforeMs": notBefore.UnixMilli(),
		"notAfterMs":  notAfter.UnixMilli(),
		"daysLeft":    days,
		"state":       state,
		"revision":    getAnyTLSCertRevision(nodeID),
		"updatedAtMs": now.UnixMilli(),
		"source":      "controller_estimate",
	}, nil
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n
	default:
		return 0
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func latestAnyTLSCertMetaFromLogs(nodeID int64) (domain string, notBeforeMs, notAfterMs, updatedAtMs int64, ok bool) {
	if nodeID <= 0 {
		return "", 0, 0, 0, false
	}
	var logs []model.NodeAnyTLSCertLog
	if err := dbpkg.DB.Where("node_id = ? AND step IN ?", nodeID, []string{
		"installed_check",
		"material_updated",
		"material_unchanged",
	}).Order("time_ms desc, id desc").Limit(30).Find(&logs).Error; err != nil || len(logs) == 0 {
		return "", 0, 0, 0, false
	}
	for _, lg := range logs {
		if strings.TrimSpace(lg.Data) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lg.Data), &m); err != nil {
			continue
		}
		d := strings.TrimSpace(asString(m["domain"]))
		nb := asInt64(m["notBeforeMs"])
		na := asInt64(m["notAfterMs"])
		if lg.Step == "installed_check" {
			if ins, okIns := m["installed"].(map[string]any); okIns {
				if nb == 0 {
					nb = asInt64(ins["notBeforeMs"])
				}
				if na == 0 {
					na = asInt64(ins["notAfterMs"])
				}
				if d == "" {
					if dns, okDNS := ins["dnsNames"].([]any); okDNS && len(dns) > 0 {
						d = asString(dns[0])
					}
				}
			}
			if d == "" {
				if exp, okExp := m["expected"].(map[string]any); okExp {
					d = asString(exp["domain"])
				}
			}
		}
		if na > 0 {
			return d, nb, na, lg.TimeMs, true
		}
	}
	return "", 0, 0, 0, false
}

func parsePrivateKeyPEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func ensureAnyTLSCA() (*x509.Certificate, any, string, error) {
	if err := os.MkdirAll(anyTLSCertDir(), 0o700); err != nil {
		return nil, nil, "", err
	}

	certPath := anyTLSCACertPath()
	keyPath := anyTLSCAKeyPath()

	// Prefer DB as source-of-truth to avoid CA/key drift across restarts or multi-instance deployments.
	if certPEMFromDB, keyPEMFromDB, ok := loadAnyTLSCAFromDB(); ok {
		block, _ := pem.Decode([]byte(certPEMFromDB))
		if block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cert.IsCA && time.Until(cert.NotAfter) > anyTLSCARefreshBefore {
					if key, err := parsePrivateKeyPEM([]byte(keyPEMFromDB)); err == nil {
						_ = os.WriteFile(certPath, []byte(certPEMFromDB+"\n"), 0o600)
						_ = os.WriteFile(keyPath, []byte(keyPEMFromDB+"\n"), 0o600)
						return cert, key, certPEMFromDB, nil
					}
				}
			}
		}
	}

	// Fallback: recover CA from local files, then sync back to DB.
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		if block, _ := pem.Decode(certPEM); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cert.IsCA && time.Until(cert.NotAfter) > anyTLSCARefreshBefore {
					if key, err := parsePrivateKeyPEM(keyPEM); err == nil {
						_ = saveAnyTLSCAToDB(string(certPEM), string(keyPEM))
						return cert, key, string(certPEM), nil
					}
				}
			}
		}
	}

	return generateAnyTLSCA()
}

func generateAnyTLSCA() (*x509.Certificate, any, string, error) {
	if err := os.MkdirAll(anyTLSCertDir(), 0o700); err != nil {
		return nil, nil, "", err
	}
	certPath := anyTLSCACertPath()
	keyPath := anyTLSCAKeyPath()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   anyTLSCertCommonName,
			Organization: []string{anyTLSCertOrganization},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(anyTLSCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, nil, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", err
	}
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, newCertPEM, 0o600); err != nil {
		return nil, nil, "", err
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0o600); err != nil {
		return nil, nil, "", err
	}
	_ = saveAnyTLSCAToDB(string(newCertPEM), string(newKeyPEM))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	return cert, priv, string(newCertPEM), nil
}

func anyTLSCAStatus() (map[string]any, error) {
	enabled := isAnyTLSCertFeatureEnabled()
	info := map[string]any{
		"enabled":             enabled,
		"certDir":             anyTLSCertDir(),
		"caCertPath":          anyTLSCACertPath(),
		"caKeyPath":           anyTLSCAKeyPath(),
		"caExists":            false,
		"keyExists":           false,
		"caRefreshBeforeMs":   int64(anyTLSCARefreshBefore / time.Millisecond),
		"nodeCertValidityMs":  int64(anyTLSLeafValidity / time.Millisecond),
		"agentRefreshHours":   anyTLSAgentRefreshHours,
		"certCommonName":      anyTLSCertCommonName,
		"certOrganization":    anyTLSCertOrganization,
		"domainSuffix":        anyTLSDomainSuffix,
		"randomPrefixLength":  anyTLSRandomPrefixSize,
		"domainFormatExample": fmt.Sprintf("<nodeId>js.<prefix>.%s", anyTLSDomainSuffix),
	}
	if !enabled {
		return info, nil
	}

	certPath := anyTLSCACertPath()
	keyPath := anyTLSCAKeyPath()
	if st, err := os.Stat(certPath); err == nil {
		info["caExists"] = true
		info["caUpdatedAtMs"] = st.ModTime().UnixMilli()
	}
	if st, err := os.Stat(keyPath); err == nil {
		info["keyExists"] = true
		info["keyUpdatedAtMs"] = st.ModTime().UnixMilli()
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return info, nil
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		info["parseError"] = "invalid cert pem"
		return info, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info["parseError"] = err.Error()
		return info, nil
	}
	now := time.Now().UTC()
	info["serialNumber"] = cert.SerialNumber.String()
	info["subject"] = cert.Subject.String()
	info["issuer"] = cert.Issuer.String()
	info["notBeforeMs"] = cert.NotBefore.UnixMilli()
	info["notAfterMs"] = cert.NotAfter.UnixMilli()
	info["daysRemaining"] = int64(time.Until(cert.NotAfter).Hours() / 24)
	info["isExpired"] = cert.NotAfter.Before(now)
	info["refreshAtMs"] = cert.NotAfter.Add(-anyTLSCARefreshBefore).UnixMilli()
	info["isCA"] = cert.IsCA
	info["publicKeyAlgorithm"] = cert.PublicKeyAlgorithm.String()
	info["signatureAlgorithm"] = cert.SignatureAlgorithm.String()
	if len(cert.Subject.Organization) > 0 {
		info["subjectOrganization"] = cert.Subject.Organization[0]
	}
	info["subjectCommonName"] = cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		info["dnsNames"] = cert.DNSNames
	}
	return info, nil
}

func issueAnyTLSNodeCert(nodeID int64, rawDomain string) (*anyTLSNodeCertBundle, error) {
	if nodeID <= 0 {
		return nil, fmt.Errorf("invalid node id")
	}
	domain, err := ensureAnyTLSCertDomain(nodeID, rawDomain)
	if err != nil {
		return nil, err
	}
	caCert, caKey, caPEM, err := ensureAnyTLSCA()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	notBeforeWithSkew, notAfter := currentAnyTLSLeafWindow(now)
	notBefore := notBeforeWithSkew.Add(1 * time.Hour)
	revision := getAnyTLSCertRevision(nodeID)
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafPub := &leafPriv.PublicKey
	serialSeed := fmt.Sprintf("%d|%s|%d|%s|%d|%d", nodeID, domain, notBefore.Unix(), caCert.SerialNumber.String(), revision, time.Now().UnixNano())
	serialHash := sha256.Sum256([]byte("serial|" + serialSeed))
	serial := new(big.Int).SetBytes(serialHash[:16])
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   anyTLSCertCommonName,
			Organization: []string{anyTLSCertOrganization},
		},
		NotBefore:             notBeforeWithSkew,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, leafPub, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &anyTLSNodeCertBundle{
		Domain:      domain,
		CertPEM:     string(certPEM),
		KeyPEM:      string(keyPEM),
		CAPEM:       caPEM,
		NotBeforeMS: tpl.NotBefore.UnixMilli(),
		NotAfterMS:  tpl.NotAfter.UnixMilli(),
	}, nil
}

func anyTLSCertPayload(nodeID int64, rawDomain string) (map[string]any, error) {
	if !isAnyTLSCertFeatureEnabled() {
		return nil, nil
	}
	bundle, err := issueAnyTLSNodeCert(nodeID, rawDomain)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"certDomain":      bundle.Domain,
		"certPem":         bundle.CertPEM,
		"keyPem":          bundle.KeyPEM,
		"caPem":           bundle.CAPEM,
		"certNotBeforeMs": bundle.NotBeforeMS,
		"certNotAfterMs":  bundle.NotAfterMS,
		"enforceVerify":   true,
	}, nil
}

// AgentAnyTLSCert provides AnyTLS server certificate material for the node.
// POST /api/v1/agent/anytls-cert {secret}
func AgentAnyTLSCert(c *gin.Context) {
	var p struct {
		Secret string `json:"secret" binding:"required"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	secret := strings.TrimSpace(p.Secret)
	if secret == "" {
		c.JSON(http.StatusOK, response.ErrMsg("secret 不能为空"))
		return
	}
	var node model.Node
	if err := dbpkg.DB.Select("id").Where("secret = ?", secret).First(&node).Error; err != nil || node.ID == 0 {
		c.JSON(http.StatusUnauthorized, response.ErrMsg("invalid secret"))
		return
	}
	if !isAnyTLSCertFeatureEnabled() {
		c.JSON(http.StatusOK, response.Ok(gin.H{"enabled": false, "reason": "controller_disabled"}))
		return
	}
	var st model.AnyTLSSetting
	if err := dbpkg.DB.Select("id").Where("node_id = ?", node.ID).First(&st).Error; err != nil || st.ID == 0 {
		c.JSON(http.StatusOK, response.Ok(gin.H{"enabled": false}))
		return
	}
	payload, err := anyTLSCertPayload(node.ID, "")
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("证书生成失败: "+err.Error()))
		return
	}
	payload["enabled"] = true
	c.JSON(http.StatusOK, response.Ok(payload))
}

// SubscriptionAnyTLSCACheck checks whether downloaded CA content is import-ready.
// GET /api/v1/subscription/anytls-ca/check
func SubscriptionAnyTLSCACheck(c *gin.Context) {
	token := extractToken(c)
	if token == "" || !util.ValidateToken(token) {
		c.JSON(http.StatusUnauthorized, response.ErrMsg("未登录或token无效"))
		return
	}
	if !isAnyTLSCertFeatureEnabled() {
		c.JSON(http.StatusOK, response.ErrMsg("控制器未启用 AnyTLS 证书"))
		return
	}

	_, _, caPEM, err := ensureAnyTLSCA()
	if err != nil || strings.TrimSpace(caPEM) == "" {
		c.JSON(http.StatusOK, response.ErrMsg("获取站点 CA 失败"))
		return
	}

	firstLine := ""
	for _, ln := range strings.Split(caPEM, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		firstLine = ln
		break
	}
	headerOK := strings.HasPrefix(firstLine, "-----BEGIN CERTIFICATE-----")
	ret := map[string]any{
		"pemFirstLine":  firstLine,
		"pemHeaderOK":   headerOK,
		"parseOK":       false,
		"downloadReady": false,
	}

	block, _ := pem.Decode([]byte(caPEM))
	if block == nil {
		ret["error"] = "invalid pem format"
		c.JSON(http.StatusOK, response.Ok(ret))
		return
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		ret["error"] = parseErr.Error()
		c.JSON(http.StatusOK, response.Ok(ret))
		return
	}

	ret["parseOK"] = true
	ret["downloadReady"] = headerOK
	ret["subjectCommonName"] = cert.Subject.CommonName
	if len(cert.Subject.Organization) > 0 {
		ret["subjectOrganization"] = cert.Subject.Organization[0]
	}
	ret["notBeforeMs"] = cert.NotBefore.UnixMilli()
	ret["notAfterMs"] = cert.NotAfter.UnixMilli()
	ret["publicKeyAlgorithm"] = cert.PublicKeyAlgorithm.String()
	ret["signatureAlgorithm"] = cert.SignatureAlgorithm.String()
	ret["isCA"] = cert.IsCA
	c.JSON(http.StatusOK, response.Ok(ret))
}

// SubscriptionAnyTLSCAStatus returns CA status for admin panel.
// GET /api/v1/subscription/anytls-ca/status
func SubscriptionAnyTLSCAStatus(c *gin.Context) {
	info, err := anyTLSCAStatus()
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("获取CA状态失败: "+err.Error()))
		return
	}
	c.JSON(http.StatusOK, response.Ok(info))
}

// SubscriptionAnyTLSCAGenerate creates or rotates controller CA.
// POST /api/v1/subscription/anytls-ca/generate {force?}
func SubscriptionAnyTLSCAGenerate(c *gin.Context) {
	var p struct {
		Force bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&p)

	rotated := false
	if p.Force {
		if _, _, _, err := generateAnyTLSCA(); err != nil {
			c.JSON(http.StatusOK, response.ErrMsg("生成CA失败: "+err.Error()))
			return
		}
		rotated = true
	} else {
		if _, _, _, err := ensureAnyTLSCA(); err != nil {
			c.JSON(http.StatusOK, response.ErrMsg("初始化CA失败: "+err.Error()))
			return
		}
	}
	info, err := anyTLSCAStatus()
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("获取CA状态失败: "+err.Error()))
		return
	}
	info["rotated"] = rotated
	c.JSON(http.StatusOK, response.Ok(info))
}
