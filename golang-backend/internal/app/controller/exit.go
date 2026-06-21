package controller

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"network-panel/golang-backend/internal/app/model"
	"network-panel/golang-backend/internal/app/response"
	dbpkg "network-panel/golang-backend/internal/db"
	"gorm.io/gorm"
)

func certFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func certSummary(cert *x509.Certificate) map[string]any {
	if cert == nil {
		return nil
	}
	out := map[string]any{
		"subject":            cert.Subject.String(),
		"issuer":             cert.Issuer.String(),
		"serial":             cert.SerialNumber.String(),
		"signatureAlgorithm": cert.SignatureAlgorithm.String(),
		"publicKeyAlgorithm": cert.PublicKeyAlgorithm.String(),
		"notBeforeMs":        cert.NotBefore.UnixMilli(),
		"notAfterMs":         cert.NotAfter.UnixMilli(),
		"fingerprintSha256":  certFingerprintSHA256(cert),
	}
	if len(cert.DNSNames) > 0 {
		out["dnsNames"] = cert.DNSNames
	}
	return out
}

func normalizeNodeDialHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil {
		if h := strings.TrimSpace(u.Hostname()); h != "" {
			raw = h
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil && strings.TrimSpace(h) != "" {
		raw = h
	}
	raw = strings.TrimSpace(strings.Trim(raw, "[]"))
	if i := strings.Index(raw, "/"); i > 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func candidateNodeHosts(node model.Node) []string {
	uniq := make(map[string]struct{})
	out := make([]string, 0, 4)
	add := func(raw string) {
		for _, t := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
		}) {
			h := normalizeNodeDialHost(t)
			if h == "" {
				continue
			}
			if _, ok := uniq[h]; ok {
				continue
			}
			uniq[h] = struct{}{}
			out = append(out, h)
		}
	}
	add(node.IP)
	add(node.ServerIP)
	return out
}

func probeAnyTLSAddress(addr, sni string, roots *x509.CertPool) (bool, string, *x509.Certificate) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	strictCfg := &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, strictCfg)
	if err == nil {
		defer conn.Close()
		st := conn.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			return true, "", st.PeerCertificates[0]
		}
		return true, "", nil
	}
	verifyErr := err.Error()

	// Fallback insecure handshake to still capture peer certificate for diagnostics.
	insecureCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	conn2, err2 := tls.DialWithDialer(dialer, "tcp", addr, insecureCfg)
	if err2 != nil {
		if verifyErr == "" {
			verifyErr = err2.Error()
		}
		return false, verifyErr, nil
	}
	defer conn2.Close()
	st2 := conn2.ConnectionState()
	if len(st2.PeerCertificates) == 0 {
		return false, verifyErr, nil
	}
	leaf := st2.PeerCertificates[0]
	inter := x509.NewCertPool()
	if len(st2.PeerCertificates) > 1 {
		for _, ic := range st2.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   time.Now(),
	}); verr == nil {
		return true, "", leaf
	} else if verifyErr == "" {
		verifyErr = verr.Error()
	}
	return false, verifyErr, leaf
}

type anyTLSPortInput struct {
	Port   int    `json:"port"`
	ExitIP string `json:"exitIp"`
}

type anyTLSPortMapping struct {
	Port   int    `json:"port"`
	ExitIP string `json:"exitIp,omitempty"`
}

func normalizeAnyTLSPortMappings(in []anyTLSPortInput) ([]anyTLSPortMapping, string) {
	if len(in) == 0 {
		return nil, ""
	}
	seen := map[int]struct{}{}
	out := make([]anyTLSPortMapping, 0, len(in))
	for _, item := range in {
		if item.Port <= 0 || item.Port > 65535 {
			return nil, fmt.Sprintf("AnyTLS端口无效: %d", item.Port)
		}
		if _, ok := seen[item.Port]; ok {
			continue
		}
		seen[item.Port] = struct{}{}
		exitIP := strings.TrimSpace(item.ExitIP)
		if exitIP != "" {
			exitIP = normalizeEgressIP(exitIP)
			if exitIP == "" {
				return nil, fmt.Sprintf("AnyTLS端口 %d 的出口IP无效", item.Port)
			}
		}
		out = append(out, anyTLSPortMapping{
			Port:   item.Port,
			ExitIP: exitIP,
		})
	}
	if len(out) == 0 {
		return nil, ""
	}
	return out, ""
}

func listAnyTLSPortMappings(nodeID int64) []anyTLSPortMapping {
	if nodeID <= 0 {
		return nil
	}
	var rows []model.AnyTLSPortEgress
	_ = dbpkg.DB.Where("node_id = ?", nodeID).Order("port asc").Find(&rows).Error
	if len(rows) == 0 {
		return nil
	}
	out := make([]anyTLSPortMapping, 0, len(rows))
	for _, row := range rows {
		if row.Port <= 0 {
			continue
		}
		exitIP := ""
		if row.EgressIP != nil {
			exitIP = strings.TrimSpace(*row.EgressIP)
		}
		out = append(out, anyTLSPortMapping{
			Port:   row.Port,
			ExitIP: exitIP,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func saveAnyTLSPortMappings(nodeID int64, items []anyTLSPortMapping) error {
	if nodeID <= 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	return dbpkg.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.AnyTLSPortEgress{}).Error; err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		ins := make([]model.AnyTLSPortEgress, 0, len(items))
		status := 1
		for _, item := range items {
			var eip *string
			if strings.TrimSpace(item.ExitIP) != "" {
				v := strings.TrimSpace(item.ExitIP)
				eip = &v
			}
			ins = append(ins, model.AnyTLSPortEgress{
				BaseEntity: model.BaseEntity{
					CreatedTime: now,
					UpdatedTime: now,
					Status:      &status,
				},
				NodeID:   nodeID,
				Port:     item.Port,
				EgressIP: eip,
			})
		}
		return tx.Create(&ins).Error
	})
}

// NodeSetExit 配置出口节点服务
// @Summary 配置出口节点服务
// @Tags node
// @Accept json
// @Produce json
// @Param data body SwaggerNodeExitReq true "出口服务配置"
// @Success 200 {object} BaseSwaggerResp
// @Router /api/v1/node/set-exit [post]
// POST /api/v1/node/set-exit {nodeId, port, password, method?}
// Creates/updates an SS server service on the selected node with given port/password.
func NodeSetExit(c *gin.Context) {
	var p struct {
		NodeID        int64   `json:"nodeId" binding:"required"`
		Type          string  `json:"type"`
		Port          int     `json:"port"`
		AnyTLSPorts   []anyTLSPortInput `json:"anytlsPorts"`
		Password      string  `json:"password"`
		Method        string  `json:"method"`
		ExitIP        *string `json:"exitIp"`
		AllowFallback *bool   `json:"allowFallback"`
		CertDomain    *string `json:"certDomain"`
		// optional extras
		Observer string                 `json:"observer"`
		Limiter  string                 `json:"limiter"`
		RLimiter string                 `json:"rlimiter"`
		Metadata map[string]interface{} `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	if _, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, true); !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	exitType := strings.ToLower(strings.TrimSpace(p.Type))
	if exitType == "" {
		exitType = "ss"
	}
	if exitType != "ss" && exitType != "anytls" {
		c.JSON(http.StatusOK, response.ErrMsg("无效的出口类型"))
		return
	}
	_, un, _, _, isShared, errMsg, ok := nodeAccess(c, p.NodeID, true)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if exitType == "anytls" {
		normalizedPorts, perr := normalizeAnyTLSPortMappings(p.AnyTLSPorts)
		if perr != "" {
			c.JSON(http.StatusOK, response.ErrMsg(perr))
			return
		}
		if len(normalizedPorts) == 0 {
			if p.Port <= 0 || p.Port > 65535 {
				c.JSON(http.StatusOK, response.ErrMsg("AnyTLS端口无效"))
				return
			}
			exitIP := ""
			if p.ExitIP != nil {
				exitIP = strings.TrimSpace(*p.ExitIP)
			}
			if exitIP != "" {
				exitIP = normalizeEgressIP(exitIP)
				if exitIP == "" {
					c.JSON(http.StatusOK, response.ErrMsg("AnyTLS出口IP无效"))
					return
				}
			}
			normalizedPorts = []anyTLSPortMapping{{Port: p.Port, ExitIP: exitIP}}
		}
		if isShared {
			for _, it := range normalizedPorts {
				if !portAllowedForShared(un, it.Port) {
					c.JSON(http.StatusOK, response.ErrMsg(fmt.Sprintf("端口 %d 不在授权范围", it.Port)))
					return
				}
			}
		}
		var existing model.AnyTLSSetting
		_ = dbpkg.DB.Where("node_id = ?", p.NodeID).First(&existing).Error
		password := strings.TrimSpace(p.Password)
		if password == "" {
			password = strings.TrimSpace(existing.Password)
		}
		if password == "" {
			c.JSON(http.StatusOK, response.ErrMsg("请填写AnyTLS密码"))
			return
		}

		allowFallback := getAnyTLSExitFallback(p.NodeID)
		if p.AllowFallback != nil {
			allowFallback = *p.AllowFallback
		}
		var baseUserID int64
		if v, ok := c.Get("user_id"); ok {
			if id, ok2 := v.(int64); ok2 {
				baseUserID = id
			}
		}
		if baseUserID == 0 {
			var u model.User
			if err := dbpkg.DB.Where("role_id = 0").Order("id asc").First(&u).Error; err == nil {
				baseUserID = u.ID
			}
		}
		req := map[string]interface{}{
			"requestId":     RandUUID(),
			"port":          normalizedPorts[0].Port,
			"password":      password,
			"users":         buildAnyTLSUsersForNode(p.NodeID, password),
			"enforceVerify": isAnyTLSCertFeatureEnabled(),
		}
		certDomainRaw := ""
		if p.CertDomain != nil {
			certDomainRaw = strings.TrimSpace(*p.CertDomain)
		}
		certPayload, certErr := anyTLSCertPayload(p.NodeID, certDomainRaw)
		if certErr != nil {
			c.JSON(http.StatusOK, response.ErrMsg("AnyTLS证书生成失败: "+certErr.Error()))
			return
		}
		for k, v := range certPayload {
			req[k] = v
		}
		if baseUserID > 0 {
			req["baseUserId"] = baseUserID
		}
		req["allowFallback"] = allowFallback

		oldMappings := listAnyTLSPortMappings(p.NodeID)
		oldPortSet := map[int]struct{}{}
		for _, item := range oldMappings {
			oldPortSet[item.Port] = struct{}{}
		}
		newPortSet := map[int]struct{}{}
		for _, item := range normalizedPorts {
			newPortSet[item.Port] = struct{}{}
		}

		okAll := true
		failMsg := ""
		for idx, item := range normalizedPorts {
			reqInst := map[string]interface{}{}
			for k, v := range req {
				reqInst[k] = v
			}
			reqInst["requestId"] = RandUUID()
			reqInst["port"] = item.Port
			if item.ExitIP != "" {
				reqInst["exitIp"] = item.ExitIP
			} else {
				delete(reqInst, "exitIp")
			}
			res, ok := RequestOp(p.NodeID, "SetAnyTLS", reqInst, 12*time.Second)
			if !ok {
				okAll = false
				failMsg = fmt.Sprintf("节点未响应，端口 %d 下发失败", item.Port)
				break
			}
			msg := ""
			success := true
			if data, _ := res["data"].(map[string]interface{}); data != nil {
				if v, _ := data["message"].(string); v != "" {
					msg = v
				}
				if v, _ := data["success"].(bool); !v {
					success = false
				}
			}
			if !success {
				okAll = false
				if msg == "" {
					msg = fmt.Sprintf("端口 %d 下发失败", item.Port)
				}
				failMsg = msg
				break
			}
			_ = idx
		}
		if okAll {
			for oldPort := range oldPortSet {
				if _, keep := newPortSet[oldPort]; keep {
					continue
				}
				_, _ = RequestOp(p.NodeID, "SetAnyTLS", map[string]any{
					"requestId": RandUUID(),
					"port":      oldPort,
					"remove":    true,
				}, 8*time.Second)
			}
		}
		if okAll {
			msg := "AnyTLS 出口已创建/更新"
			now := time.Now().UnixMilli()
			tx := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&existing)
			if tx.Error == nil && existing.ID > 0 {
				existing.Port = normalizedPorts[0].Port
				existing.Password = password
				if baseUserID > 0 {
					existing.BaseUserID = &baseUserID
				}
				existing.UpdatedTime = now
				_ = dbpkg.DB.Save(&existing).Error
			} else {
				status := 1
				rec := model.AnyTLSSetting{
					BaseEntity: model.BaseEntity{CreatedTime: now, UpdatedTime: now, Status: &status},
					NodeID:     p.NodeID,
					Port:       normalizedPorts[0].Port,
					Password:   password,
					BaseUserID: func() *int64 {
						if baseUserID > 0 {
							return &baseUserID
						}
						return nil
					}(),
				}
				_ = dbpkg.DB.Create(&rec).Error
			}
			_ = saveAnyTLSPortMappings(p.NodeID, normalizedPorts)
			_ = setAnyTLSExitIP(p.NodeID, normalizedPorts[0].ExitIP)
			if p.AllowFallback != nil {
				_ = setAnyTLSExitFallback(p.NodeID, allowFallback)
			}
			outPorts := make([]map[string]any, 0, len(normalizedPorts))
			for _, it := range normalizedPorts {
				outPorts = append(outPorts, map[string]any{
					"port":   it.Port,
					"exitIp": it.ExitIP,
				})
			}
			c.JSON(http.StatusOK, response.Ok(gin.H{
				"msg":         msg,
				"port":        normalizedPorts[0].Port,
				"password":    password,
				"anytlsPorts": outPorts,
			}))
			return
		}
		if failMsg == "" {
			failMsg = "节点未响应，请稍后重试"
		}
		c.JSON(http.StatusOK, response.ErrMsg(failMsg))
		return
	}

	if isShared {
		if !portAllowedForShared(un, p.Port) {
			c.JSON(http.StatusOK, response.ErrMsg("端口不在授权范围"))
			return
		}
	}
	if p.Port <= 0 || p.Port > 65535 || strings.TrimSpace(p.Password) == "" {
		c.JSON(http.StatusOK, response.ErrMsg("无效的端口或密码"))
		return
	}
	p.Password = strings.TrimSpace(p.Password)
	if p.Method == "" && exitType == "ss" {
		p.Method = "AEAD_CHACHA20_POLY1305"
	}

	// Build service config (SS)
	name := fmt.Sprintf("exit_ss_%d", p.Port)
	var baseUserID int64
	if v, ok := c.Get("user_id"); ok {
		if id, ok2 := v.(int64); ok2 {
			baseUserID = id
		}
	}
	if baseUserID == 0 {
		var u model.User
		if err := dbpkg.DB.Where("role_id = 0").Order("id asc").First(&u).Error; err == nil {
			baseUserID = u.ID
		}
	}
	exitObserverName := ""
	var exitObserverSpec map[string]any
	if baseUserID > 0 {
		exitObserverName, exitObserverSpec = buildExitObserverPluginSpec(p.NodeID, baseUserID, p.Port)
	}
	obsName := exitObserverName
	if obsName == "" {
		obsName = strings.TrimSpace(p.Observer)
	}
	svc := buildSSService(name, p.Port, p.Password, p.Method, map[string]any{
		"observer": obsName,
		"limiter":  p.Limiter,
		"rlimiter": p.RLimiter,
		"metadata": p.Metadata,
	})
	if exitObserverSpec != nil {
		svc["_observers"] = []any{exitObserverSpec}
	}
	// 同步等待 agent 回执，便于捕获 GOST 配置错误
	req := map[string]interface{}{
		"requestId": RandUUID(),
		"services":  expandRUDP([]map[string]any{svc}),
	}
	if res, ok := RequestOp(p.NodeID, "AddService", req, 10*time.Second); ok {
		// Parse agent result
		msg := "出口节点服务已创建/更新"
		success := true
		if data, _ := res["data"].(map[string]interface{}); data != nil {
			if v, _ := data["message"].(string); v != "" {
				msg = v
			}
			if v, _ := data["success"].(bool); !v {
				success = false
			}
		}
		if !success {
			c.JSON(http.StatusOK, response.ErrMsg(msg))
			return
		}
		// persist settings for this node (upsert by node_id)
		now := time.Now().UnixMilli()
		var metaStr *string
		if p.Metadata != nil {
			if b, err := json.Marshal(p.Metadata); err == nil {
				s := string(b)
				metaStr = &s
			}
		}
		var existing model.ExitSetting
		tx := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&existing)
		if tx.Error == nil && existing.ID > 0 {
			existing.Port = p.Port
			existing.Password = p.Password
			existing.Method = p.Method
			existing.Observer = strPtrOrNil(p.Observer)
			existing.Limiter = strPtrOrNil(p.Limiter)
			existing.RLimiter = strPtrOrNil(p.RLimiter)
			if baseUserID > 0 {
				existing.BaseUserID = &baseUserID
			}
			existing.Metadata = metaStr
			existing.UpdatedTime = now
			_ = dbpkg.DB.Save(&existing).Error
		} else {
			status := 1
			rec := model.ExitSetting{
				BaseEntity: model.BaseEntity{CreatedTime: now, UpdatedTime: now, Status: &status},
				NodeID:     p.NodeID,
				Port:       p.Port,
				Password:   p.Password,
				Method:     p.Method,
				Observer:   strPtrOrNil(p.Observer),
				Limiter:    strPtrOrNil(p.Limiter),
				RLimiter:   strPtrOrNil(p.RLimiter),
				BaseUserID: func() *int64 {
					if baseUserID > 0 {
						return &baseUserID
					}
					return nil
				}(),
				Metadata: metaStr,
			}
			_ = dbpkg.DB.Create(&rec).Error
		}
		c.JSON(http.StatusOK, response.OkMsg(msg))
		return
	}

	c.JSON(http.StatusOK, response.ErrMsg("节点未响应，请稍后重试"))
	return

}

// NodeGetExit 获取出口节点配置
// @Summary 获取出口节点配置
// @Tags node
// @Accept json
// @Produce json
// @Param data body SwaggerNodeSimpleReq true "节点ID"
// @Success 200 {object} SwaggerResp
// @Router /api/v1/node/get-exit [post]
// POST /api/v1/node/get-exit {nodeId}
// Returns last saved SS exit settings for node if any
func NodeGetExit(c *gin.Context) {
	var p struct {
		NodeID int64  `json:"nodeId" binding:"required"`
		Type   string `json:"type"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	exitType := strings.ToLower(strings.TrimSpace(p.Type))
	if exitType == "" {
		exitType = "ss"
	}
	if exitType == "anytls" {
		var item model.AnyTLSSetting
		if err := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&item).Error; err != nil || item.ID == 0 {
			c.JSON(http.StatusOK, response.OkNoData())
			return
		}
		ports := listAnyTLSPortMappings(p.NodeID)
		if len(ports) == 0 && item.Port > 0 {
			ports = []anyTLSPortMapping{{
				Port:   item.Port,
				ExitIP: getAnyTLSExitIP(p.NodeID),
			}}
		}
		exitIP := ""
		if len(ports) > 0 {
			exitIP = strings.TrimSpace(ports[0].ExitIP)
		}
		allowFallback := getAnyTLSExitFallback(p.NodeID)
		certDomain := getAnyTLSCertDomain(p.NodeID)
		if isAnyTLSCertFeatureEnabled() && strings.TrimSpace(certDomain) == "" {
			if v, err := ensureAnyTLSCertDomain(p.NodeID, ""); err == nil {
				certDomain = v
			}
		}
		certStatus, _ := anyTLSNodeCertStatus(p.NodeID, false)
		out := gin.H{
			"nodeId":        item.NodeID,
			"port":          item.Port,
			"password":      item.Password,
			"type":          "anytls",
			"exitIp":        exitIP,
			"anytlsPorts":   ports,
			"allowFallback": allowFallback,
			"certDomain":    certDomain,
			"certStatus":    certStatus,
		}
		c.JSON(http.StatusOK, response.Ok(out))
		return
	}
	var item model.ExitSetting
	if err := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&item).Error; err != nil || item.ID == 0 {
		c.JSON(http.StatusOK, response.OkNoData())
		return
	}
	// unpack metadata JSON string into map for frontend convenience
	var meta map[string]interface{}
	if item.Metadata != nil && *item.Metadata != "" {
		_ = json.Unmarshal([]byte(*item.Metadata), &meta)
	}
	out := gin.H{
		"nodeId":   item.NodeID,
		"port":     item.Port,
		"password": item.Password,
		"method":   item.Method,
		"observer": deref(item.Observer),
		"limiter":  deref(item.Limiter),
		"rlimiter": deref(item.RLimiter),
		"metadata": meta,
	}
	c.JSON(http.StatusOK, response.Ok(out))
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func anytlsExitIPKey(nodeID int64) string { return fmt.Sprintf("anytls_exit_ip_%d", nodeID) }
func anytlsExitFallbackKey(nodeID int64) string {
	return fmt.Sprintf("anytls_exit_fallback_%d", nodeID)
}

func setAnyTLSExitIP(nodeID int64, ip string) error {
	key := anytlsExitIPKey(nodeID)
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return dbpkg.DB.Where("name = ?", key).Delete(&model.ViteConfig{}).Error
	}
	now := time.Now().UnixMilli()
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).First(&cfg).Error; err == nil {
		cfg.Value = ip
		cfg.Time = now
		return dbpkg.DB.Save(&cfg).Error
	}
	return dbpkg.DB.Create(&model.ViteConfig{Name: key, Value: ip, Time: now}).Error
}

func getAnyTLSExitIP(nodeID int64) string {
	key := anytlsExitIPKey(nodeID)
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).First(&cfg).Error; err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Value)
}

func setAnyTLSExitFallback(nodeID int64, allow bool) error {
	key := anytlsExitFallbackKey(nodeID)
	val := "false"
	if allow {
		val = "true"
	}
	now := time.Now().UnixMilli()
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).First(&cfg).Error; err == nil {
		cfg.Value = val
		cfg.Time = now
		return dbpkg.DB.Save(&cfg).Error
	}
	return dbpkg.DB.Create(&model.ViteConfig{Name: key, Value: val, Time: now}).Error
}

func getAnyTLSExitFallback(nodeID int64) bool {
	key := anytlsExitFallbackKey(nodeID)
	var cfg model.ViteConfig
	if err := dbpkg.DB.Where("name = ?", key).First(&cfg).Error; err != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Value), "true")
}

// NodeAnyTLSCertPreview ensures and returns AnyTLS cert info for a node.
// POST /api/v1/node/anytls-cert-preview {nodeId}
func NodeAnyTLSCertPreview(c *gin.Context) {
	var p struct {
		NodeID int64 `json:"nodeId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	if _, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, true); !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if !isAnyTLSCertFeatureEnabled() {
		c.JSON(http.StatusOK, response.ErrMsg("控制器未启用 AnyTLS 证书"))
		return
	}
	st, err := anyTLSNodeCertStatus(p.NodeID, true)
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("获取AnyTLS证书信息失败: "+err.Error()))
		return
	}
	if st == nil {
		c.JSON(http.StatusOK, response.OkNoData())
		return
	}
	c.JSON(http.StatusOK, response.Ok(st))
}

// NodeAnyTLSCertChainCheck actively probes node AnyTLS TLS chain against controller CA.
// POST /api/v1/node/anytls-cert-chain-check {nodeId}
func NodeAnyTLSCertChainCheck(c *gin.Context) {
	var p struct {
		NodeID int64 `json:"nodeId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	node, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, true)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if !isAnyTLSCertFeatureEnabled() {
		c.JSON(http.StatusOK, response.ErrMsg("控制器未启用 AnyTLS 证书"))
		return
	}
	var st model.AnyTLSSetting
	if err := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&st).Error; err != nil || st.ID == 0 {
		c.JSON(http.StatusOK, response.ErrMsg("该节点尚未配置 AnyTLS 出口"))
		return
	}
	certSt, err := anyTLSNodeCertStatus(p.NodeID, true)
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("读取证书信息失败: "+err.Error()))
		return
	}
	domain := ""
	if certSt != nil {
		if v, _ := certSt["domain"].(string); strings.TrimSpace(v) != "" {
			domain = strings.TrimSpace(v)
		}
	}
	if domain == "" {
		c.JSON(http.StatusOK, response.ErrMsg("证书域名为空"))
		return
	}

	hosts := candidateNodeHosts(node)
	if len(hosts) == 0 {
		c.JSON(http.StatusOK, response.ErrMsg("节点地址为空"))
		return
	}
	caCert, _, caPEM, err := ensureAnyTLSCA()
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("读取控制器CA失败: "+err.Error()))
		return
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(caPEM)); !ok {
		c.JSON(http.StatusOK, response.ErrMsg("控制器CA格式无效"))
		return
	}

	attempts := make([]map[string]any, 0, len(hosts))
	selectedAddr := ""
	verifyOK := false
	verifyErr := ""
	var peerCert *x509.Certificate
	for _, h := range hosts {
		addr := net.JoinHostPort(h, strconv.Itoa(st.Port))
		ok, errStr, peer := probeAnyTLSAddress(addr, domain, roots)
		att := map[string]any{
			"addr":     addr,
			"verifyOK": ok,
		}
		if errStr != "" {
			att["verifyErr"] = errStr
		}
		if peer != nil {
			att["peer"] = certSummary(peer)
		}
		attempts = append(attempts, att)
		if selectedAddr == "" && (ok || peer != nil) {
			selectedAddr = addr
			verifyOK = ok
			verifyErr = errStr
			peerCert = peer
		}
		if ok {
			break
		}
	}
	if selectedAddr == "" && len(attempts) > 0 {
		selectedAddr, _ = attempts[0]["addr"].(string)
		verifyErr, _ = attempts[0]["verifyErr"].(string)
	}

	c.JSON(http.StatusOK, response.Ok(gin.H{
		"nodeId":       p.NodeID,
		"nodeName":     node.Name,
		"domain":       domain,
		"port":         st.Port,
		"selectedAddr": selectedAddr,
		"verifyOK":     verifyOK,
		"verifyErr":    verifyErr,
		"chainMatched": verifyOK,
		"checkedAtMs":  time.Now().UnixMilli(),
		"ca":           certSummary(caCert),
		"peer":         certSummary(peerCert),
		"attempts":     attempts,
	}))
}

// NodeAnyTLSCertReissue forces AnyTLS node cert re-issuance and pushes it to agent immediately.
// POST /api/v1/node/anytls-cert-reissue {nodeId, certDomain?}
func NodeAnyTLSCertReissue(c *gin.Context) {
	var p struct {
		NodeID     int64  `json:"nodeId" binding:"required"`
		CertDomain string `json:"certDomain"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	if _, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, true); !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if !isAnyTLSCertFeatureEnabled() {
		c.JSON(http.StatusOK, response.ErrMsg("控制器未启用 AnyTLS 证书"))
		return
	}

	var st model.AnyTLSSetting
	if err := dbpkg.DB.Where("node_id = ?", p.NodeID).First(&st).Error; err != nil || st.ID == 0 {
		c.JSON(http.StatusOK, response.ErrMsg("该节点尚未配置 AnyTLS 出口"))
		return
	}

	certDomainRaw := strings.TrimSpace(p.CertDomain)
	if certDomainRaw != "" {
		if _, err := setAnyTLSCertDomain(p.NodeID, certDomainRaw); err != nil {
			c.JSON(http.StatusOK, response.ErrMsg("证书域名无效: "+err.Error()))
			return
		}
	}
	revision, err := bumpAnyTLSCertRevision(p.NodeID)
	if err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("证书重签失败: "+err.Error()))
		return
	}

	allowFallback := getAnyTLSExitFallback(p.NodeID)
	ports := listAnyTLSPortMappings(p.NodeID)
	if len(ports) == 0 && st.Port > 0 {
		ports = []anyTLSPortMapping{{
			Port:   st.Port,
			ExitIP: getAnyTLSExitIP(p.NodeID),
		}}
	}
	if len(ports) == 0 {
		c.JSON(http.StatusOK, response.ErrMsg("该节点尚未配置 AnyTLS 端口"))
		return
	}
	baseUserID := int64(0)
	if st.BaseUserID != nil {
		baseUserID = *st.BaseUserID
	}
	if baseUserID == 0 {
		baseUserID = defaultAnyTLSBaseUserID()
	}

	req := map[string]any{
		"requestId":     RandUUID(),
		"port":          ports[0].Port,
		"password":      st.Password,
		"allowFallback": allowFallback,
		"users":         buildAnyTLSUsersForNode(p.NodeID, st.Password),
	}
	if baseUserID > 0 {
		req["baseUserId"] = baseUserID
	}

	certPayload, certErr := anyTLSCertPayload(p.NodeID, certDomainRaw)
	if certErr != nil {
		c.JSON(http.StatusOK, response.ErrMsg("AnyTLS证书生成失败: "+certErr.Error()))
		return
	}
	for k, v := range certPayload {
		req[k] = v
	}
	msg := "AnyTLS 证书已重新颁发并下发"
	for _, item := range ports {
		reqInst := map[string]any{}
		for k, v := range req {
			reqInst[k] = v
		}
		reqInst["requestId"] = RandUUID()
		reqInst["port"] = item.Port
		if strings.TrimSpace(item.ExitIP) != "" {
			reqInst["exitIp"] = strings.TrimSpace(item.ExitIP)
		} else {
			delete(reqInst, "exitIp")
		}
		res, ok := RequestOp(p.NodeID, "SetAnyTLS", reqInst, 12*time.Second)
		if !ok {
			c.JSON(http.StatusOK, response.ErrMsg(fmt.Sprintf("节点未响应，端口 %d 证书下发失败", item.Port)))
			return
		}
		success := true
		if data, _ := res["data"].(map[string]interface{}); data != nil {
			if v, _ := data["message"].(string); v != "" {
				msg = v
			}
			if v, _ := data["success"].(bool); !v {
				success = false
			}
		}
		if !success {
			c.JSON(http.StatusOK, response.ErrMsg(msg))
			return
		}
	}
	certStatus, _ := anyTLSNodeCertStatus(p.NodeID, false)
	c.JSON(http.StatusOK, response.Ok(gin.H{
		"message":    msg,
		"revision":   revision,
		"certDomain": certPayload["certDomain"],
		"certStatus": certStatus,
	}))
}
