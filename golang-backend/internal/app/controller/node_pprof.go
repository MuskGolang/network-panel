package controller

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"network-panel/golang-backend/internal/app/response"
)

// NodePprofControl toggles runtime pprof endpoint on agent.
// @Summary 控制节点 pprof 开关
// @Tags node
// @Accept json
// @Produce json
// @Param data body object true "nodeId, action(enable|disable|status), addr(optional)"
// @Success 200 {object} SwaggerResp
// @Router /api/v1/node/pprof/control [post]
func NodePprofControl(c *gin.Context) {
	var p struct {
		NodeID int64  `json:"nodeId" binding:"required"`
		Action string `json:"action"`
		Addr   string `json:"addr"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	node, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, false)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if !IsNodeWSOnline(node.ID) {
		c.JSON(http.StatusOK, response.ErrMsg("节点不在线（WS未连接）"))
		return
	}
	action := strings.ToLower(strings.TrimSpace(p.Action))
	if action == "" {
		action = "status"
	}
	addr := strings.TrimSpace(p.Addr)
	if action == "enable" || action == "start" {
		if addr == "" {
			addr = "127.0.0.1:6060"
		}
	}
	req := map[string]interface{}{
		"requestId": RandUUID(),
		"action":    action,
		"addr":      addr,
	}
	res, ok := RequestOp(node.ID, "PprofControl", req, 10*time.Second)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg("节点未响应，请稍后重试"))
		return
	}
	data, _ := res["data"].(map[string]interface{})
	if data == nil {
		c.JSON(http.StatusOK, response.ErrMsg("节点返回异常"))
		return
	}
	if s, _ := data["success"].(bool); !s {
		msg, _ := data["message"].(string)
		if strings.TrimSpace(msg) == "" {
			msg = "操作失败"
		}
		c.JSON(http.StatusOK, response.ErrMsg(msg))
		return
	}
	c.JSON(http.StatusOK, response.Ok(data))
}

// NodePprofFetch fetches pprof text snapshot from agent.
// @Summary 获取节点 pprof 文本快照
// @Tags node
// @Accept json
// @Produce json
// @Param data body object true "nodeId, profile(goroutine|heap|mutex|block|threadcreate), debug"
// @Success 200 {object} SwaggerResp
// @Router /api/v1/node/pprof/fetch [post]
func NodePprofFetch(c *gin.Context) {
	var p struct {
		NodeID   int64  `json:"nodeId" binding:"required"`
		Profile  string `json:"profile"`
		Debug    int    `json:"debug"`
		WithAddr bool   `json:"withAddr"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusOK, response.ErrMsg("参数错误"))
		return
	}
	node, _, _, _, _, errMsg, ok := nodeAccess(c, p.NodeID, false)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg(errMsg))
		return
	}
	if !IsNodeWSOnline(node.ID) {
		c.JSON(http.StatusOK, response.ErrMsg("节点不在线（WS未连接）"))
		return
	}
	prof := strings.ToLower(strings.TrimSpace(p.Profile))
	if prof == "" {
		prof = "goroutine"
	}
	if p.Debug <= 0 {
		p.Debug = 1
	}
	req := map[string]interface{}{
		"requestId": RandUUID(),
		"profile":   prof,
		"debug":     p.Debug,
	}
	res, ok := RequestOp(node.ID, "PprofFetch", req, 15*time.Second)
	if !ok {
		c.JSON(http.StatusOK, response.ErrMsg("节点未响应，请稍后重试"))
		return
	}
	data, _ := res["data"].(map[string]interface{})
	if data == nil {
		c.JSON(http.StatusOK, response.ErrMsg("节点返回异常"))
		return
	}
	if s, _ := data["success"].(bool); !s {
		msg, _ := data["message"].(string)
		if strings.TrimSpace(msg) == "" {
			msg = "获取失败"
		}
		c.JSON(http.StatusOK, response.ErrMsg(msg))
		return
	}
	c.JSON(http.StatusOK, response.Ok(data))
}
