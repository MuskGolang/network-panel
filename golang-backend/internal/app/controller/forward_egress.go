package controller

import (
	"encoding/json"
	"strings"
)

type forwardEgressItem struct {
	IP     string `json:"ip"`
	Suffix string `json:"suffix,omitempty"`
}

func normalizeForwardEgressItems(items []forwardEgressItem) []forwardEgressItem {
	if len(items) == 0 {
		return nil
	}
	out := make([]forwardEgressItem, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		ip := normalizeEgressIP(item.IP)
		if ip == "" {
			continue
		}
		suffix := normalizeForwardEgressSuffix(item.Suffix)
		key := ip + "\x00" + suffix
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, forwardEgressItem{IP: ip, Suffix: suffix})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeForwardEgressSuffix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.TrimSpace(s)
	return s
}

func parseForwardEgressItems(raw string) []forwardEgressItem {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var items []forwardEgressItem
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}
	return normalizeForwardEgressItems(items)
}

func encodeForwardEgressItems(items []forwardEgressItem) string {
	items = normalizeForwardEgressItems(items)
	if len(items) == 0 {
		return ""
	}
	b, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	return string(b)
}

func appendForwardNameSuffix(baseName, suffix string) string {
	baseName = strings.TrimSpace(baseName)
	suffix = normalizeForwardEgressSuffix(suffix)
	if suffix == "" {
		return baseName
	}
	if strings.HasPrefix(suffix, "-") || strings.HasPrefix(suffix, "_") || strings.HasPrefix(suffix, ".") || strings.HasPrefix(suffix, " ") {
		return baseName + suffix
	}
	return baseName + "-" + suffix
}

func cloneStringAnyMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
