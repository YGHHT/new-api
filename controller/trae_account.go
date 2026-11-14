package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel/trae"

	"github.com/gin-gonic/gin"
)

func loadTraeChannel(c *gin.Context) *model.Channel {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, fmt.Errorf("invalid channel id: %w", err))
		return nil
	}
	ch, err := model.GetChannelById(id, true)
	if err != nil {
		common.ApiError(c, err)
		return nil
	}
	if ch.Type != constant.ChannelTypeTrae {
		common.ApiErrorMsg(c, "this endpoint serves Trae channels only")
		return nil
	}
	return ch
}

// StartTraeLogin 返回 Trae 授权页链接；用户在浏览器授权后把回调地址贴回来。
func StartTraeLogin(c *gin.Context) {
	if loadTraeChannel(c) == nil {
		return
	}
	flow := trae.StartOAuthLogin()
	common.ApiSuccess(c, gin.H{"url": flow.URL, "state": flow.State})
}

// TraeLoginCallback 用回调地址（或 authCode+verifier）换回 JWT 并写入渠道。
func TraeLoginCallback(c *gin.Context) {
	ch := loadTraeChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		CallbackURL string `json:"callback_url"`
		RedirectURL string `json:"redirect_url"`
		URL         string `json:"url"`
		AuthCode    string `json:"auth_code"`
		Verifier    string `json:"verifier"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiError(c, err)
		return
	}
	raw := firstNonEmptyTrimmed(req.CallbackURL, req.RedirectURL, req.URL)

	var cred *trae.Credential
	var err error
	if strings.TrimSpace(req.AuthCode) != "" {
		cred, err = trae.ExchangeAuthCode(req.AuthCode, req.Verifier)
	} else {
		cred, err = trae.ParseCallbackURL(raw)
	}
	if err != nil {
		common.ApiError(c, err)
		return
	}
	encoded, err := cred.MarshalCredential()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
		stored.Key = upsertTraeCredential(stored.Key, cred.UID, encoded)
		return nil
	}); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"uid": cred.UID, "name": cred.Name})
}

// ListTraeAccounts 列出渠道 Key 里的账号（令牌脱敏）。
func ListTraeAccounts(c *gin.Context) {
	ch := loadTraeChannel(c)
	if ch == nil {
		return
	}
	items := make([]gin.H, 0)
	for _, line := range trae.SplitCredentialLines(ch.Key) {
		cred, err := trae.ParseCredential(line)
		if err != nil {
			continue
		}
		items = append(items, gin.H{
			"uid":              cred.UID,
			"name":             cred.Name,
			"jwt":              maskSecret(cred.JWT),
			"expires_at":       trae.JWTExpiry(cred.JWT),
			"needs_refresh":    cred.NeedsRefresh(),
			"credits":          cred.Credits,
			"credits_total":    cred.CreditsTotal,
			"last_checkin_day": cred.LastCheckinDay,
		})
	}
	common.ApiSuccess(c, gin.H{"items": items, "total": len(items)})
}

// TraeCheckin 对渠道里的账号逐个签到并回写。
func TraeCheckin(c *gin.Context) {
	ch := loadTraeChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		UID string `json:"uid"`
	}
	_ = c.ShouldBindJSON(&req)
	today := time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02")
	updates := map[string]string{}
	results := make([]gin.H, 0)

	for _, line := range trae.SplitCredentialLines(ch.Key) {
		cred, perr := trae.ParseCredential(line)
		if perr != nil {
			continue
		}
		if req.UID != "" && cred.UID != req.UID {
			continue
		}
		res := trae.DailyCheckin(cred)
		item := gin.H{
			"uid":     cred.UID,
			"name":    cred.Name,
			"status":  res.Status,
			"credits": res.Credits,
			"message": res.Message,
		}
		if res.Status == "checked" || res.Status == "already" {
			cred.LastCheckinDay = today
			if bal, berr := trae.FetchBalance(cred); berr == nil {
				cred.Credits, cred.CreditsTotal = bal.Remaining, bal.Total
				item["balance"] = bal.Remaining
				item["balance_total"] = bal.Total
			}
			if encoded, merr := cred.MarshalCredential(); merr == nil {
				updates[cred.UID] = encoded
			}
		}
		results = append(results, item)
	}

	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyTraeUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

// TraeBalance 刷新余额快照并回写渠道 Key。
func TraeBalance(c *gin.Context) {
	ch := loadTraeChannel(c)
	if ch == nil {
		return
	}
	updates := map[string]string{}
	results := make([]gin.H, 0)
	for _, line := range trae.SplitCredentialLines(ch.Key) {
		cred, perr := trae.ParseCredential(line)
		if perr != nil {
			continue
		}
		bal, berr := trae.FetchBalance(cred)
		item := gin.H{"uid": cred.UID, "name": cred.Name}
		if berr != nil {
			item["error"] = berr.Error()
		} else {
			cred.Credits, cred.CreditsTotal = bal.Remaining, bal.Total
			item["credits"] = bal.Remaining
			item["credits_total"] = bal.Total
			if encoded, merr := cred.MarshalCredential(); merr == nil {
				updates[cred.UID] = encoded
			}
		}
		results = append(results, item)
	}
	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyTraeUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

func upsertTraeCredential(key, uid, encoded string) string {
	lines := trae.SplitCredentialLines(key)
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		cred, err := trae.ParseCredential(line)
		if err == nil && cred.UID == uid {
			out = append(out, encoded)
			replaced = true
		} else {
			out = append(out, line)
		}
	}
	if !replaced {
		out = append(out, encoded)
	}
	return strings.Join(out, "\n")
}

func applyTraeUpdates(key string, updates map[string]string) string {
	lines := trae.SplitCredentialLines(key)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		cred, err := trae.ParseCredential(line)
		if err == nil {
			if encoded, ok := updates[cred.UID]; ok {
				out = append(out, encoded)
				continue
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func firstNonEmptyTrimmed(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ = http.StatusOK
