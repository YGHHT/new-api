package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel/workbuddy"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// WorkBuddy 设备授权是「浏览器完成 + 后端轮询」的两段式流程：state 只在
// 15 分钟内有效，且轮询期间必须记住站点（CN / intl / workbuddy 的 platform
// 与主机不同）。会话放进程内即可，与 panel 的做法一致。
type wbLoginSession struct {
	Site      workbuddy.Site
	CreatedAt time.Time
}

var (
	wbLoginMu sync.Mutex
	wbLogins  = map[string]wbLoginSession{}
)

const wbLoginTTL = 15 * time.Minute

func pruneWBLoginsLocked() {
	for state, sess := range wbLogins {
		if time.Since(sess.CreatedAt) > wbLoginTTL {
			delete(wbLogins, state)
		}
	}
}

func loadWorkBuddyChannel(c *gin.Context) *model.Channel {
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
	if ch.Type != constant.ChannelTypeWorkBuddy {
		common.ApiErrorMsg(c, "this endpoint serves WorkBuddy channels only")
		return nil
	}
	return ch
}

func workBuddyHTTPClient(ch *model.Channel) (*http.Client, error) {
	setting := ch.GetSetting()
	return service.GetHttpClientWithProxySettings(setting.Proxy, setting)
}

// StartWorkBuddyLogin 发起设备授权，返回浏览器打开的链接与 state。
func StartWorkBuddyLogin(c *gin.Context) {
	ch := loadWorkBuddyChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		Site  string `json:"site"`
		Realm string `json:"realm"`
	}
	_ = c.ShouldBindJSON(&req)
	site := workbuddy.ResolveSite(req.Site)
	if strings.TrimSpace(req.Site) == "" {
		site = workbuddy.ResolveSiteByRealm(req.Realm)
	}
	client, err := workBuddyHTTPClient(ch)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	flow, err := workbuddy.StartDeviceLogin(client, site)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	wbLoginMu.Lock()
	pruneWBLoginsLocked()
	wbLogins[flow.State] = wbLoginSession{Site: site, CreatedAt: time.Now()}
	wbLoginMu.Unlock()

	common.ApiSuccess(c, gin.H{
		"url":        flow.AuthURL,
		"state":      flow.State,
		"realm":      site.Realm,
		"site":       site.ID,
		"expires_in": int(wbLoginTTL.Seconds()),
	})
}

// PollWorkBuddyLogin 轮询一次；完成后把账号写进渠道 Key（一行一个账号）。
func PollWorkBuddyLogin(c *gin.Context) {
	ch := loadWorkBuddyChannel(c)
	if ch == nil {
		return
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		common.ApiErrorMsg(c, "missing state")
		return
	}
	wbLoginMu.Lock()
	sess, ok := wbLogins[state]
	wbLoginMu.Unlock()
	if !ok || time.Since(sess.CreatedAt) > wbLoginTTL {
		c.JSON(http.StatusGone, gin.H{"success": false, "message": "login session expired, start again"})
		return
	}
	client, err := workBuddyHTTPClient(ch)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	cred, done, err := workbuddy.PollDeviceLogin(client, sess.Site, state)
	if err != nil {
		wbLoginMu.Lock()
		delete(wbLogins, state)
		wbLoginMu.Unlock()
		common.ApiError(c, err)
		return
	}
	if !done {
		common.ApiSuccess(c, gin.H{"done": false, "message": "waiting for browser authorization"})
		return
	}
	encoded, err := cred.MarshalCredential()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
		stored.Key = upsertWorkBuddyCredential(stored.Key, cred.UID, encoded)
		return nil
	}); err != nil {
		common.ApiError(c, err)
		return
	}
	wbLoginMu.Lock()
	delete(wbLogins, state)
	wbLoginMu.Unlock()

	common.ApiSuccess(c, gin.H{
		"done":     true,
		"uid":      cred.UID,
		"nickname": cred.Nickname,
		"realm":    cred.Realm,
	})
}

// ListWorkBuddyAccounts 列出渠道 Key 里的账号（令牌脱敏）。
func ListWorkBuddyAccounts(c *gin.Context) {
	ch := loadWorkBuddyChannel(c)
	if ch == nil {
		return
	}
	items := make([]gin.H, 0)
	for _, line := range splitCredentialLines(ch.Key) {
		cred, err := workbuddy.ParseCredential(line)
		if err != nil {
			continue
		}
		items = append(items, gin.H{
			"uid":              cred.UID,
			"nickname":         cred.Nickname,
			"realm":            cred.Realm,
			"enterprise_id":    cred.EnterpriseID,
			"access_token":     maskSecret(cred.AccessToken),
			"expires_at":       cred.ExpiresAt,
			"needs_refresh":    cred.NeedsRefresh(),
			"credits":          cred.Credits,
			"credits_total":    cred.CreditsTotal,
			"last_checkin_day": cred.LastCheckinDay,
		})
	}
	common.ApiSuccess(c, gin.H{"items": items, "total": len(items)})
}

// WorkBuddyCheckin 对渠道里的账号逐个签到，并把结果回写到 Key 行。
func WorkBuddyCheckin(c *gin.Context) {
	ch := loadWorkBuddyChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		UID string `json:"uid"`
	}
	_ = c.ShouldBindJSON(&req)
	client, err := workBuddyHTTPClient(ch)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	today := time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02")
	updates := map[string]string{}
	results := make([]gin.H, 0)

	for _, line := range splitCredentialLines(ch.Key) {
		cred, perr := workbuddy.ParseCredential(line)
		if perr != nil {
			continue
		}
		if req.UID != "" && cred.UID != req.UID {
			continue
		}
		res, cerr := workbuddy.DailyCheckin(client, cred, ch.GetBaseURL())
		item := gin.H{
			"uid":      cred.UID,
			"nickname": cred.Nickname,
			"state":    res.State,
			"credit":   res.Credit,
			"streak":   res.StreakDays,
			"message":  res.Message,
		}
		if res.State == "checked" || res.State == "already" {
			cred.LastCheckinDay = today
			if bal, berr := workbuddy.FetchBalance(client, cred, ch.GetBaseURL()); berr == nil {
				cred.Credits, cred.CreditsTotal = bal.Remain, bal.Total
				item["credits"] = bal.Remain
				item["credits_total"] = bal.Total
			}
			if encoded, merr := cred.MarshalCredential(); merr == nil {
				updates[cred.UID] = encoded
			}
		}
		if cerr != nil {
			item["error"] = cerr.Error()
		}
		results = append(results, item)
	}

	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyWorkBuddyUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

// WorkBuddyBalance 刷新余额快照并回写渠道 Key。
func WorkBuddyBalance(c *gin.Context) {
	ch := loadWorkBuddyChannel(c)
	if ch == nil {
		return
	}
	client, err := workBuddyHTTPClient(ch)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	updates := map[string]string{}
	results := make([]gin.H, 0)
	for _, line := range splitCredentialLines(ch.Key) {
		cred, perr := workbuddy.ParseCredential(line)
		if perr != nil {
			continue
		}
		bal, berr := workbuddy.FetchBalance(client, cred, ch.GetBaseURL())
		item := gin.H{"uid": cred.UID, "nickname": cred.Nickname}
		if berr != nil {
			item["error"] = berr.Error()
		} else {
			cred.Credits, cred.CreditsTotal = bal.Remain, bal.Total
			item["credits"] = bal.Remain
			item["credits_total"] = bal.Total
			if encoded, merr := cred.MarshalCredential(); merr == nil {
				updates[cred.UID] = encoded
			}
		}
		results = append(results, item)
	}
	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyWorkBuddyUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

func splitCredentialLines(key string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// upsertWorkBuddyCredential 同 UID 替换、新 UID 追加，保留其余行。
func upsertWorkBuddyCredential(key, uid, encoded string) string {
	lines := splitCredentialLines(key)
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		cred, err := workbuddy.ParseCredential(line)
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

func applyWorkBuddyUpdates(key string, updates map[string]string) string {
	lines := splitCredentialLines(key)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		cred, err := workbuddy.ParseCredential(line)
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

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
