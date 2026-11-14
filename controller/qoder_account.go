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
	"github.com/QuantumNous/new-api/relay/channel/qoder"

	"github.com/gin-gonic/gin"
)

// Qoder device authorization is a browser-complete + backend-poll flow like
// WorkBuddy: the nonce/verifier pair lives in-process for 15 minutes.
type qdLoginSession struct {
	Realm     string
	Verifier  string
	CreatedAt time.Time
}

var (
	qdLoginMu sync.Mutex
	qdLogins  = map[string]qdLoginSession{}
)

const qdLoginTTL = 15 * time.Minute

func pruneQDLoginsLocked() {
	for state, sess := range qdLogins {
		if time.Since(sess.CreatedAt) > qdLoginTTL {
			delete(qdLogins, state)
		}
	}
}

func loadQoderChannel(c *gin.Context) *model.Channel {
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
	if ch.Type != constant.ChannelTypeQoder {
		common.ApiErrorMsg(c, "this endpoint serves Qoder channels only")
		return nil
	}
	return ch
}

// StartQoderLogin 发起设备授权，返回浏览器打开的链接与 state。
func StartQoderLogin(c *gin.Context) {
	ch := loadQoderChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		Realm string `json:"realm"`
	}
	_ = c.ShouldBindJSON(&req)
	flow, err := qoder.StartDeviceLogin(req.Realm)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	qdLoginMu.Lock()
	pruneQDLoginsLocked()
	qdLogins[flow.State] = qdLoginSession{Realm: flow.Realm, Verifier: flow.Verifier, CreatedAt: time.Now()}
	qdLoginMu.Unlock()

	common.ApiSuccess(c, gin.H{
		"url":        flow.URL,
		"state":      flow.State,
		"realm":      flow.Realm,
		"expires_in": int(qdLoginTTL.Seconds()),
	})
}

// PollQoderLogin 轮询一次；完成后把账号写进渠道 Key（一行一个账号）。
func PollQoderLogin(c *gin.Context) {
	ch := loadQoderChannel(c)
	if ch == nil {
		return
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		common.ApiErrorMsg(c, "missing state")
		return
	}
	qdLoginMu.Lock()
	sess, ok := qdLogins[state]
	qdLoginMu.Unlock()
	if !ok || time.Since(sess.CreatedAt) > qdLoginTTL {
		c.JSON(http.StatusGone, gin.H{"success": false, "message": "login session expired, start again"})
		return
	}
	cred, done, err := qoder.PollDeviceLogin(sess.Realm, state, sess.Verifier)
	if err != nil {
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
		stored.Key = upsertQoderCredential(stored.Key, cred.UID, encoded)
		return nil
	}); err != nil {
		common.ApiError(c, err)
		return
	}
	qdLoginMu.Lock()
	delete(qdLogins, state)
	qdLoginMu.Unlock()

	common.ApiSuccess(c, gin.H{
		"done":     true,
		"uid":      cred.UID,
		"nickname": cred.Nickname,
		"realm":    cred.Realm,
	})
}

// ImportQoderPAT 用个人访问令牌导入账号。
func ImportQoderPAT(c *gin.Context) {
	ch := loadQoderChannel(c)
	if ch == nil {
		return
	}
	var req struct {
		PAT   string `json:"pat"`
		Realm string `json:"realm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiError(c, err)
		return
	}
	cred, err := qoder.ImportPAT(req.PAT, req.Realm)
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
		stored.Key = upsertQoderCredential(stored.Key, cred.UID, encoded)
		return nil
	}); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"uid": cred.UID, "nickname": cred.Nickname, "realm": cred.Realm})
}

// ListQoderAccounts 列出渠道 Key 里的账号（令牌脱敏）。
func ListQoderAccounts(c *gin.Context) {
	ch := loadQoderChannel(c)
	if ch == nil {
		return
	}
	items := make([]gin.H, 0)
	for _, line := range qoder.SplitCredentialLines(ch.Key) {
		cred, err := qoder.ParseCredential(line)
		if err != nil {
			continue
		}
		items = append(items, gin.H{
			"uid":              cred.UID,
			"nickname":         cred.Nickname,
			"realm":            cred.Realm,
			"source":           cred.Source,
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

// QoderCheckin 对渠道里的账号逐个签到，并把结果回写到 Key 行。
func QoderCheckin(c *gin.Context) {
	ch := loadQoderChannel(c)
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

	for _, line := range qoder.SplitCredentialLines(ch.Key) {
		cred, perr := qoder.ParseCredential(line)
		if perr != nil {
			continue
		}
		if req.UID != "" && cred.UID != req.UID {
			continue
		}
		res, cerr := qoder.DailyCheckin(cred)
		item := gin.H{
			"uid":      cred.UID,
			"nickname": cred.Nickname,
			"status":   "",
			"credits":  int64(0),
			"message":  "",
		}
		if res != nil {
			item["status"] = res.Status
			item["credits"] = res.Credits
			item["message"] = res.Message
			if res.Status == "claimed" || res.Status == "already" {
				cred.LastCheckinDay = today
				if bal, berr := qoder.FetchBalance(cred); berr == nil {
					cred.Credits, cred.CreditsTotal = bal.Remaining, bal.Total
					item["balance"] = bal.Remaining
					item["balance_total"] = bal.Total
				}
				if encoded, merr := cred.MarshalCredential(); merr == nil {
					updates[cred.UID] = encoded
				}
			}
		}
		if cerr != nil {
			item["error"] = cerr.Error()
		}
		results = append(results, item)
	}

	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyQoderUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

// QoderBalance 刷新余额快照并回写渠道 Key。
func QoderBalance(c *gin.Context) {
	ch := loadQoderChannel(c)
	if ch == nil {
		return
	}
	updates := map[string]string{}
	results := make([]gin.H, 0)
	for _, line := range qoder.SplitCredentialLines(ch.Key) {
		cred, perr := qoder.ParseCredential(line)
		if perr != nil {
			continue
		}
		bal, berr := qoder.FetchBalance(cred)
		item := gin.H{"uid": cred.UID, "nickname": cred.Nickname}
		if berr != nil {
			item["error"] = berr.Error()
		} else {
			cred.Credits, cred.CreditsTotal = bal.Remaining, bal.Total
			item["credits"] = bal.Remaining
			item["credits_total"] = bal.Total
			item["plan"] = bal.Plan
			item["exceeded"] = bal.Exceeded
			if encoded, merr := cred.MarshalCredential(); merr == nil {
				updates[cred.UID] = encoded
			}
		}
		results = append(results, item)
	}
	if len(updates) > 0 {
		if _, err := model.UpdateChannelLocked(ch.Id, func(stored *model.Channel) error {
			stored.Key = applyQoderUpdates(stored.Key, updates)
			return nil
		}); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{"items": results, "total": len(results)})
}

// upsertQoderCredential 同 UID 替换、新 UID 追加，保留其余行。
func upsertQoderCredential(key, uid, encoded string) string {
	lines := qoder.SplitCredentialLines(key)
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		cred, err := qoder.ParseCredential(line)
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

func applyQoderUpdates(key string, updates map[string]string) string {
	lines := qoder.SplitCredentialLines(key)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		cred, err := qoder.ParseCredential(line)
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
