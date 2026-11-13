package workbuddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Site 是设备授权站点。CN 与 global 的 platform 参数、UA、X-Domain 都不同，
// 混用会让上游把请求当成未知客户端。
type Site struct {
	ID       string
	Realm    string
	API      string
	Platform string
	UA       string
	Domain   string
}

// 站点表对齐官方分发包的 product.json：CN 是 platform=workbuddy，
// 国际包是 workbuddy-ai。API 主机与 X-Domain 声明的主机不是同一台，
// X-Domain 表示「哪个前端在调用」，不是请求落到哪。
var (
	SiteCN = Site{
		ID: "cn", Realm: "cn",
		API:      "https://copilot.tencent.com",
		Platform: "workbuddy",
		UA:       "WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0",
		Domain:   "www.workbuddy.cn",
	}
	SiteIntl = Site{
		ID: "intl", Realm: "global",
		API:      "https://www.codebuddy.ai",
		Platform: "workbuddy-ai",
		UA:       "workbuddy-ai/5.9.4 workbuddy-ai/5.9.4 CLI/2.165.0",
		Domain:   "www.codebuddy.ai",
	}
	SiteWorkBuddy = Site{
		ID: "workbuddy", Realm: "global",
		API:      "https://www.workbuddy.ai",
		Platform: "workbuddy-ai",
		UA:       "workbuddy-ai/5.9.4 workbuddy-ai/5.9.4 CLI/2.165.0",
		Domain:   "www.workbuddy.ai",
	}
)

// ResolveSite 按站点标识取定义，空值或未知回落 CN（与面板默认一致）。
func ResolveSite(id string) Site {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "intl":
		return SiteIntl
	case "workbuddy":
		return SiteWorkBuddy
	}
	return SiteCN
}

// ResolveSiteByRealm 按 realm 取站点：global 走旧桌面端 workbuddy.ai，
// 与面板「只传 realm」的历史语义保持一致。
func ResolveSiteByRealm(realm string) Site {
	if strings.EqualFold(strings.TrimSpace(realm), "global") {
		return SiteWorkBuddy
	}
	return SiteCN
}

// authFlow 是一次进行中的设备授权。
type authFlow struct {
	Site      Site
	AuthURL   string
	State     string
	CreatedAt time.Time
}

const authFlowTTL = 15 * time.Minute

// StartDeviceLogin 发起设备授权，返回浏览器要打开的授权链接与 state。
//
// 上游是 POST /v2/plugin/auth/state?platform=<platform>，返回 {state, authUrl}。
// 这里不伪造 x-device-token / ww_device_nonce：缺值比错值安全，缺了上游仍能授权。
func StartDeviceLogin(client *http.Client, site Site) (*authFlow, error) {
	body, status, err := doJSONRequest(client, http.MethodPost,
		site.API+"/v2/plugin/auth/state?platform="+site.Platform,
		deviceStateHeaders(site), []byte("{}"))
	if err != nil {
		return nil, fmt.Errorf("auth state (upstream %d): %w", status, err)
	}
	var reply struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if err := json.Unmarshal(body, &reply); err != nil || reply.State == "" || reply.AuthURL == "" {
		return nil, fmt.Errorf("auth state: missing state or authUrl")
	}
	return &authFlow{Site: site, AuthURL: reply.AuthURL, State: reply.State, CreatedAt: time.Now()}, nil
}

// PendingState 报告一次扫码/跳转是否还在有效期内。
func (f *authFlow) PendingState() bool {
	return time.Since(f.CreatedAt) < authFlowTTL
}

// PollDeviceLogin 轮询一次授权结果。
//
// 返回 (credential, done, err)：
//   - done=false 表示上游还没登完（11217/12151 或账号信息未落库），继续轮询；
//   - done=true 时 credential 已填好，可直接写进渠道 Key；
//   - err 非空表示终态失败（席位满、许可证过期、试用到期等），不再轮询。
func PollDeviceLogin(client *http.Client, site Site, state string) (*Credential, bool, error) {
	tokRaw, code, msg, err := doAuthJSON(client, http.MethodGet,
		site.API+"/v2/plugin/auth/token?state="+state, tokenHeaders(site), nil)
	if err != nil {
		if isAuthPending(code) {
			return nil, false, nil
		}
		if isAuthFatal(code) {
			return nil, false, fmt.Errorf("login rejected by upstream (code %d): %s", code, msg)
		}
		return nil, false, err
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(tokRaw, &tok); err != nil || tok.AccessToken == "" {
		return nil, false, nil
	}

	acctRaw, acode, amsg, aerr := doAuthJSON(client, http.MethodGet,
		site.API+"/v2/plugin/login/account?state="+state, accountHeaders(site, tok.AccessToken), nil)
	var acct struct {
		UID          string `json:"uid"`
		EnterpriseID string `json:"enterpriseId"`
		Nickname     string `json:"nickname"`
	}
	if aerr == nil {
		_ = json.Unmarshal(acctRaw, &acct)
	} else if isAuthPending(acode) {
		// token 已发但账号信息还在落库：继续轮询，此时报错会让刚登上的号白丢。
		return nil, false, nil
	} else if isAuthFatal(acode) {
		return nil, false, fmt.Errorf("login rejected by upstream (code %d): %s", acode, amsg)
	}
	if acct.UID == "" {
		return nil, false, nil
	}
	if !validUID(acct.UID) {
		return nil, false, fmt.Errorf("upstream uid contains illegal characters")
	}

	cred := &Credential{
		UID:          acct.UID,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Domain:       tok.Domain,
		Realm:        site.Realm,
		EnterpriseID: acct.EnterpriseID,
		Nickname:     acct.Nickname,
	}
	if tok.ExpiresIn > 0 && tok.ExpiresIn < 10*365*24*3600 {
		cred.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	cred.normalize()
	return cred, true, nil
}

// 官方设备授权业务码：pending 两个，终态三个。
const (
	codeRetryFetchToken   = 11217
	codeRetryFetchAccount = 12151
	codeLicenseSeatLimit  = 12005
	codeLicenseExpired    = 11212
	codeTrialExpired      = 11216
)

func isAuthPending(code int) bool {
	return code == codeRetryFetchToken || code == codeRetryFetchAccount
}

func isAuthFatal(code int) bool {
	switch code {
	case codeLicenseSeatLimit, codeLicenseExpired, codeTrialExpired:
		return true
	}
	return false
}

// CheckinResult 一次签到的归属。与上游四态一一对应，调用方据此区分
// 「今天真签上了」和「今天早就签过」，不能混成一个布尔值。
type CheckinResult struct {
	State       string `json:"state"`  // checked / already / pending / failed
	Credit      int    `json:"credit"` // 仅 checked 时可信
	CreditKnown bool   `json:"credit_known"`
	StreakDays  int    `json:"streak_days,omitempty"`
	Message     string `json:"message,omitempty"`
}

var checkinAlreadyMarkers = []string{"已签到", "已经签到", "已领取", "already"}
var checkinFailureMarkers = []string{"失败", "fail", "未开启", "不支持", "not started"}
var checkinPendingMarkers = []string{"请求处理中", "request is being processed", "processing"}

// DailyCheckin 打一次签到。
//
// 上游成功回执是**平铺**的 {"credit":100,"streak_days":44}，不是 {code,msg,data}
// 信封；重复签到是 HTTP 400 + {"code":10001,"msg":"今天已签到…"}。因此这里必须
// 拿原始 body 判断，只解信封会丢掉积分字段。
func DailyCheckin(client *http.Client, cred *Credential, customBase string) (CheckinResult, error) {
	paths := checkinPaths(cred)
	var lastErr error
	for i, path := range paths {
		raw, status, err := doRawRequest(client, http.MethodPost,
			cred.BaseURL(customBase)+path, billingHeaders(cred), []byte("{}"))
		res := classifyCheckin(raw, status, err)
		if res.State == "failed" && status == http.StatusNotFound && i < len(paths)-1 {
			lastErr = err
			continue // global 站新旧路径分叉：404 才换路径
		}
		if err != nil && res.State == "failed" {
			return res, err
		}
		return res, nil
	}
	return CheckinResult{State: "failed", Message: "all checkin paths returned 404"}, lastErr
}

func checkinPaths(cred *Credential) []string {
	if cred.IsGlobal() {
		// 国际版优先无 /v2 前缀，404 再回落带前缀。
		return []string{
			"/billing/meter/daily-checkin",
			"/v2/billing/meter/daily-checkin",
		}
	}
	return []string{"/v2/billing/meter/daily-checkin"}
}

func classifyCheckin(raw []byte, status int, err error) CheckinResult {
	res := CheckinResult{State: "failed"}
	var env struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Msg != "" {
		res.Message = env.Msg
	} else if err != nil {
		res.Message = err.Error()
	}
	text := strings.ToLower(res.Message)

	// 顺序即正确性：pending → failed → already → checked。
	if containsMarker(text, checkinPendingMarkers) {
		res.State = "pending"
		return res
	}
	if containsMarker(text, checkinFailureMarkers) {
		res.State = "failed"
		return res
	}
	if env.Code != 0 || status >= http.StatusBadRequest ||
		containsMarker(text, checkinAlreadyMarkers) {
		res.State = "already"
		return res
	}

	var body struct {
		Credit     *int `json:"credit"`
		StreakDays int  `json:"streak_days"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Credit != nil {
		res.Credit, res.CreditKnown = *body.Credit, true
	}
	if !res.CreditKnown && len(env.Data) > 0 && string(env.Data) != "null" {
		var dataBody struct {
			Credit     *int `json:"credit"`
			StreakDays int  `json:"streak_days"`
		}
		if json.Unmarshal(env.Data, &dataBody) == nil && dataBody.Credit != nil {
			res.Credit, res.CreditKnown = *dataBody.Credit, true
			body.StreakDays = dataBody.StreakDays
		}
	}
	res.StreakDays = body.StreakDays
	res.State = "checked"
	return res
}

// Balance 余额快照。
type Balance struct {
	Remain int64 `json:"remain"`
	Total  int64 `json:"total"`
}

// FetchBalance 查余额。
//
// CN 与 global 口径不同：CN 打 /billing/meter/get-user-resource 解
// Response.Data.Accounts[]，global 走 summary 的 Packages[].CycleRemainCapacity。
// 两条都失败时返回错误，由调用方决定是否只记日志。
func FetchBalance(client *http.Client, cred *Credential, customBase string) (Balance, error) {
	if cred.IsGlobal() {
		if bal, err := fetchGlobalBalance(client, cred, customBase); err == nil {
			return bal, nil
		}
	}
	return fetchCNBalance(client, cred, customBase)
}

func fetchCNBalance(client *http.Client, cred *Credential, customBase string) (Balance, error) {
	now := time.Now()
	body, _ := json.Marshal(map[string]any{
		"PageNumber":               1,
		"PageSize":                 100,
		"ProductCode":              "p_tcaca",
		"Status":                   []int{0, 3},
		"PackageEndTimeRangeBegin": now.Format("2006-01-02 15:04:05"),
		"PackageEndTimeRangeEnd":   now.AddDate(101, 0, 0).Format("2006-01-02 15:04:05"),
	})
	path := "/v2/billing/meter/get-user-resource"
	payload, status, err := fetchBillingData(client, cred, customBase, path, body)
	if err != nil {
		return Balance{}, fmt.Errorf("balance (upstream %d): %w", status, err)
	}
	var reply struct {
		Response struct {
			Data struct {
				Accounts []struct {
					CapacityRemain int64 `json:"CapacityRemain"`
					CapacitySize   int64 `json:"CapacitySize"`
				} `json:"Accounts"`
			} `json:"Data"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(payload, &reply); err != nil {
		return Balance{}, fmt.Errorf("balance parse: %w", err)
	}
	var bal Balance
	for _, acct := range reply.Response.Data.Accounts {
		remain := acct.CapacityRemain
		if remain < 0 {
			remain = 0
		}
		if remain > acct.CapacitySize && acct.CapacitySize > 0 {
			remain = acct.CapacitySize
		}
		bal.Remain += remain
		bal.Total += acct.CapacitySize
	}
	return bal, nil
}

func fetchGlobalBalance(client *http.Client, cred *Credential, customBase string) (Balance, error) {
	paths := []string{"/billing/meter/get-user-resource", "/v2/billing/meter/get-user-resource"}
	var lastErr error
	for _, path := range paths {
		payload, status, err := fetchBillingData(client, cred, customBase, path, []byte("{}"))
		if err != nil {
			lastErr = fmt.Errorf("balance (upstream %d): %w", status, err)
			continue
		}
		var reply struct {
			Packages []struct {
				CycleRemainCapacity float64 `json:"CycleRemainCapacity"`
				CycleTotalCapacity  float64 `json:"CycleTotalCapacity"`
			} `json:"Packages"`
		}
		if err := json.Unmarshal(payload, &reply); err != nil {
			lastErr = fmt.Errorf("balance parse: %w", err)
			continue
		}
		if len(reply.Packages) == 0 {
			lastErr = fmt.Errorf("balance: no packages returned")
			continue
		}
		var bal Balance
		for _, p := range reply.Packages {
			remain := int64(p.CycleRemainCapacity)
			total := int64(p.CycleTotalCapacity)
			if remain < 0 {
				remain = 0
			}
			if remain > total && total > 0 {
				remain = total
			}
			bal.Remain += remain
			bal.Total += total
		}
		return bal, nil
	}
	return Balance{}, lastErr
}

// fetchBillingData 发一次计费请求并解 {code,msg,data} 信封。
func fetchBillingData(client *http.Client, cred *Credential, customBase, path string, body []byte) ([]byte, int, error) {
	raw, status, err := doRawRequest(client, http.MethodPost,
		cred.BaseURL(customBase)+path, billingHeaders(cred), body)
	if err != nil {
		return nil, status, err
	}
	var env struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Code != 0 {
		return nil, status, fmt.Errorf("upstream code %d: %s", env.Code, env.Msg)
	}
	if len(env.Data) > 0 {
		return env.Data, status, nil
	}
	return raw, status, nil
}

// doRawRequest 发请求并返回原始 body 与状态码；4xx/5xx 时仍返回 body（错误回执
// 里有 code/msg 和积分信息，不能丢）。
func doRawRequest(client *http.Client, method, url string, headers map[string]string, body []byte) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		if rerr != nil {
			return raw, resp.StatusCode, fmt.Errorf("http %d: %w", resp.StatusCode, rerr)
		}
		return raw, resp.StatusCode, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, resp.StatusCode, rerr
}

func doJSONRequest(client *http.Client, method, url string, headers map[string]string, body []byte) ([]byte, int, error) {
	return doRawRequest(client, method, url, headers, body)
}

// doAuthJSON 解设备授权端点的 {code,msg,data} 信封，并把业务码交回调用方。
func doAuthJSON(client *http.Client, method, url string, headers map[string]string, body []byte) ([]byte, int, string, error) {
	raw, _, err := doRawRequest(client, method, url, headers, body)
	var env struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &env)
	if err != nil {
		return nil, env.Code, env.Msg, err
	}
	if env.Code != 0 && env.Code != codeRetryFetchToken && env.Code != codeRetryFetchAccount {
		return nil, env.Code, env.Msg, fmt.Errorf("upstream code %d: %s", env.Code, env.Msg)
	}
	if len(env.Data) > 0 && string(env.Data) != "null" {
		return env.Data, env.Code, env.Msg, nil
	}
	return raw, env.Code, env.Msg, nil
}

func baseHeaders(site Site) map[string]string {
	return map[string]string{
		"Accept":       "application/json, text/plain, */*",
		"User-Agent":   site.UA,
		"X-Product":    "SaaS",
		"X-Request-ID": newHex(32),
	}
}

func deviceStateHeaders(site Site) map[string]string {
	h := baseHeaders(site)
	h["Content-Type"] = "application/json"
	h["X-Domain"] = site.Domain
	h["X-Custom-Channel-Id"] = "unknown"
	h["X-No-User-Id"] = "true"
	h["X-No-Enterprise-Id"] = "true"
	h["X-No-Department-Info"] = "true"
	h["X-No-Authorization"] = "true"
	return h
}

// tokenHeaders 注意：auth/token 真机不发 X-Domain，也不带 Content-Type。
func tokenHeaders(site Site) map[string]string {
	h := baseHeaders(site)
	delete(h, "Content-Type")
	h["X-No-User-Id"] = "true"
	h["X-No-Enterprise-Id"] = "true"
	h["X-No-Department-Info"] = "true"
	h["X-No-Authorization"] = "true"
	return h
}

func accountHeaders(site Site, accessToken string) map[string]string {
	h := baseHeaders(site)
	h["X-Domain"] = site.Domain
	h["X-No-User-Id"] = "true"
	h["X-No-Enterprise-Id"] = "true"
	h["X-No-Department-Info"] = "true"
	if accessToken != "" {
		h["Authorization"] = "Bearer " + accessToken
	}
	return h
}

// billingHeaders 计费族请求头：客户端发裸主机名 X-Domain，并带 UID/企业标识。
func billingHeaders(cred *Credential) map[string]string {
	h := map[string]string{
		"Authorization":   "Bearer " + cred.AccessToken,
		"Accept":          "application/json",
		"Content-Type":    "application/json",
		"Accept-Encoding": "gzip, compress, deflate, br",
		"X-Request-ID":    newHex(32),
		"User-Agent":      rpcUserAgent(cred),
		"X-Domain":        cred.DomainHeader(),
	}
	if cred.UID != "" {
		h["X-User-Id"] = cred.UID
	}
	if cred.EnterpriseID != "" {
		h["X-Enterprise-Id"] = cred.EnterpriseID
		h["X-Tenant-Id"] = cred.EnterpriseID
	}
	if cred.DeviceToken != "" {
		h["X-Device-Token"] = cred.DeviceToken
	}
	return h
}

func containsMarker(text string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(text, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// validUID 只放行账号标识的合法字符：UID 来自上游，直接拼进文件名会被
// 路径穿越利用（"workbuddy-../../evil.json"）。
func validUID(uid string) bool {
	if uid == "" || len(uid) > 128 {
		return false
	}
	for _, r := range uid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
