package qoder

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Account-side protocol: device authorization login, PAT import, userinfo,
// daily check-in (campaign platform + legacy sash) and credit balance.
// Everything here talks to the official openapi host of the account's realm.

const (
	loginUserAgent = "QoderWork/1.1.75"
	clientIDCN     = "1c5e33e1-364d-4ce6-b02c-acaa81274a5c"
	clientIDINTL   = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	redirectCN     = "qoder-work-cn://"
	redirectINTL   = "qoder://aicoding.aicoding-agent/login-success"
)

func hc(ctx context.Context, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// LoginStart describes one device authorization attempt.
type LoginStart struct {
	URL      string
	State    string
	Realm    string
	Verifier string
}

// StartDeviceLogin builds the browser authorization URL and PKCE pair.
func StartDeviceLogin(realm string) (*LoginStart, error) {
	global := realm == "global" || realm == "intl"
	nonce := newHex(16)
	verifier := newHex(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	website := WebsiteCN
	clientID := clientIDCN
	redirect := redirectCN
	if global {
		website = WebsiteINTL
		clientID = clientIDINTL
		redirect = redirectINTL
	}

	q := url.Values{}
	q.Set("challenge", challenge)
	q.Set("challenge_method", "S256")
	q.Set("nonce", nonce)
	q.Set("client_id", clientID)
	q.Set("machine_id", DeriveID("", "machine"))
	q.Set("redirect_uri", redirect)

	return &LoginStart{
		URL:      website + "/device/selectAccounts?" + q.Encode(),
		State:    nonce,
		Realm:    realmOrDefault(realm),
		Verifier: verifier,
	}, nil
}

func realmOrDefault(realm string) string {
	if realm == "global" || realm == "intl" {
		return "global"
	}
	return "cn"
}

// PollDeviceLogin exchanges the nonce for a token. done=false means the user
// has not authorized in the browser yet.
func PollDeviceLogin(realm, nonce, verifier string) (*Credential, bool, error) {
	global := realm == "global" || realm == "intl"
	openapi := OpenAPICN
	if global {
		openapi = OpenAPIINTL
	}
	q := url.Values{}
	q.Set("nonce", nonce)
	q.Set("verifier", verifier)
	q.Set("challenge_method", "S256")
	endpoint := openapi + "/api/v1/deviceToken/poll?" + q.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", loginUserAgent)

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("device poll status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	var tok struct {
		Token        string `json:"token"`
		DeviceToken  string `json:"device_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
		ExpiresIn    int64  `json:"expires_in"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, false, fmt.Errorf("device poll decode: %w", err)
	}
	access := firstNonEmpty(tok.AccessToken, tok.Token, tok.DeviceToken)
	if access == "" {
		return nil, false, nil
	}

	cred := &Credential{
		UID:          tok.UserID,
		AccessToken:  access,
		RefreshToken: tok.RefreshToken,
		Realm:        realmOrDefault(realm),
		Source:       "oauth",
	}
	applyExpiry(cred, tok.ExpiresAt, tok.ExpiresIn)

	// Fill identity from userinfo; a failure here is not fatal.
	if info, err := FetchUserInfo(cred); err == nil {
		mergeUserInfo(cred, info)
	}
	return cred, true, nil
}

// ImportPAT exchanges a personal access token for an account credential.
func ImportPAT(pat, realm string) (*Credential, error) {
	pat = strings.TrimSpace(pat)
	if !strings.HasPrefix(pat, "pt-") {
		return nil, fmt.Errorf("qoder: PAT must start with pt-")
	}
	openapi := OpenAPICN
	if realm == "global" || realm == "intl" {
		openapi = OpenAPIINTL
	}
	body, _ := json.Marshal(map[string]string{"personal_token": pat})
	req, err := http.NewRequest(http.MethodPost, openapi+"/api/v1/jobToken/exchange", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", loginUserAgent)

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PAT exchange status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var tok struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Token == "" {
		return nil, fmt.Errorf("PAT exchange returned no token: %s", truncate(string(raw), 200))
	}
	cred := &Credential{
		AccessToken:  tok.Token,
		RefreshToken: tok.RefreshToken,
		Realm:        realmOrDefault(realm),
		Source:       "pat",
	}
	applyExpiry(cred, tok.ExpiresAt, tok.ExpiresIn)
	if info, err := FetchUserInfo(cred); err == nil {
		mergeUserInfo(cred, info)
	}
	if cred.UID == "" {
		cred.UID = DeriveID(pat, "pat")
	}
	return cred, nil
}

func applyExpiry(c *Credential, at, in int64) {
	switch {
	case at > 0:
		c.ExpiresAt = normalizeEpochMillis(at)
	case in > 0 && in < 10*365*24*3600:
		c.ExpiresAt = time.Now().Add(time.Duration(in) * time.Second).Unix()
	}
}

// UserInfo is the subset of /api/v1/userinfo the pool needs.
type UserInfo struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	UserType         string `json:"user_type"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
}

// FetchUserInfo reads identity for a credential.
func FetchUserInfo(cred *Credential) (*UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, cred.OpenAPI()+"/api/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", loginUserAgent)

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var info UserInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("userinfo decode: %w", err)
	}
	return &info, nil
}

func mergeUserInfo(cred *Credential, info *UserInfo) {
	if info == nil {
		return
	}
	if cred.UID == "" {
		cred.UID = info.ID
	}
	if cred.Nickname == "" {
		cred.Nickname = info.Name
	}
	if cred.UserType == "" {
		cred.UserType = info.UserType
	}
	if cred.OrganizationID == "" {
		cred.OrganizationID = info.OrganizationID
	}
	if cred.OrganizationName == "" {
		cred.OrganizationName = info.OrganizationName
	}
}

// CheckinResult is the outcome of one account's daily check-in.
type CheckinResult struct {
	Status     string `json:"status"`            // claimed | already | pending | locked | blocked | failed | disabled
	Credits    int64  `json:"credits,omitempty"` // reward for this round
	Message    string `json:"message,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
}

// DailyCheckin runs campaign-platform check-in first, then the legacy sash
// daily check-in. It never reports an idempotent rejection as a success.
func DailyCheckin(cred *Credential) (*CheckinResult, error) {
	if res, err := campaignCheckin(cred); err == nil && res != nil {
		return res, nil
	}
	return sashCheckin(cred)
}

// campaignCheckin lists claimable campaigns and claims each one.
func campaignCheckin(cred *Credential) (*CheckinResult, error) {
	campaigns, err := listCampaigns(cred)
	if err != nil || len(campaigns) == 0 {
		return nil, err
	}
	claimed := int64(0)
	claimedAny := ""
	sawClaimedState := false
	for _, c := range campaigns {
		status := strings.ToUpper(c.ClaimStatus)
		action := strings.ToUpper(c.ActionType)
		if status == "CLAIMED" {
			sawClaimedState = true
			continue
		}
		if status != "CLAIMABLE" {
			continue
		}
		if action != "" && action != "CLAIM_BENEFIT" {
			continue
		}
		res, err := claimCampaign(cred, c.CampaignID)
		if err != nil {
			continue
		}
		if res.Credits > 0 {
			claimed += res.Credits
		}
		claimedAny = c.CampaignID
		time.Sleep(time.Second)
	}
	switch {
	case claimedAny != "":
		return &CheckinResult{Status: "claimed", Credits: claimed, CampaignID: claimedAny}, nil
	case sawClaimedState:
		return &CheckinResult{Status: "already", Message: "campaign already claimed today"}, nil
	}
	return nil, fmt.Errorf("no claimable campaign")
}

type campaignItem struct {
	CampaignID  string `json:"campaignId"`
	CampaignKey string `json:"campaignKey"`
	ActionType  string `json:"actionType"`
	ClaimStatus string `json:"claimStatus"`
}

func listCampaigns(cred *Credential) ([]campaignItem, error) {
	req, err := http.NewRequest(http.MethodGet, cred.OpenAPI()+"/sash/api/v1/me/campaigns", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", "10")
	req.Header.Set("Origin", cred.Website())
	req.Header.Set("Referer", cred.Website()+"/")

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("campaigns status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Campaigns []struct {
			CampaignID  string `json:"campaignId"`
			CampaignKey string `json:"campaignKey"`
			ActionType  string `json:"actionType"`
			ClaimStatus string `json:"claimStatus"`
		} `json:"campaigns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("campaigns decode: %w", err)
	}
	items := make([]campaignItem, 0, len(out.Campaigns))
	for _, c := range out.Campaigns {
		items = append(items, campaignItem{
			CampaignID:  c.CampaignID,
			CampaignKey: c.CampaignKey,
			ActionType:  c.ActionType,
			ClaimStatus: c.ClaimStatus,
		})
	}
	return items, nil
}

func claimCampaign(cred *Credential, id string) (*CheckinResult, error) {
	if id == "" {
		return nil, fmt.Errorf("campaign id missing")
	}
	endpoint := cred.OpenAPI() + "/sash/api/v1/me/campaigns/" + url.PathEscape(id) + "/claim"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", "10")

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var body struct {
		Status         string `json:"status"`
		ErrorCode      string `json:"errorCode"`
		FailureCode    string `json:"failureCode"`
		RedemptionCode string `json:"redemptionCode"`
		Benefit        struct {
			Amount int64 `json:"amount"`
		} `json:"benefit"`
	}
	_ = json.Unmarshal(raw, &body)

	status := strings.ToUpper(body.Status)
	switch {
	case resp.StatusCode == http.StatusConflict,
		body.ErrorCode == "ALREADY_CLAIMED" || body.ErrorCode == "REPLAYED":
		return &CheckinResult{Status: "already", CampaignID: id}, nil
	case body.FailureCode == "SAME_PERSON_ALREADY_CLAIMED" || status == "BLOCKED":
		return &CheckinResult{Status: "blocked", Message: body.FailureCode, CampaignID: id}, nil
	case status == "CLAIMED" || status == "GRANTED" || status == "SUCCESS":
		return &CheckinResult{Status: "claimed", Credits: body.Benefit.Amount, CampaignID: id}, nil
	case resp.StatusCode == http.StatusOK:
		return &CheckinResult{Status: "pending", Message: body.FailureCode, CampaignID: id}, nil
	}
	return &CheckinResult{Status: "failed", Message: truncate(string(raw), 200), CampaignID: id}, nil
}

// sashCheckin is the legacy daily check-in (CN only; INTL returns 404).
func sashCheckin(cred *Credential) (*CheckinResult, error) {
	status, err := sashStatus(cred)
	if err != nil {
		return &CheckinResult{Status: "failed", Message: err.Error()}, nil
	}
	if status.TodayCheckedIn {
		return &CheckinResult{Status: "already", Message: "already checked in today", Credits: status.RewardCredits}, nil
	}
	if status.Status != "" && status.Status != "CLAIMABLE" && status.Status != "CLAIMED" {
		return &CheckinResult{Status: "disabled", Message: status.Status}, nil
	}

	req, err := http.NewRequest(http.MethodPost, cred.OpenAPI()+"/sash/api/v1/me/daily-check-in/claim", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", "10")

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusConflict || bytes.Contains(raw, []byte("ALREADY")) {
		return &CheckinResult{Status: "already", Message: "already claimed"}, nil
	}
	var body struct {
		Success       bool  `json:"success"`
		RewardCredits int64 `json:"rewardCredits"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Success {
		return &CheckinResult{Status: "claimed", Credits: body.RewardCredits}, nil
	}
	return &CheckinResult{Status: "failed", Message: truncate(string(raw), 200)}, nil
}

type sashStatusResult struct {
	Status         string
	TodayCheckedIn bool
	RewardCredits  int64
	CurrentStreak  int64
}

func sashStatus(cred *Credential) (*sashStatusResult, error) {
	req, err := http.NewRequest(http.MethodGet, cred.OpenAPI()+"/sash/api/v1/me/daily-check-in/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", "10")

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed ||
		resp.StatusCode == http.StatusGone {
		return nil, fmt.Errorf("daily check-in unavailable in this region")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check-in status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var body struct {
		Status        string `json:"status"`
		LastClaimedAt int64  `json:"lastClaimedAt"`
		CurrentStreak int64  `json:"currentStreakDays"`
		RewardCredits int64  `json:"rewardCredits"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("check-in status decode: %w", err)
	}
	today := time.Now().Format("2006-01-02")
	claimedDay := ""
	if body.LastClaimedAt > 0 {
		claimedDay = time.Unix(normalizeEpochMillis(body.LastClaimedAt), 0).Format("2006-01-02")
	}
	return &sashStatusResult{
		Status:         strings.ToUpper(body.Status),
		TodayCheckedIn: strings.ToUpper(body.Status) == "CLAIMED" && claimedDay == today,
		RewardCredits:  body.RewardCredits,
		CurrentStreak:  body.CurrentStreak,
	}, nil
}

// Balance is the quota snapshot returned to the channel panel.
type Balance struct {
	Remaining int64  `json:"remaining"`
	Used      int64  `json:"used"`
	Total     int64  `json:"total"`
	Plan      string `json:"plan,omitempty"`
	Exceeded  bool   `json:"exceeded,omitempty"`
}

// FetchBalance reads quota usage and plan.
func FetchBalance(cred *Credential) (*Balance, error) {
	req, err := http.NewRequest(http.MethodGet, cred.OpenAPI()+"/api/v2/quota/usage", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")
	req.Header.Set("Cosy-ClientType", "10")

	resp, err := hc(context.Background(), 20*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quota status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var body struct {
		UserQuota struct {
			Remaining int64 `json:"remaining"`
			Used      int64 `json:"used"`
			Total     int64 `json:"total"`
		} `json:"userQuota"`
		AddOnQuota struct {
			Remaining int64 `json:"remaining"`
			Used      int64 `json:"used"`
			Total     int64 `json:"total"`
		} `json:"addOnQuota"`
		IsQuotaExceeded bool `json:"isQuotaExceeded"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("quota decode: %w", err)
	}
	out := &Balance{
		Remaining: body.UserQuota.Remaining + body.AddOnQuota.Remaining,
		Used:      body.UserQuota.Used + body.AddOnQuota.Used,
		Total:     body.UserQuota.Total + body.AddOnQuota.Total,
		Exceeded:  body.IsQuotaExceeded,
	}
	if plan, err := fetchPlan(cred); err == nil {
		out.Plan = plan
	}
	return out, nil
}

func fetchPlan(cred *Credential) (string, error) {
	req, err := http.NewRequest(http.MethodGet, cred.OpenAPI()+"/api/v2/user/plan", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("User-Agent", "Qoder")

	resp, err := hc(context.Background(), 15*time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("plan status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		PlanTierName string `json:"plan_tier_name"`
		UserType     string `json:"user_type"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", err
	}
	return firstNonEmpty(body.PlanTierName, body.UserType), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ = rand.Read
