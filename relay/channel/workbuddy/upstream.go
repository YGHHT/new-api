package workbuddy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

const (
	clientVersionCN     = "5.9.3"
	clientVersionGlobal = "5.9.4"
	cliVersion          = "2.165.0"
)

func chatUserAgent(c *Credential) string {
	if c.IsGlobal() {
		return "WorkBuddy/" + clientVersionGlobal + " workbuddy-ai/" + clientVersionGlobal + " CLI/" + cliVersion
	}
	return "WorkBuddy/" + clientVersionCN + " WorkBuddy/" + clientVersionCN + " CLI/" + cliVersion
}

func rpcUserAgent(c *Credential) string {
	if c.IsGlobal() {
		return "workbuddy-ai/" + clientVersionGlobal + " workbuddy-ai/" + clientVersionGlobal + " CLI/" + cliVersion
	}
	return "WorkBuddy/" + clientVersionCN + " WorkBuddy/" + clientVersionCN + " CLI/" + cliVersion
}

func newHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// newTimeOrderedID builds a UUIDv7-shaped 36-char id, matching the official
// client's X-Conversation-ID form (01a1815d-…).
func newTimeOrderedID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// setConversationHeaders reproduces the official chat header family. The
// upstream rejects a chat request whose conversation triple is incomplete.
func setConversationHeaders(h *http.Header) {
	conv := newTimeOrderedID()
	reqID := newTimeOrderedID()
	msgID := newHex(32)
	traceID := newHex(32)
	spanID := newHex(16)
	parentSpanID := newHex(16)

	h.Set("X-Conversation-ID", conv)
	h.Set("X-Conversation-Request-ID", reqID)
	h.Set("X-Conversation-Message-ID", msgID)
	h.Set("X-Request-ID", msgID)
	h.Set("X-Root-Request-ID", reqID)
	h.Set("X-Trace-ID", traceID)
	h.Set("X-B3-TraceId", traceID)
	h.Set("X-B3-SpanId", spanID)
	h.Set("X-B3-ParentSpanId", parentSpanID)
	h.Set("X-B3-Sampled", "1")
	h.Set("b3", traceID+"-"+spanID+"-1-"+parentSpanID)
	h.Set("traceparent", "00-"+traceID+"-"+spanID+"-01")
}

// refreshLocks serializes refreshes per UID: a WorkBuddy refresh token is
// single-use, so two concurrent relays must not spend it twice.
var refreshLocks sync.Map

func lockFor(uid string) *sync.Mutex {
	v, _ := refreshLocks.LoadOrStore(uid, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ensureFreshCredential refreshes an expiring token before the chat request is
// built. It rewrites info.ApiKey for this request and persists the rotated
// credential on the channel, so the next relay sees the new token too.
func ensureFreshCredential(c *gin.Context, info *relaycommon.RelayInfo) {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil || !cred.NeedsRefresh() {
		return
	}
	key := cred.UID
	if key == "" {
		key = newHex(16)
	}
	mu := lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	// Another goroutine may have rotated the token while we waited.
	if fresh, err := ParseCredential(info.ApiKey); err == nil && !fresh.NeedsRefresh() {
		return
	}

	updated, err := refreshCredential(c, info, cred)
	if err != nil {
		common.SysError("workbuddy refresh failed: " + err.Error())
		return
	}
	encoded, err := updated.MarshalCredential()
	if err != nil {
		return
	}
	info.ApiKey = encoded
	if info.ChannelMeta != nil {
		info.ChannelMeta.ApiKey = encoded
	}
	if id := info.GetChannelID(); id > 0 {
		if err := model.DB.Model(&model.Channel{}).Where("id = ?", id).
			Update("key", encoded).Error; err == nil {
			model.BumpSyncTopic(model.SyncTopicChannels)
		}
	}
}

func refreshCredential(c *gin.Context, info *relaycommon.RelayInfo, cred *Credential) (*Credential, error) {
	endpoint := cred.BaseURL(info.ChannelBaseUrl) + "/v2/plugin/auth/token/refresh"
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost,
		endpoint, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/plain, */*")
	h.Set("X-Product", "SaaS")
	h.Set("User-Agent", rpcUserAgent(cred))
	h.Set("X-Refresh-Token", cred.RefreshToken)
	h.Set("X-Auth-Refresh-Source", "plugin")
	h.Set("Authorization", "Bearer "+cred.AccessToken)
	h.Set("X-Request-ID", newHex(32))
	if cred.UID != "" {
		h.Set("X-User-Id", cred.UID)
	}
	h.Set("X-Domain", cred.DomainHeader())
	if cred.EnterpriseID != "" {
		h.Set("X-Enterprise-Id", cred.EnterpriseID)
	}

	client, err := service.GetHttpClientWithProxySettings(info.ChannelSetting.Proxy, info.ChannelSetting)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh status %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("refresh returned no accessToken: %s", truncate(string(raw), 160))
	}
	out := *cred
	out.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		out.RefreshToken = tok.RefreshToken
	}
	if tok.Domain != "" {
		out.Domain = tok.Domain
	}
	if tok.ExpiresIn > 0 && tok.ExpiresIn < 10*365*24*3600 {
		out.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	return &out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// aggregateSSEResponse turns the upstream's forced SSE stream into a single
// chat.completion object when the downstream client asked for a non-stream
// response. The returned response advertises JSON so the relay picks
// OpenaiHandler instead of the stream handler.
func aggregateSSEResponse(resp *http.Response, model string) (*http.Response, error) {
	raw, err := io.ReadAll(resp.Body)
	service.CloseResponseBodyGracefully(resp)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(raw, []byte("data:")) {
		return syntheticResponse(resp, raw, model), nil
	}

	var content, reasoning strings.Builder
	var responseID string
	var created int64
	var finishReason string
	var usage map[string]any
	responseModel := model
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var frame struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if err := json.Unmarshal(payload, &frame); err != nil {
			continue
		}
		if frame.ID != "" {
			responseID = frame.ID
		}
		if frame.Created > 0 {
			created = frame.Created
		}
		if frame.Model != "" {
			responseModel = frame.Model
		}
		if frame.Usage != nil {
			usage = frame.Usage
		}
		for _, ch := range frame.Choices {
			content.WriteString(ch.Delta.Content)
			reasoning.WriteString(ch.Delta.ReasoningContent)
			if ch.FinishReason != nil {
				finishReason = *ch.FinishReason
			}
		}
	}
	if responseID == "" {
		responseID = "chatcmpl-" + newHex(24)
	}
	if created == 0 {
		created = time.Now().Unix()
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	out := map[string]any{
		"id":      responseID,
		"object":  "chat.completion",
		"created": created,
		"model":   responseModel,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
	}
	if usage != nil {
		out["usage"] = usage
	}
	body, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return syntheticResponse(resp, body, model), nil
}

func syntheticResponse(src *http.Response, body []byte, _ string) *http.Response {
	out := &http.Response{
		StatusCode:    src.StatusCode,
		Status:        src.Status,
		Proto:         src.Proto,
		ProtoMajor:    src.ProtoMajor,
		ProtoMinor:    src.ProtoMinor,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	for k, v := range src.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "content-length" || lk == "content-encoding" ||
			lk == "transfer-encoding" || lk == "connection" {
			continue
		}
		out.Header[k] = append([]string(nil), v...)
	}
	out.Header.Set("Content-Type", "application/json; charset=utf-8")
	out.Header.Set("Content-Length", fmt.Sprint(len(body)))
	return out
}

var _ = channel.DoApiRequest
