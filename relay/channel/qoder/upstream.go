package qoder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// DefaultModels is a fallback catalog for QoderEngine's GetModelList. The real
// catalog is fetched live from /algo/api/v2/model/list, but the type 66 channel
// keeps its model list manual (like WorkBuddy) so this only matters when a UI
// asks for models without a live gateway.
var DefaultModels = []string{
	"auto", "kmodel_latest", "claude-sonnet-4", "gpt-5", "gemini-2.5-pro",
	"deepseek-v3", "kimi-k2", "glm-4.6", "qwen3-coder",
}

// refreshMu serializes refreshes per account UID; Qoder refresh tokens can be
// single-use, so two concurrent relays must not spend one twice.
var refreshMu sync.Map

func lockUID(uid string) *sync.Mutex {
	v, _ := refreshMu.LoadOrStore(uid, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ensureFreshCredential rotates an expiring token before the chat request is
// built and persists the rotated line, so the next relay reuses it.
func ensureFreshCredential(c *gin.Context, info *relaycommon.RelayInfo) {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil || !cred.NeedsRefresh() {
		return
	}
	key := cred.UID
	if key == "" {
		key = "anonymous"
	}
	mu := lockUID(key)
	mu.Lock()
	defer mu.Unlock()

	if fresh, err := ParseCredential(info.ApiKey); err == nil && !fresh.NeedsRefresh() {
		return
	}
	updated, err := refreshCredential(c, info, cred)
	if err != nil {
		common.SysError("qoder refresh failed: " + err.Error())
		return
	}
	encoded, err := updated.MarshalCredential()
	if err != nil {
		return
	}
	originalKey := info.ApiKey
	info.ApiKey = encoded
	if info.ChannelMeta != nil {
		info.ChannelMeta.ApiKey = encoded
	}
	if id := info.GetChannelID(); id > 0 {
		if _, err := model.UpdateChannelLocked(id, func(stored *model.Channel) error {
			stored.Key = ReplaceCredentialLine(stored.Key, originalKey, encoded)
			return nil
		}); err != nil {
			common.SysError("qoder persist rotated credential failed: " + err.Error())
		}
	}
}

func refreshCredential(c *gin.Context, info *relaycommon.RelayInfo, cred *Credential) (*Credential, error) {
	endpoint := cred.RefreshURL()
	payload, _ := json.Marshal(map[string]string{"refresh_token": cred.RefreshToken})
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "QoderWork/1.1.75")
	if cred.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
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
		return nil, fmt.Errorf("qoder refresh %s status %d: %s", endpoint, resp.StatusCode, truncate(string(raw), 160))
	}
	var tok struct {
		Token        string `json:"token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("qoder refresh decode: %w", err)
	}
	access := tok.AccessToken
	if access == "" {
		access = tok.Token
	}
	if access == "" {
		return nil, fmt.Errorf("qoder refresh returned no token: %s", truncate(string(raw), 160))
	}
	out := *cred
	out.AccessToken = access
	if tok.RefreshToken != "" {
		out.RefreshToken = tok.RefreshToken
	}
	switch {
	case tok.ExpiresAt > 0:
		out.ExpiresAt = normalizeEpochMillis(tok.ExpiresAt)
	case tok.ExpiresIn > 0 && tok.ExpiresIn < 10*365*24*3600:
		out.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	return &out, nil
}

func normalizeEpochMillis(v int64) int64 {
	if v > 1e11 {
		return v / 1000
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func modelFromOpenAI(raw []byte) string {
	var obj struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.Model
}

// buildQoderBody turns an OpenAI chat request into the COSY-encoded Qoder
// agent_chat_generation body. It starts from the official skeleton and
// overrides the ids, model config, prompt, parameters and business block.
func buildQoderBody(raw []byte, cred *Credential, modelKey string) (string, error) {
	var req struct {
		Messages            []map[string]any `json:"messages"`
		MaxTokens           *int             `json:"max_tokens"`
		MaxCompletionTokens *int             `json:"max_completion_tokens"`
		Tools               []any            `json:"tools"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", fmt.Errorf("qoder decode request: %w", err)
	}

	body := map[string]any{}
	if err := json.Unmarshal(baseprompt, &body); err != nil {
		return "", fmt.Errorf("qoder baseprompt: %w", err)
	}

	// Messages: keep the template's system base, drop its sample turns, then
	// append the real conversation.
	tmplSystem := []any{}
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok && mm["role"] == "system" {
				tmplSystem = append(tmplSystem, m)
			}
		}
	}
	outMsgs := tmplSystem
	for _, m := range req.Messages {
		if m["role"] == "system" {
			continue
		}
		outMsgs = append(outMsgs, m)
	}
	body["messages"] = outMsgs

	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i]["role"] == "user" {
			prompt = contentToText(req.Messages[i]["content"])
			break
		}
	}

	nid := newUUID()
	body["request_id"] = nid
	body["chat_record_id"] = nid
	body["request_set_id"] = newUUID()
	body["session_id"] = newUUID()
	body["stream"] = true
	body["agent_id"] = "agent_common"
	body["aliyun_user_type"] = userTypeName(cred.UserType)

	mc, _ := body["model_config"].(map[string]any)
	if mc == nil {
		mc = map[string]any{}
	}
	mc["key"] = modelKey
	mc["display_name"] = modelKey
	mc["model"] = ""
	mc["format"] = "openai"
	mc["is_vl"] = false
	mc["is_reasoning"] = false
	mc["api_key"] = ""
	mc["url"] = ""
	mc["source"] = "system"
	if _, ok := mc["max_input_tokens"]; !ok || mc["max_input_tokens"] == nil {
		mc["max_input_tokens"] = 180000
	}
	body["model_config"] = mc

	cc, _ := body["chat_context"].(map[string]any)
	if cc == nil {
		cc = map[string]any{}
	}
	txt, _ := cc["text"].(map[string]any)
	if txt == nil {
		txt = map[string]any{}
	}
	txt["text"] = prompt
	cc["text"] = txt
	extra, _ := cc["extra"].(map[string]any)
	if extra == nil {
		extra = map[string]any{}
	}
	oc, _ := extra["originalContent"].(map[string]any)
	if oc == nil {
		oc = map[string]any{}
	}
	oc["text"] = prompt
	extra["originalContent"] = oc
	extra["modelConfig"] = cloneMap(mc)
	cc["extra"] = extra
	body["chat_context"] = cc

	params, _ := body["parameters"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		params["max_tokens"] = *req.MaxTokens
	} else if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0 {
		params["max_tokens"] = *req.MaxCompletionTokens
	}
	body["parameters"] = params

	body["tools"] = normalizeTools(req.Tools)

	biz, _ := body["business"].(map[string]any)
	if biz == nil {
		biz = map[string]any{}
	}
	biz["id"] = newUUID()
	biz["begin_at"] = time.Now().UnixMilli()
	biz["name"] = businessName(prompt)
	if _, ok := biz["product"]; !ok {
		biz["product"] = "cli"
	}
	if _, ok := biz["type"]; !ok {
		biz["type"] = "agent"
	}
	if _, ok := biz["stage"]; !ok {
		biz["stage"] = "start"
	}
	biz["model_key"] = modelKey
	biz["version"] = CosyVersion
	body["business"] = biz

	compact, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return QoderEncode(compact), nil
}

func contentToText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, p := range c {
			if pm, ok := p.(map[string]any); ok && pm["type"] == "text" {
				if s, ok := pm["text"].(string); ok {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

// normalizeTools rewrites tools to the nested chat `function` schema the
// upstream requires, dropping anything unrecognized.
func normalizeTools(tools []any) []any {
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if _, hasFn := tm["function"]; hasFn {
			out = append(out, tm)
			continue
		}
		// Flat {"type":"function","name":...} -> nested function object.
		if tm["type"] == "function" {
			fn := map[string]any{}
			if n, ok := tm["name"]; ok {
				fn["name"] = n
			}
			if d, ok := tm["description"]; ok {
				fn["description"] = d
			}
			if p, ok := tm["parameters"]; ok {
				fn["parameters"] = p
			}
			out = append(out, map[string]any{"type": "function", "function": fn})
		}
	}
	return out
}

func businessName(prompt string) string {
	if len(prompt) == 0 {
		return "chat"
	}
	r := []rune(prompt)
	if len(r) > 30 {
		r = r[:30]
	}
	return string(r)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// wrapEnvelopeStream unwraps the Qoder SSE envelope into a plain OpenAI chunk
// stream. Each upstream line is {"headers":...,"body":"<inner chunk>",
// "statusCodeValue":200}; the downstream relay expects `data: <inner>` frames.
func wrapEnvelopeStream(resp *http.Response) *http.Response {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer service.CloseResponseBodyGracefully(resp)
		buf := make([]byte, 0, 64*1024)
		tmp := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				for {
					idx := bytes.IndexByte(buf, '\n')
					if idx < 0 {
						break
					}
					line := bytes.TrimSpace(buf[:idx])
					buf = buf[idx+1:]
					frame, done := unwrapEnvelopeLine(line)
					if len(frame) > 0 {
						if _, werr := pw.Write(frame); werr != nil {
							return
						}
					}
					if done {
						return
					}
				}
			}
			if err != nil {
				if len(buf) > 0 {
					frame, _ := unwrapEnvelopeLine(bytes.TrimSpace(buf))
					if len(frame) > 0 {
						_, _ = pw.Write(frame)
					}
				}
				return
			}
		}
	}()
	out := *resp
	out.Body = pr
	out.Header = cloneHeader(resp.Header)
	out.Header.Set("Content-Type", "text/event-stream")
	out.Header.Del("Content-Length")
	return &out
}

// unwrapEnvelopeLine returns the rewritten `data:` frame and whether the
// stream ended ([DONE]).
func unwrapEnvelopeLine(line []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return nil, false
	}
	data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	if len(data) == 0 {
		return nil, false
	}
	var outer struct {
		Body            string `json:"body"`
		StatusCodeValue int    `json:"statusCodeValue"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		// Already a plain chunk; pass it through.
		return append(append([]byte("data: "), data...), '\n', '\n'), false
	}
	if outer.StatusCodeValue != 0 && outer.StatusCodeValue != 200 {
		errBody := outer.Body
		if errBody == "" {
			errBody = string(data)
		}
		frame, _ := json.Marshal(map[string]any{"error": map[string]any{"message": truncate(errBody, 400), "type": "upstream_error"}})
		return append(append([]byte("data: "), frame...), '\n', '\n'), true
	}
	if outer.Body == "[DONE]" {
		return []byte("data: [DONE]\n\n"), true
	}
	if outer.Body == "" {
		return nil, false
	}
	return append(append([]byte("data: "), []byte(outer.Body)...), '\n', '\n'), false
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// aggregateQoderResponse folds the envelope stream into one chat.completion for
// a non-streaming client.
func aggregateQoderResponse(resp *http.Response, model string) (*http.Response, error) {
	raw, err := io.ReadAll(resp.Body)
	service.CloseResponseBodyGracefully(resp)
	if err != nil {
		return nil, err
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
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(data) == 0 {
			continue
		}
		var outer struct {
			Body string `json:"body"`
		}
		inner := data
		if err := json.Unmarshal(data, &outer); err == nil && outer.Body != "" {
			if outer.Body == "[DONE]" {
				break
			}
			inner = []byte(outer.Body)
		}
		var frame struct {
			ID      string `json:"id"`
			Created int64  `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if err := json.Unmarshal(inner, &frame); err != nil {
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
	return syntheticResponse(resp, body), nil
}

func syntheticResponse(src *http.Response, body []byte) *http.Response {
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
