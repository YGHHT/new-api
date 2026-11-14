package trae

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// wrapSoloStream converts the upstream SOLO SSE dialect into an OpenAI chunk
// stream: output/thought carry deltas, token_usage is held until the closing
// frame, done/turn_completion carry finish_reason.
func wrapSoloStream(resp *http.Response, model string) *http.Response {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer service.CloseResponseBodyGracefully(resp)

		chatID := "chatcmpl-" + newHex(12)
		created := time.Now().Unix()
		var pendingUsage map[string]any
		var buf []byte
		tmp := make([]byte, 32*1024)
		sawToolCalls := false
		sentAny := false

		write := func(delta map[string]any, finish string, usage map[string]any) bool {
			choice := map[string]any{"index": 0, "delta": delta}
			if finish != "" {
				choice["finish_reason"] = finish
			}
			frame := map[string]any{
				"id":      chatID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []any{choice},
			}
			if usage != nil {
				frame["usage"] = usage
			}
			out, err := json.Marshal(frame)
			if err != nil {
				return true
			}
			if _, err := pw.Write(append(append([]byte("data: "), out...), '\n', '\n')); err != nil {
				return false
			}
			return true
		}

		emit := func(ev *soloEvent) bool {
			if ev == nil {
				return true
			}
			if ev.HasError {
				if sentAny {
					frame, _ := json.Marshal(map[string]any{
						"error": map[string]any{"message": ev.ErrorMessage, "type": "api_error", "code": ev.ErrorCode},
					})
					_, _ = pw.Write(append(append([]byte("data: "), frame...), '\n', '\n'))
					_, _ = pw.Write([]byte("data: [DONE]\n\n"))
				}
				return false
			}
			if ev.Usage != nil {
				pendingUsage = ev.Usage
			}
			delta := map[string]any{}
			if !sentAny {
				delta["role"] = "assistant"
			}
			if ev.Response != "" {
				delta["content"] = ev.Response
			}
			if ev.Reasoning != "" {
				delta["reasoning_content"] = ev.Reasoning
			}
			if len(ev.ToolCalls) > 0 {
				delta["tool_calls"] = ev.ToolCalls
				sawToolCalls = true
			}
			if len(delta) > 1 || (len(delta) == 1 && delta["role"] == nil) {
				sentAny = true
				if !write(delta, "", nil) {
					return false
				}
			}
			if ev.FinishReason != "" {
				finish := ev.FinishReason
				if sawToolCalls && finish == "stop" {
					finish = "tool_calls"
				}
				var usage map[string]any
				if pendingUsage != nil {
					usage = normalizeUsage(pendingUsage)
				}
				sentAny = true
				if !write(map[string]any{}, finish, usage) {
					return false
				}
			}
			return true
		}

		for {
			n, err := resp.Body.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				for {
					idx := bytes.Index(buf, []byte("\n\n"))
					if idx < 0 {
						break
					}
					frame := buf[:idx]
					buf = buf[idx+2:]
					ev := parseFrame(frame)
					if !emit(ev) {
						return
					}
				}
			}
			if err != nil {
				if len(bytes.TrimSpace(buf)) > 0 {
					_ = emit(parseFrame(buf))
				}
				_, _ = pw.Write([]byte("data: [DONE]\n\n"))
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

// parseFrame parses one "event: x\ndata: {...}" block into a soloEvent.
func parseFrame(frame []byte) *soloEvent {
	var event, data string
	for _, line := range strings.Split(string(frame), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "event:"); ok {
			event = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "data:"); ok {
			data += strings.TrimSpace(v)
		}
	}
	if event == "" && data == "" {
		return nil
	}
	return parseSoloEvent(event, data)
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// aggregateSoloResponse folds the SOLO stream into one chat.completion.
func aggregateSoloResponse(resp *http.Response, model string) (*http.Response, error) {
	raw, err := io.ReadAll(resp.Body)
	service.CloseResponseBodyGracefully(resp)
	if err != nil {
		return nil, err
	}
	var content, reasoning strings.Builder
	var toolCalls []any
	var finishReason string
	var usage map[string]any
	chatID := "chatcmpl-" + newHex(12)
	created := time.Now().Unix()

	for _, block := range bytes.Split(raw, []byte("\n\n")) {
		ev := parseFrame(block)
		if ev == nil {
			continue
		}
		if ev.Usage != nil {
			usage = normalizeUsage(ev.Usage)
		}
		content.WriteString(ev.Response)
		reasoning.WriteString(ev.Reasoning)
		if len(ev.ToolCalls) > 0 {
			toolCalls = append(toolCalls, ev.ToolCalls...)
		}
		if ev.FinishReason != "" {
			finishReason = ev.FinishReason
		}
	}
	if finishReason == "" {
		finishReason = "stop"
	}
	if len(toolCalls) > 0 && finishReason == "stop" {
		finishReason = "tool_calls"
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	out := map[string]any{
		"id":      chatID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
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

// ensureFreshCredential rotates an expiring JWT and persists the account line.
func ensureFreshCredential(c *gin.Context, info *relaycommon.RelayInfo) {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil || !cred.NeedsRefresh() || cred.RefreshToken == "" {
		return
	}
	updated, err := refreshJWT(c, info, cred)
	if err != nil {
		common.SysError("trae jwt refresh failed: " + err.Error())
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
			common.SysError("trae persist rotated jwt failed: " + err.Error())
		}
	}
}

// refreshJWT exchanges the refresh token for a new JWT.
func refreshJWT(c *gin.Context, info *relaycommon.RelayInfo, cred *Credential) (*Credential, error) {
	body, _ := json.Marshal(map[string]any{
		"ClientID":     AppID,
		"RefreshToken": cred.RefreshToken,
		"DeviceID":     cred.Device().DeviceID,
		"PlatformCode": "IDE_PC",
	})
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost,
		TraeAPIHost+"/trae/api/v3/oauth/ExchangeToken", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-cloudide-token", "")
	req.Header.Set("x-device-id", cred.Device().DeviceID)
	req.Header.Set("x-app-id", AppID)
	req.Header.Set("x-platform-code", "IDE_PC")

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
		return nil, fmt.Errorf("exchange status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	// Volcano envelope: Result.Token / Result.RefreshToken.
	var env struct {
		Result struct {
			Token        string `json:"Token"`
			RefreshToken string `json:"RefreshToken"`
		} `json:"Result"`
		Token        string `json:"Token"`
		RefreshToken string `json:"RefreshToken"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("exchange decode: %w", err)
	}
	token := firstNonEmpty(env.Result.Token, env.Token)
	if token == "" {
		return nil, fmt.Errorf("exchange returned no token: %s", truncate(string(raw), 200))
	}
	out := *cred
	out.JWT = StripJWTPrefix(token)
	// A rotated refresh token invalidates the old one; keep the new value when
	// present, otherwise the old one stays valid for the next exchange.
	if rt := firstNonEmpty(env.Result.RefreshToken, env.RefreshToken); rt != "" {
		out.RefreshToken = rt
	}
	if out.UID == "" {
		out.UID = JWTUserID(out.JWT)
	}
	return &out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
