package trae

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// buildChatBody turns an OpenAI chat request into the llm_utils_chat body.
// It mirrors prepare_llm_chat_body: content strings become text parts,
// assistant tool_calls use function_call, and the upstream's required fields
// (config_name, model_name, function, ids, prompt_max_tokens, ...) are added.
func buildChatBody(raw []byte, cred *Credential, model string) ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("trae: decode request: %w", err)
	}
	// The upstream has its own streaming contract; drop OpenAI-only knobs that
	// it would reject.
	delete(obj, "stream_options")
	delete(obj, "n")

	// messages: content string -> [{type:text,text:...}], assistant tool_calls
	// function -> function_call.
	if msgs, ok := obj["messages"].([]any); ok {
		for _, mi := range msgs {
			m, ok := mi.(map[string]any)
			if !ok {
				continue
			}
			role, _ := m["role"].(string)
			if role == "assistant" {
				if tcs, ok := m["tool_calls"].([]any); ok {
					kept := make([]any, 0, len(tcs))
					for _, tci := range tcs {
						tc, ok := tci.(map[string]any)
						if !ok {
							continue
						}
						if fn, has := tc["function"]; has {
							delete(tc, "function")
							tc["function_call"] = fn
						}
						fc, _ := tc["function_call"].(map[string]any)
						name, _ := fc["name"].(string)
						if strings.TrimSpace(name) == "" {
							continue
						}
						kept = append(kept, tc)
					}
					if len(kept) == 0 {
						delete(m, "tool_calls")
					} else {
						m["tool_calls"] = kept
					}
				}
			}
			if s, ok := m["content"].(string); ok {
				m["content"] = []any{map[string]any{"type": "text", "text": s}}
			}
		}
	}

	normalizeToolChoice(obj)
	normalizeTools(obj)

	if strings.TrimSpace(model) == "" {
		model = DefaultModel
	}
	configName, modelName := modelConfig(model)

	obj["config_name"] = configName
	obj["model_name"] = modelName
	obj["stream"] = true
	obj["function"] = DefaultFunc

	maxTokens := int64(4096)
	for _, k := range []string{"max_tokens", "max_completion_tokens"} {
		if v, ok := obj[k].(float64); ok && v > 0 {
			maxTokens = int64(v)
			break
		}
	}
	obj["max_tokens"] = maxTokens

	dev := cred.Device()
	obj["conversation_id"] = newUUID()
	obj["user_id"] = cred.UID
	obj["session_id"] = newUUID()
	obj["device_id"] = dev.DeviceID
	obj["machine_id"] = cred.MachineID()
	obj["project_id"] = newUUID()
	obj["workspace_id"] = "e04cdd"
	obj["prompt_max_tokens"] = 168000
	obj["mode"] = "FunctionCall"
	obj["ide_version"] = IDEVersion
	obj["ide_version_code"] = IDEVerCode
	obj["app_id"] = AppID
	obj["package_type"] = "stable_cn"

	return json.Marshal(obj)
}

func normalizeToolChoice(obj map[string]any) {
	tc, ok := obj["tool_choice"]
	if !ok {
		return
	}
	switch v := tc.(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "none") {
			delete(obj, "tools")
			delete(obj, "functions")
		}
	case map[string]any:
		typ, _ := v["type"].(string)
		switch strings.ToLower(typ) {
		case "none":
			delete(obj, "tools")
			delete(obj, "functions")
		case "auto", "required":
			obj["tool_choice"] = strings.ToLower(typ)
		case "function":
			name := ""
			if fn, ok := v["function"].(map[string]any); ok {
				name, _ = fn["name"].(string)
			}
			if name == "" {
				name, _ = v["name"].(string)
			}
			name = strings.TrimSpace(name)
			if name == "" {
				name = "auto"
			}
			obj["tool_choice"] = name
		default:
			delete(obj, "tool_choice")
		}
	}
}

func normalizeTools(obj map[string]any) {
	tools, ok := obj["tools"].([]any)
	if !ok {
		return
	}
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if _, has := tm["function"]; has {
			out = append(out, tm)
			continue
		}
		if tm["type"] == "function" {
			fn := map[string]any{}
			for _, k := range []string{"name", "description", "parameters"} {
				if v, ok := tm[k]; ok {
					fn[k] = v
				}
			}
			out = append(out, map[string]any{"type": "function", "function": fn})
		}
	}
	obj["tools"] = out
}

// soloEvent is one parsed upstream SSE event.
type soloEvent struct {
	Event        string
	Response     string
	Reasoning    string
	ToolCalls    []any
	FinishReason string
	Usage        map[string]any
	ErrorCode    int64
	ErrorMessage string
	HasError     bool
}

// parseSoloEvent maps one upstream SSE frame onto the OpenAI shape.
func parseSoloEvent(event, data string) *soloEvent {
	ev := &soloEvent{Event: event}
	if strings.TrimSpace(data) == "" {
		return ev
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return ev
	}
	switch event {
	case "output":
		ev.Response, _ = raw["response"].(string)
		ev.Reasoning, _ = raw["reasoning_content"].(string)
		if tc, ok := raw["tool_calls"]; ok && tc != nil {
			ev.ToolCalls = normalizeToolCalls(tc)
		}
	case "thought":
		if s, ok := raw["thought"].(string); ok {
			ev.Response = s
		}
		ev.Reasoning, _ = raw["reasoning_content"].(string)
		if tc, ok := raw["tool_calls"]; ok && tc != nil {
			ev.ToolCalls = normalizeToolCalls(tc)
		}
	case "token_usage":
		ev.Usage = raw
	case "done":
		ev.FinishReason, _ = raw["finish_reason"].(string)
	case "turn_completion":
		fr, _ := raw["finish_reason"].(string)
		switch fr {
		case "stop", "length", "tool_calls", "function_call", "content_filter":
			ev.FinishReason = fr
		default:
			ev.FinishReason = "stop"
		}
	case "error":
		ev.HasError = true
		if c, ok := raw["code"].(float64); ok {
			ev.ErrorCode = int64(c)
		}
		ev.ErrorMessage, _ = raw["message"].(string)
	}
	return ev
}

// normalizeToolCalls renames the upstream's function_call back to function and
// strips the namespace/partial_arguments fields the OpenAI shape does not use.
func normalizeToolCalls(v any) []any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]any, 0, len(arr))
	for _, item := range arr {
		tc, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if fn, has := tc["function_call"]; has {
			delete(tc, "function_call")
			tc["function"] = fn
		}
		delete(tc, "namespace")
		delete(tc, "partial_arguments")
		out = append(out, tc)
	}
	return out
}

// normalizeUsage converts the upstream token_usage payload to OpenAI usage.
func normalizeUsage(raw map[string]any) map[string]any {
	prompt := pickNumber(raw, "prompt_tokens", "input_tokens")
	completion := pickNumber(raw, "completion_tokens", "output_tokens")
	total := pickNumber(raw, "total_tokens")
	if total == 0 {
		total = prompt + completion
	}
	out := map[string]any{
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      total,
	}
	if cached := pickNumber(raw, "cached_tokens", "cache_read_input_tokens"); cached > 0 {
		out["prompt_tokens_details"] = map[string]any{"cached_tokens": cached}
	}
	return out
}

func pickNumber(raw map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := raw[k].(float64); ok {
			return int64(v)
		}
	}
	return 0
}

// newUUID returns a random RFC-4122 v4 UUID string.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func randRead(b []byte) (int, error) {
	return cryptoRandRead(b)
}

var _ = bytes.NewReader
var _ = time.Now
