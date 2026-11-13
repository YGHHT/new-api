package workbuddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/relay/channel"
	"github.com/QuantumNous/new-api/relay/channel/openai"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"

	"github.com/gin-gonic/gin"
)

// Adaptor relays OpenAI-shaped chat requests to the official WorkBuddy
// /v2/chat/completions endpoint using the account credentials stored in the
// channel key. It embeds the OpenAI adaptor for protocol conversions and
// response/billing handling; only the upstream-specific parts are overridden.
type Adaptor struct {
	oa *openai.Adaptor
}

func (a *Adaptor) openaiAdaptor() *openai.Adaptor {
	if a.oa == nil {
		a.oa = &openai.Adaptor{}
	}
	return a.oa
}

func (a *Adaptor) Init(info *relaycommon.RelayInfo) {
	a.openaiAdaptor().Init(info)
}

func (a *Adaptor) GetRequestURL(info *relaycommon.RelayInfo) (string, error) {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil {
		return "", err
	}
	return cred.BaseURL(info.ChannelBaseUrl) + "/v2/chat/completions", nil
}

func (a *Adaptor) SetupRequestHeader(c *gin.Context, header *http.Header, info *relaycommon.RelayInfo) error {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil {
		return err
	}
	header.Set("Content-Type", "application/json")
	header.Set("Accept", "application/json")
	header.Set("X-Requested-With", "XMLHttpRequest")
	header.Set("X-Product", "SaaS")
	header.Set("Authorization", "Bearer "+cred.AccessToken)
	if cred.IsAPIKey() {
		header.Set("X-API-Key", cred.AccessToken)
	}
	if cred.UID != "" {
		header.Set("X-User-Id", cred.UID)
	}
	header.Set("X-Domain", cred.DomainHeader())
	if cred.EnterpriseID != "" {
		header.Set("X-Enterprise-Id", cred.EnterpriseID)
	}
	header.Set("X-Private-Data", "false")
	if cred.EnterpriseID != "" {
		header.Set("X-Private-Data", "true")
	}
	header.Set("X-CodeBuddy-Request", "1")
	header.Set("X-Agent-Runtime", "local-agent")
	header.Set("X-Agent-Type", "main")
	header.Set("X-Agent-Intent", "crf")
	header.Set("User-Agent", chatUserAgent(cred))
	header.Set("X-Stainless-Lang", "js")
	header.Set("X-Stainless-Package-Version", "4.104.0")
	header.Set("X-Stainless-OS", "Windows")
	header.Set("X-Stainless-Arch", "x64")
	header.Set("X-Stainless-Runtime", "node")
	header.Set("X-Stainless-Runtime-Version", "v22.14.0")
	header.Set("X-Stainless-Retry-Count", "0")
	if cred.DeviceToken != "" {
		header.Set("X-Device-Token", cred.DeviceToken)
	}
	setConversationHeaders(header)
	return nil
}

func (a *Adaptor) ConvertOpenAIRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.GeneralOpenAIRequest) (any, error) {
	converted, err := a.openaiAdaptor().ConvertOpenAIRequest(c, info, request)
	if err != nil {
		return nil, err
	}
	return converted, nil
}

func (a *Adaptor) ConvertClaudeRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.ClaudeRequest) (any, error) {
	converted, err := a.openaiAdaptor().ConvertClaudeRequest(c, info, request)
	if err != nil {
		return nil, err
	}
	return normalizeConvertedRequest(converted), nil
}

func (a *Adaptor) ConvertGeminiRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.GeminiChatRequest) (any, error) {
	converted, err := a.openaiAdaptor().ConvertGeminiRequest(c, info, request)
	if err != nil {
		return nil, err
	}
	return normalizeConvertedRequest(converted), nil
}

func (a *Adaptor) ConvertRerankRequest(c *gin.Context, relayMode int, request dto.RerankRequest) (any, error) {
	return a.openaiAdaptor().ConvertRerankRequest(c, relayMode, request)
}

func (a *Adaptor) ConvertEmbeddingRequest(c *gin.Context, info *relaycommon.RelayInfo, request dto.EmbeddingRequest) (any, error) {
	return a.openaiAdaptor().ConvertEmbeddingRequest(c, info, request)
}

func (a *Adaptor) ConvertAudioRequest(c *gin.Context, info *relaycommon.RelayInfo, request dto.AudioRequest) (io.Reader, error) {
	return a.openaiAdaptor().ConvertAudioRequest(c, info, request)
}

func (a *Adaptor) ConvertImageRequest(c *gin.Context, info *relaycommon.RelayInfo, request dto.ImageRequest) (any, error) {
	return a.openaiAdaptor().ConvertImageRequest(c, info, request)
}

func (a *Adaptor) ConvertOpenAIResponsesRequest(c *gin.Context, info *relaycommon.RelayInfo, request dto.OpenAIResponsesRequest) (any, error) {
	return a.openaiAdaptor().ConvertOpenAIResponsesRequest(c, info, request)
}

// DoRequest refreshes an expiring credential before sending, then rewrites the
// outbound body to the upstream's required shape. A streaming client keeps the
// SSE response; a non-streaming client gets an aggregated chat.completion.
func (a *Adaptor) DoRequest(c *gin.Context, info *relaycommon.RelayInfo, requestBody io.Reader) (any, error) {
	ensureFreshCredential(c, info)

	raw, err := io.ReadAll(requestBody)
	if err != nil {
		return nil, fmt.Errorf("read workbuddy request body: %w", err)
	}
	body := bytes.NewReader(prepareUpstreamBody(raw))

	resp, err := channel.DoApiRequest(a, c, info, body)
	if err != nil {
		return nil, err
	}
	if info.IsStream || resp.StatusCode != http.StatusOK ||
		!strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return resp, nil
	}
	return aggregateSSEResponse(resp, info.UpstreamModelName)
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (usage any, err *types.NewAPIError) {
	return a.openaiAdaptor().DoResponse(c, resp, info)
}

func (a *Adaptor) GetModelList() []string {
	return DefaultModels
}

func (a *Adaptor) GetChannelName() string {
	return "WorkBuddy"
}

// normalizeConvertedRequest re-applies the upstream shape after a protocol
// conversion produced a GeneralOpenAIRequest.
func normalizeConvertedRequest(converted any) any {
	if req, ok := converted.(*dto.GeneralOpenAIRequest); ok {
		_, bare := SplitRealmPrefix(req.Model)
		req.Model = bare
		stream := true
		req.Stream = &stream
		req.StreamOptions = &dto.StreamOptions{IncludeUsage: true}
		if req.MaxCompletionTokens != nil && req.MaxTokens == nil {
			req.MaxTokens = req.MaxCompletionTokens
			req.MaxCompletionTokens = nil
		}
	}
	return converted
}

// prepareUpstreamBody rewrites the marshaled request exactly as the panel did
// before handing it to CodeBuddy: strip the realm prefix, force streaming,
// translate max_completion_tokens, normalize tool_choice and image_url.
func prepareUpstreamBody(src []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(src, &obj); err != nil {
		return src
	}
	if model, ok := obj["model"].(string); ok {
		_, bare := SplitRealmPrefix(model)
		obj["model"] = bare
	}
	obj["stream"] = true
	if _, exists := obj["stream_options"]; !exists {
		obj["stream_options"] = map[string]any{"include_usage": true}
	}
	if v, ok := obj["max_completion_tokens"]; ok {
		if _, has := obj["max_tokens"]; !has {
			obj["max_tokens"] = v
		}
		delete(obj, "max_completion_tokens")
	}
	if tc, ok := obj["tool_choice"].(map[string]any); ok {
		if fn, ok := tc["function"].(map[string]any); ok {
			if name, ok := fn["name"].(string); ok && name != "" {
				obj["tool_choice"] = name
			} else {
				obj["tool_choice"] = "auto"
			}
		} else if kind, ok := tc["type"].(string); ok && kind != "function" {
			obj["tool_choice"] = kind
		} else {
			obj["tool_choice"] = "auto"
		}
	}
	normalizeImageURLs(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		return src
	}
	return out
}

func normalizeImageURLs(obj map[string]any) {
	msgs, ok := obj["messages"].([]any)
	if !ok {
		return
	}
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		parts, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, p := range parts {
			part, ok := p.(map[string]any)
			if !ok || part["type"] != "image_url" {
				continue
			}
			if s, ok := part["image_url"].(string); ok {
				part["image_url"] = map[string]any{"url": s}
			}
		}
	}
}

var _ channel.Adaptor = (*Adaptor)(nil)

// keep the constant import live for relay mode checks in future extensions.
var _ = constant.ChannelTypeWorkBuddy
var _ = common.DebugEnabled
