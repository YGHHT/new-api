package qoder

import (
	_ "embed"
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
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// baseprompt is the official request skeleton; every chat request starts from
// it and overrides a subset of fields, mirroring build_qoder_body.
//
//go:embed baseprompt.json
var baseprompt []byte

// Adaptor relays OpenAI-shaped chat requests to the official Qoder
// agent_chat_generation endpoint. The outbound body is the COSY-encoded
// skeleton and the Authorization is the COSY Bearer, both derived from the
// account credential in the channel key.
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
	return cred.ChatURL(), nil
}

// SetupRequestHeader is a no-op placeholder; the real headers are computed in
// DoRequest because the COSY Bearer signature depends on the encoded body.
func (a *Adaptor) SetupRequestHeader(c *gin.Context, header *http.Header, info *relaycommon.RelayInfo) error {
	header.Set("Content-Type", "application/json")
	return nil
}

func (a *Adaptor) ConvertOpenAIRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.GeneralOpenAIRequest) (any, error) {
	return a.openaiAdaptor().ConvertOpenAIRequest(c, info, request)
}

func (a *Adaptor) ConvertClaudeRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.ClaudeRequest) (any, error) {
	return a.openaiAdaptor().ConvertClaudeRequest(c, info, request)
}

func (a *Adaptor) ConvertGeminiRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.GeminiChatRequest) (any, error) {
	return a.openaiAdaptor().ConvertGeminiRequest(c, info, request)
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

// DoRequest refreshes an expiring credential, builds + COSY-signs the chat
// body, sends it, and either unwraps the SSE envelope into an OpenAI chunk
// stream (streaming client) or folds it into one chat.completion.
func (a *Adaptor) DoRequest(c *gin.Context, info *relaycommon.RelayInfo, requestBody io.Reader) (any, error) {
	ensureFreshCredential(c, info)

	cred, err := ParseCredential(info.ApiKey)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(requestBody)
	if err != nil {
		return nil, fmt.Errorf("read qoder request body: %w", err)
	}

	modelKey := info.UpstreamModelName
	if strings.TrimSpace(modelKey) == "" {
		modelKey = modelFromOpenAI(raw)
	}

	encodedBody, err := buildQoderBody(raw, cred, modelKey)
	if err != nil {
		return nil, err
	}

	// A channel base URL (no trailing /v1) can route one realm through a proxy.
	chatURL := cred.ChatURL()
	if custom := strings.TrimRight(strings.TrimSpace(info.ChannelBaseUrl), "/"); custom != "" {
		chatURL = custom + ChatPath
	}

	sess := NewCosySession(cred)
	hdrs := sess.Headers(encodedBody, chatURL, modelKey, true)

	req, err := http.NewRequest(http.MethodPost, chatURL, strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := channel.DoRequest(c, req, info)
	if err != nil {
		return nil, err
	}
	if info.IsStream {
		return wrapEnvelopeStream(resp), nil
	}
	return aggregateQoderResponse(resp, info.UpstreamModelName)
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (usage any, err *types.NewAPIError) {
	return a.openaiAdaptor().DoResponse(c, resp, info)
}

func (a *Adaptor) GetModelList() []string {
	return DefaultModels
}

func (a *Adaptor) GetChannelName() string {
	return "Qoder"
}

var _ channel.Adaptor = (*Adaptor)(nil)
var _ = constant.ChannelTypeQoder
var _ = common.DebugEnabled
var _ = service.CloseResponseBodyGracefully
