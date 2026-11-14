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
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/relay/channel"
	"github.com/QuantumNous/new-api/relay/channel/openai"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// Adaptor relays OpenAI-shaped chat requests to the official Trae
// llm_utils_chat endpoint using the account JWT stored in the channel key.
// The upstream speaks its own SOLO SSE dialect, so the adaptor converts each
// event into OpenAI chunks.
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
	base := strings.TrimRight(strings.TrimSpace(info.ChannelBaseUrl), "/")
	if base == "" {
		base = AgentHost
	}
	return base + ChatPath, nil
}

func (a *Adaptor) SetupRequestHeader(c *gin.Context, header *http.Header, info *relaycommon.RelayInfo) error {
	cred, err := ParseCredential(info.ApiKey)
	if err != nil {
		return err
	}
	dev := cred.Device()
	traceID := "00-" + newHex(16) + "-" + newHex(16) + "-01"
	requestID := "req_" + newHex(16)

	header.Set("content-type", "application/json")
	header.Set("accept", "*/*")
	header.Set("accept-encoding", "gzip, deflate, br, zstd")
	header.Set("user-agent", "TraeClient/TTNet")
	// The mchost gateway rejects the prefixed token; it wants the bare JWT.
	header.Set("x-ide-token", StripJWTPrefix(cred.JWT))
	header.Set("x-app-id", AppID)
	header.Set("x-app-version", "default")
	header.Set("x-app-version-code", IDEVerCode)
	header.Set("x-ide-version", IDEVersion)
	header.Set("x-ide-version-code", IDEVerCode)
	header.Set("x-ide-version-type", "stable")
	header.Set("x-device-type", "windows")
	header.Set("x-device-brand", "CREFG-XX")
	header.Set("x-device-cpu", "Intel")
	header.Set("x-device-id", dev.DeviceID)
	header.Set("x-machine-id", cred.MachineID())
	header.Set("x-os-version", "Windows 11 Home China")
	header.Set("request-traffic-type", "prod")
	header.Set("package-type", "stable_cn")
	header.Set("x-lgw-req-sdk-type", "3")
	header.Set("x-lscbd-aid", "787976")
	header.Set("x-lscbd-platform", "windows")
	header.Set("x-ss-dp", "787976")
	header.Set("app-version", IDEVersion)
	header.Set("x-custom-trace-id", traceID)
	header.Set("x-flow-traceparent", "04-"+traceID)
	header.Set("x-tt-trace-id", traceID)
	header.Set("x-request-id", requestID)
	header.Set("referer", AgentHost+ChatPath)
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

// DoRequest refreshes an expiring JWT, builds the upstream body, and converts
// the SOLO SSE dialect into OpenAI chunks (streaming) or one chat.completion.
func (a *Adaptor) DoRequest(c *gin.Context, info *relaycommon.RelayInfo, requestBody io.Reader) (any, error) {
	ensureFreshCredential(c, info)

	cred, err := ParseCredential(info.ApiKey)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(requestBody)
	if err != nil {
		return nil, fmt.Errorf("read trae request body: %w", err)
	}
	model := info.UpstreamModelName
	if strings.TrimSpace(model) == "" {
		var probe struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &probe)
		model = probe.Model
	}
	body, err := buildChatBody(raw, cred, model)
	if err != nil {
		return nil, err
	}

	resp, err := channel.DoApiRequest(a, c, info, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if info.IsStream {
		return wrapSoloStream(resp, model), nil
	}
	return aggregateSoloResponse(resp, model)
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo) (usage any, err *types.NewAPIError) {
	return a.openaiAdaptor().DoResponse(c, resp, info)
}

func (a *Adaptor) GetModelList() []string {
	return DefaultModels
}

func (a *Adaptor) GetChannelName() string {
	return "Trae"
}

var _ channel.Adaptor = (*Adaptor)(nil)
var _ = constant.ChannelTypeTrae
var _ = common.DebugEnabled
var _ = service.CloseResponseBodyGracefully
var _ = time.Now
