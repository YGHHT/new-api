package relay

import (
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

// The customer only ever calls new-api's /v1 surface. These tests pin the two
// engine channels to baseURL + /v1/chat/completions so a channel configured
// with http://trae:8080 or http://qoder:8790 reaches the engine's OpenAI
// endpoint without a duplicated /v1.
func TestEngineChannelRequestURL(t *testing.T) {
	cases := []struct {
		name        string
		channelType int
		base        string
		want        string
	}{
		{"trae", constant.ChannelTypeTrae, "http://trae:8080", "http://trae:8080/v1/chat/completions"},
		{"qoder", constant.ChannelTypeQoder, "http://qoder:8790", "http://qoder:8790/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &relaycommon.RelayInfo{
				RequestURLPath: "/v1/chat/completions",
				ChannelMeta: &relaycommon.ChannelMeta{
					ChannelType:    tc.channelType,
					ChannelBaseUrl: tc.base,
					ApiType:        constant.APITypeOpenAI,
				},
			}
			adaptor := GetAdaptor(constant.APITypeOpenAI)
			if adaptor == nil {
				t.Fatal("openai adaptor is nil")
			}
			got, err := adaptor.GetRequestURL(info)
			if err != nil {
				t.Fatalf("GetRequestURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("url = %q, want %q", got, tc.want)
			}
		})
	}
}

// WorkBuddy's native channel builds the official URL from the credential realm
// and never touches the engine base URL.
func TestWorkBuddyNativeRequestURL(t *testing.T) {
	key := `{"uid":"u1","access_token":"at","refresh_token":"rt","realm":"cn"}`
	info := &relaycommon.RelayInfo{
		RequestURLPath: "/v1/chat/completions",
		ChannelMeta: &relaycommon.ChannelMeta{
			ChannelType: constant.ChannelTypeWorkBuddy,
			ApiKey:      key,
		},
	}
	adaptor := GetAdaptor(constant.APITypeWorkBuddy)
	got, err := adaptor.GetRequestURL(info)
	if err != nil {
		t.Fatalf("GetRequestURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://www.workbuddy.cn/v2/chat/completions") {
		t.Fatalf("url = %q", got)
	}

	globalKey := `{"uid":"u2","access_token":"at","refresh_token":"rt","realm":"global","domain":"www.codebuddy.ai"}`
	info.ApiKey = globalKey
	got, err = adaptor.GetRequestURL(info)
	if err != nil {
		t.Fatalf("global GetRequestURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://www.codebuddy.ai/v2/chat/completions") {
		t.Fatalf("global url = %q", got)
	}
}
