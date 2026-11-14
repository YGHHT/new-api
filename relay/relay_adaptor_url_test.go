package relay

import (
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

// Once native, Trae and Qoder resolve their adaptor from their own API type
// and build the official endpoint from the credential, not from baseURL+/v1.
func TestNativeChannelAdaptorTypes(t *testing.T) {
	cases := []struct {
		name        string
		apiType     int
		wantChannel string
	}{
		{"trae", constant.APITypeTrae, "Trae"},
		{"qoder", constant.APITypeQoder, "Qoder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adaptor := GetAdaptor(tc.apiType)
			if adaptor == nil {
				t.Fatalf("%s adaptor is nil", tc.name)
			}
			if got := adaptor.GetChannelName(); got != tc.wantChannel {
				t.Fatalf("channel name = %q, want %q", got, tc.wantChannel)
			}
		})
	}
}

// A Trae channel with only an account key still resolves the official URL.
func TestTraeNativeRequestURL(t *testing.T) {
	key := `{"uid":"u1","jwt":"a.b.c"}`
	info := &relaycommon.RelayInfo{
		RequestURLPath: "/v1/chat/completions",
		ChannelMeta:    &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeTrae, ApiKey: key},
	}
	adaptor := GetAdaptor(constant.APITypeTrae)
	got, err := adaptor.GetRequestURL(info)
	if err != nil {
		t.Fatalf("GetRequestURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://trae-api-cn.mchost.guru/api/agent/v3/llm_utils_chat") {
		t.Fatalf("url = %q", got)
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
