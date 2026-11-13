package common

import (
	"testing"

	"github.com/QuantumNous/new-api/constant"
)

func TestAccountPoolChannelAPIType(t *testing.T) {
	cases := []struct {
		channelType int
		wantAPIType int
		wantOK      bool
	}{
		{constant.ChannelTypeWorkBuddy, constant.APITypeWorkBuddy, true},
		// Trae and Qoder are OpenAI-compatible engine channels: the adaptor
		// resolves to OpenAI while success stays false so no default model
		// catalog is invented for them.
		{constant.ChannelTypeTrae, constant.APITypeOpenAI, false},
		{constant.ChannelTypeQoder, constant.APITypeOpenAI, false},
	}

	for _, tc := range cases {
		apiType, ok := ChannelType2APIType(tc.channelType)
		if apiType != tc.wantAPIType || ok != tc.wantOK {
			t.Fatalf("ChannelType2APIType(%d) = (%d,%v), want (%d,%v)",
				tc.channelType, apiType, ok, tc.wantAPIType, tc.wantOK)
		}
	}
}
