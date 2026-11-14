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
		// Trae and Qoder now have native adaptors with their own API types, so
		// the relay resolves to the native adaptor and the default model list
		// comes from DefaultModels.
		{constant.ChannelTypeTrae, constant.APITypeTrae, true},
		{constant.ChannelTypeQoder, constant.APITypeQoder, true},
	}

	for _, tc := range cases {
		apiType, ok := ChannelType2APIType(tc.channelType)
		if apiType != tc.wantAPIType || ok != tc.wantOK {
			t.Fatalf("ChannelType2APIType(%d) = (%d,%v), want (%d,%v)",
				tc.channelType, apiType, ok, tc.wantAPIType, tc.wantOK)
		}
	}
}
