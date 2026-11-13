package relay

import (
	"testing"

	"github.com/QuantumNous/new-api/constant"
)

// The model-list bootstrap in controller/model.go walks every APIType below
// APITypeDummy and dereferences the adaptor, so a missing case panics the
// process at startup. AIProxyLibrary is the one type that bootstrap skips.
func TestGetAdaptorCoversEveryAPIType(t *testing.T) {
	for apiType := 0; apiType < constant.APITypeDummy; apiType++ {
		if apiType == constant.APITypeAIProxyLibrary {
			continue
		}
		if adaptor := GetAdaptor(apiType); adaptor == nil {
			t.Fatalf("GetAdaptor(%d) returned nil", apiType)
		}
	}
}

func TestAccountPoolAdaptorsRegistered(t *testing.T) {
	workbuddy := GetAdaptor(constant.APITypeWorkBuddy)
	if workbuddy == nil {
		t.Fatal("WorkBuddy adaptor is nil")
	}
	if name := workbuddy.GetChannelName(); name != "WorkBuddy" {
		t.Fatalf("WorkBuddy channel name = %q", name)
	}
	if models := workbuddy.GetModelList(); len(models) == 0 {
		t.Fatal("WorkBuddy default model list is empty")
	}

	for _, apiType := range []int{constant.APITypeTrae, constant.APITypeQoder} {
		if adaptor := GetAdaptor(apiType); adaptor == nil {
			t.Fatalf("engine adaptor for APIType %d is nil", apiType)
		}
	}
}
