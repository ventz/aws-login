package aws

import (
	"errors"
	"testing"
)

func TestNextLowerDuration(t *testing.T) {
	tests := []struct {
		name    string
		current int32
		tried   map[int32]bool
		want    int32
	}{
		{"8h steps to 4h", 8 * 3600, map[int32]bool{8 * 3600: true}, 4 * 3600},
		{"4h steps to 1h", 4 * 3600, map[int32]bool{8 * 3600: true, 4 * 3600: true}, 3600},
		{"1h exhausts ladder", 3600, map[int32]bool{3600: true}, 0},
		{"12h steps to 8h", 12 * 3600, map[int32]bool{12 * 3600: true}, 8 * 3600},
		{"below ladder floor yields 0", 1800, map[int32]bool{1800: true}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextLowerDuration(tt.current, tt.tried); got != tt.want {
				t.Errorf("nextLowerDuration(%d) = %d, want %d", tt.current, got, tt.want)
			}
		})
	}
}

func TestIsMaxSessionDurationError(t *testing.T) {
	if isMaxSessionDurationError(nil) {
		t.Error("nil error should not match")
	}
	if isMaxSessionDurationError(errors.New("AccessDenied: not authorized")) {
		t.Error("unrelated error should not match")
	}
	stsMsg := errors.New("ValidationError: The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
	if !isMaxSessionDurationError(stsMsg) {
		t.Error("MaxSessionDuration validation error should match")
	}
}
