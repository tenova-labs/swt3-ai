package swt3

import "testing"

func TestSha256Truncated(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello, world!", "315f5bdb76d078c4"},
		{"", "e3b0c44298fc1c14"},
		{"What is the meaning of life?", "318f903a83b4d30d"},
		{"gpt-4o-2024-11-20:fp_abc123", "0f6b04241d237297"},
		{"You are a helpful fraud detection assistant. Flag any transaction over $10,000.", "479eaa1ee804f844"},
	}
	for _, tt := range tests {
		got := Sha256Truncated(tt.input, 16)
		if got != tt.expected {
			t.Errorf("Sha256Truncated(%q, 16) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
