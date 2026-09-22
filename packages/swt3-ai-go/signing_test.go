package swt3

import "testing"

func TestSignPayload(t *testing.T) {
	// Vector 1: with agent_id
	got := SignPayload("test-signing-key", "019eaf85fcba", "agent-007")
	want := "00ff82da1659e2e6a7fa875c781ed4635976c8136b8dc2c24672adb8673cb112"
	if got != want {
		t.Errorf("SignPayload with agent_id = %q, want %q", got, want)
	}

	// Vector 2: without agent_id
	got = SignPayload("test-signing-key", "019eaf85fcba", "")
	want = "d844102f40fb5dad449a2f57922f5b23f73ffb3a026b5bd5fd537ebe5c6c44d0"
	if got != want {
		t.Errorf("SignPayload without agent_id = %q, want %q", got, want)
	}
}
