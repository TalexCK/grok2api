package inference

import (
	"io"
	"strings"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/application/gateway"
)

func TestSearchReplyReturnsTextAndFinalizesUsage(t *testing.T) {
	var usage gateway.Usage
	var id, code string
	result := &gateway.Result{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"id":"reply-1","model":"grok-chat-fast","choices":[{"message":{"content":"  回答\n[[1]](https://example.org)  "},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":7}}`)),
		Finalize: func(value gateway.Usage, responseID, errorCode string) {
			usage, id, code = value, responseID, errorCode
		},
	}
	text, err := readSearchReply(result)
	if err != nil || text != "  回答\n[[1]](https://example.org)  " {
		t.Fatalf("text = %q, err = %v", text, err)
	}
	if !usage.Reported || !usage.OutputObserved || usage.InputTokens != 12 || usage.OutputTokens != 7 || id != "reply-1" || code != "" {
		t.Fatalf("usage = %#v, id = %q, error = %q", usage, id, code)
	}
}

func TestSearchReplyRejectsFailedEmptyAndIncompleteUpstream(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"upstream credential error", `{"error":"sso=upstream-secret"}`, 401},
		{"empty", `{"choices":[{"message":{"content":" "},"finish_reason":"stop"}]}`, 200},
		{"truncated", `{"choices":[{"message":{"content":"partial answer"},"finish_reason":"length"}]}`, 200},
		{"malformed", `{"choices":`, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			finalized := false
			result := &gateway.Result{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Finalize: func(_ gateway.Usage, _ string, code string) { finalized = code != "" }}
			text, err := readSearchReply(result)
			if err == nil || text != "" || !finalized || strings.Contains(err.Error(), "upstream-secret") {
				t.Fatalf("text = %q, err = %v, finalized = %v", text, err, finalized)
			}
		})
	}
}
