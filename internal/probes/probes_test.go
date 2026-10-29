package probes

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebhookServerListening(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	check := WebhookServerListening(port)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)

	require.NoError(t, check(request), "the check passes while the webhook server listens")

	require.NoError(t, listener.Close())
	require.Error(t, check(request), "the check fails when the webhook server does not listen")
}
