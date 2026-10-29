// Package probes holds the health and readiness checks of the controller manager.
package probes

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

// webhookServerDialTimeout is the timeout of the connection that WebhookServerListening opens.
const webhookServerDialTimeout = time.Second

// WebhookServerListening returns a readiness check that passes when the webhook server on port accepts connections.
//
// The Service of the webhooks sends traffic only to ready pods. With this check, the API server never calls a pod
// whose webhook server does not listen yet. The webhook server listens only after it loads its certificate.
//
// The check opens a plain TCP connection. The StartedChecker of controller-runtime opens a TLS connection without a
// client certificate, which a webhook server with mTLS rejects.
func WebhookServerListening(port int) healthz.Checker {
	address := net.JoinHostPort("localhost", strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: webhookServerDialTimeout}
	return func(request *http.Request) error {
		conn, err := dialer.DialContext(request.Context(), "tcp", address)
		if err != nil {
			return fmt.Errorf("the webhook server does not accept connections: %w", err)
		}
		if err = conn.Close(); err != nil {
			return fmt.Errorf("failed to close the connection to the webhook server: %w", err)
		}
		return nil
	}
}
