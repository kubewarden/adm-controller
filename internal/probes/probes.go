// Package probes holds the health and readiness checks of the controller manager.
package probes

import (
	"net/http"
	"sync/atomic"

	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

// PassAfterFirstSuccess returns a check that runs check until check passes one time. After that, the returned check
// passes and does not run check again.
//
// Use it with the StartedChecker of the webhook server. The Service of the webhooks sends traffic only to ready pods.
// With this check, the API server never calls a pod whose webhook server does not listen yet.
//
// The StartedChecker opens a TLS connection to the webhook server, without a client certificate. When mTLS is on, the
// webhook server rejects this connection and logs an error. PassAfterFirstSuccess limits this to one log line for each
// start of the pod, instead of one log line for each probe.
//
// When mTLS is on, the StartedChecker passes only with TLS 1.3. With TLS 1.3, the client completes the handshake
// before the server rejects the missing certificate. With TLS 1.2, the handshake fails and the pod never becomes
// ready. The webhook server permits TLS 1.3 by default. Do not limit the webhook server to TLS 1.2.
func PassAfterFirstSuccess(check healthz.Checker) healthz.Checker {
	var passed atomic.Bool
	return func(request *http.Request) error {
		if passed.Load() {
			return nil
		}
		if err := check(request); err != nil {
			return err
		}
		passed.Store(true)
		return nil
	}
}
