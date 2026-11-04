package probes

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPassAfterFirstSuccess(t *testing.T) {
	var innerErr error
	calls := 0
	check := PassAfterFirstSuccess(func(_ *http.Request) error {
		calls++
		return innerErr
	})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)

	innerErr = errors.New("the webhook server has not been started yet")
	require.Error(t, check(request), "the check fails while the inner check fails")
	require.Error(t, check(request), "the check fails while the inner check fails")
	require.Equal(t, 2, calls)

	innerErr = nil
	require.NoError(t, check(request), "the check passes when the inner check passes")
	require.Equal(t, 3, calls)

	innerErr = errors.New("the webhook server is not reachable")
	require.NoError(t, check(request), "the check passes after the inner check passed one time")
	require.NoError(t, check(request), "the check passes after the inner check passed one time")
	require.Equal(t, 3, calls, "the check does not run the inner check after it passed one time")
}
