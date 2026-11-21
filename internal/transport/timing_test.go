package transport

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Waiting for the rate limiter must not count against the per-request
// timeout: with rate 2/s, 4 workers and a 300ms timeout every request still
// succeeds (it waits up to ~2.5s for its token, then has 300ms to finish).
func TestRateLimitWaitNotCountedInTimeout(t *testing.T) {
	srv, _ := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Rate: 2, Timeout: 300 * time.Millisecond})
	jobs := make(chan int, 6)
	for i := 0; i < 6; i++ {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	var failed atomic.Int32
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				if _, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, "")); err != nil {
					failed.Add(1)
					t.Log(err)
				}
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 0, failed.Load())
	_, _, errs := c.Stats()
	assert.Equal(t, 0, errs)
}

// The per-attempt timeout still applies to a slow server.
func TestTimeoutStillApplies(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Timeout: 100 * time.Millisecond})
	start := time.Now()
	_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

// A request blocked by scope or safe mode neither waits for nor consumes a
// rate-limit token.
func TestBlockedRequestsDoNotConsumeTokens(t *testing.T) {
	srv, _ := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Rate: 1})
	start := time.Now()
	for i := 0; i < 3; i++ {
		_, err := c.Do(context.Background(), mustReq(t, "DELETE", srv.URL, ""))
		require.ErrorIs(t, err, ErrDestructiveBlocked)
		_, err = c.Do(context.Background(), mustReq(t, "GET", "http://out.example/x", ""))
		require.ErrorIs(t, err, ErrOutOfScope)
	}
	_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 500*time.Millisecond, "blocked requests must not wait for tokens")
}
