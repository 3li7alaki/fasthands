package accounts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudelock"
	"fasthands/internal/oauth"
	"fasthands/internal/usage"
)

const fetchNow int64 = 1792070000

func setupFetch(t *testing.T, platform string) *switchFixture {
	t.Helper()
	f := setupSwitch(t, platform)
	t.Setenv("TZ", "UTC")
	oldNow := now
	now = func() time.Time { return time.Unix(fetchNow, 0) }
	t.Cleanup(func() { now = oldNow })
	return f
}

func fetchBlob(token string, expires int64) []byte {
	return fmt.Appendf(nil, `{"claudeAiOauth":{"accessToken":%q,"expiresAt":%d}}`, token, expires)
}

func fetchClient(t *testing.T, handler http.HandlerFunc) oauth.Client {
	t.Helper()
	return oauth.Client{UsageURL: "http://usage.test", UserAgent: "fasthands/dev", HTTP: &http.Client{Transport: fetchTransport(handler)}}
}

type fetchTransport http.HandlerFunc

// O1 request assertions use httptest without binding a sandbox-blocked socket.
func (handler fetchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	response := httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(response, r)
	return response.Result(), nil
}

// Slice 4b1 invariants 4, 10: reserve durably before HTTP, with every unrelated lock held elsewhere.
func TestFetchPersistsBeforeRequest(t *testing.T) {
	f := setupFetch(t, "linux")
	if err := f.m.Store.Write("id-b", fetchBlob("fetch-access-private", (fetchNow+3600)*1000)); err != nil {
		t.Fatal(err)
	}
	accountsLock, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock(accountsLock)
	for _, lock := range claudelock.Locks(f.loc) {
		if err := os.Mkdir(lock.Path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			t.Error("usage request lacks the five-second context timeout")
		}
		state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
		if err != nil || len(state.Accounts["id-b"].Requests) != 1 || state.Accounts["id-b"].Requests[0] != fetchNow {
			t.Error("request arrived before reservation was on disk")
		}
		lock, err := os.OpenFile(filepath.Join(f.m.Paths.State, "usage.lock"), os.O_RDWR, 0600)
		if err != nil {
			t.Error(err)
			return
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Error("network request held usage flock")
		}
		io.WriteString(w, `{"five_hour":{"utilization":12,"resets_at":null}}`)
	})
	results := f.m.Fetch([]string{"id-b"}, "id-a", nil, client)
	if len(results) != 1 || !results[0].Fetched || results[0].Error != "" || results[0].Skipped != "" {
		t.Fatalf("fetch failed: %+v", results)
	}
	for _, name := range []string{"usage.json", "accounts.json"} {
		data, err := os.ReadFile(filepath.Join(f.m.Paths.State, name))
		if err != nil || strings.Contains(string(data), "fetch-access-private") {
			t.Fatal("credential escaped into state")
		}
	}
}

// Slice 4b1: each account uses its own source and both requests must run concurrently.
func TestFetchConcurrentSources(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupFetch(t, platform)
			if err := f.m.Store.Write("id-b", fetchBlob("stored-access-private", (fetchNow+3600)*1000)); err != nil {
				t.Fatal(err)
			}
			var arrivals atomic.Int32
			both := make(chan struct{})
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				token := r.Header.Get("Authorization")
				if token != "Bearer live-fetch-private" && token != "Bearer stored-access-private" {
					t.Error("wrong credential source")
				}
				if arrivals.Add(1) == 2 {
					close(both)
				}
				select {
				case <-both:
					io.WriteString(w, `{}`)
				case <-r.Context().Done():
				}
			})
			results := f.m.Fetch([]string{"id-b", "id-a"}, "id-a", fetchBlob("live-fetch-private", (fetchNow+3600)*1000), client)
			if len(results) != 2 || results[0].Alias != "a" || results[1].Alias != "b" || !results[0].Fetched || !results[1].Fetched || arrivals.Load() != 2 {
				t.Fatalf("fetch did not run concurrently or sort results: %+v", results)
			}
		})
	}
}

// Slice 4b1 invariant 5: 429 blocks persist and suppress later HTTP requests.
func TestFetchRateLimitBlocks(t *testing.T) {
	for _, retry := range []string{"120", "", "invalid"} {
		t.Run("retry="+retry, func(t *testing.T) {
			f := setupFetch(t, "linux")
			calls := 0
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", retry)
				w.WriteHeader(http.StatusTooManyRequests)
			})
			blob := fetchBlob("limited-access-private", (fetchNow+7200)*1000)
			first := f.m.Fetch([]string{"id-a"}, "id-a", blob, client)[0]
			until := fetchNow + 3600
			if retry == "120" {
				until = fetchNow + 120 + 900
			}
			want := "rate limited until " + time.Unix(until, 0).Local().Format("15:04")
			state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
			if err != nil || first.Error != want || first.Fetched || first.Skipped != "" || state.Accounts["id-a"].BlockedUntil != until || len(state.Accounts["id-a"].Requests) != 1 {
				t.Fatalf("wrong rate limit block: %+v, %v", first, err)
			}
			second := f.m.Fetch([]string{"id-a"}, "id-a", blob, client)[0]
			if second.Error != "" || second.Skipped != "blocked until "+time.Unix(until, 0).Local().Format("15:04") || calls != 1 {
				t.Fatal("blocked account sent another request")
			}
		})
	}
}

// Slice 4b1 invariant 6: include the exact 60s margin and millisecond boundary.
func TestFetchExpiryMargin(t *testing.T) {
	for _, margin := range []int64{-1, 0, 59999, 60000, 60001} {
		for _, live := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/live=%t", margin, live), func(t *testing.T) {
				f := setupFetch(t, "linux")
				blob := fetchBlob("expiry-access-private", fetchNow*1000+margin)
				if err := f.m.Store.Write("id-b", blob); err != nil {
					t.Fatal(err)
				}
				calls := 0
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) { calls++; io.WriteString(w, `{}`) })
				id := "id-b"
				if live {
					id = "id-a"
				}
				result := f.m.Fetch([]string{id}, "id-a", blob, client)[0]
				if margin <= 60000 {
					if calls != 0 || result.Skipped != "access token expired" || result.Error != "" {
						t.Fatal("expired token sent a request or failed to skip")
					}
					state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
					if err != nil || len(state.Accounts[id].Requests) != 0 {
						t.Fatal("expired token spent request budget")
					}
				} else if calls != 1 || !result.Fetched {
					t.Fatalf("valid token skipped: %+v", result)
				}
			})
		}
	}
}

func TestFetchCredentialRefusals(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"live-unreadable", "absent", "unreadable", "malformed", "budget", "usage-unreadable"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupFetch(t, platform)
				id, skip, message := "id-b", "", ""
				if err := f.m.Store.Write(id, fetchBlob("refused-access-private", (fetchNow+3600)*1000)); err != nil {
					t.Fatal(err)
				}
				store := usage.Store{Directory: f.m.Paths.State}
				switch failure {
				case "live-unreadable":
					id, skip = "id-a", "live login unreadable"
				case "absent":
					if err := os.Remove(f.backupPath(id, false)); err != nil {
						t.Fatal(err)
					}
					skip = "no stored login"
				case "unreadable":
					if platform == "darwin" {
						t.Setenv("FH_FAIL_READ", "fasthands/"+id)
					} else {
						if err := os.Remove(f.backupPath(id, false)); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(f.backupPath(id, false), 0700); err != nil {
							t.Fatal(err)
						}
					}
					message = unreadableBackup("b").Error()
				case "malformed":
					if err := f.m.Store.Write(id, []byte("refused-access-private")); err != nil {
						t.Fatal(err)
					}
					message = unreadableBackup("b").Error()
				case "budget":
					for range 20 {
						if _, _, err := store.Reserve(id, fetchNow); err != nil {
							t.Fatal(err)
						}
					}
					skip = "request budget spent (20 per hour)"
				case "usage-unreadable":
					put(t, filepath.Join(f.m.Paths.State, "usage.json"), []byte("torn"))
					message = fmt.Sprintf("invalid usage at %q", filepath.Join(f.m.Paths.State, "usage.json"))
				}
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("refused account sent HTTP") })
				result := f.m.Fetch([]string{id}, "id-a", nil, client)[0]
				if result.Skipped != skip || result.Error != message || result.Fetched {
					t.Fatalf("wrong credential refusal: %+v", result)
				}
			})
		}
	}
}

// Slice 4b1 invariants 3, 10: rejected tokens and server errors stay private and do not retry.
func TestFetchHTTPFailures(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := setupFetch(t, "linux")
			calls := 0
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				io.WriteString(w, "failure-access-private distinctive-body-private")
			})
			result := f.m.Fetch([]string{"id-a"}, "id-a", fetchBlob("failure-access-private", (fetchNow+3600)*1000), client)[0]
			want := "access token rejected"
			if status == 500 {
				want = "usage request returned HTTP 500"
			}
			encoded, _ := json.Marshal(result)
			state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
			if err != nil || len(state.Accounts["id-a"].Requests) != 1 || result.Error != want || result.Fetched || result.Skipped != "" || calls != 1 || strings.Contains(string(encoded), "private") {
				t.Fatalf("wrong HTTP failure: %+v", result)
			}
		})
	}
}
