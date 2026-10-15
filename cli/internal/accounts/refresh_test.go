package accounts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/claudelock"
	"fasthands/internal/credstore"
	"fasthands/internal/oauth"
	"fasthands/internal/usage"
)

const rotatedAccess = "rotated-access-distinctive-private"
const rotatedRefresh = "rotated-refresh-distinctive-private"
const refreshReply = `{"access_token":"` + rotatedAccess + `","refresh_token":"` + rotatedRefresh + `","expires_in":28800,"account":{"uuid":"id-b"}}`

func setupRefresh(t *testing.T, platform string) *switchFixture {
	t.Helper()
	f := setupFetch(t, platform)
	old := beforeRefreshLock
	t.Cleanup(func() { beforeRefreshLock = old })
	return f
}

func assertRefreshPrivate(t *testing.T, f *switchFixture, output string) {
	t.Helper()
	for _, name := range []string{"usage.json", "accounts.json"} {
		data, err := os.ReadFile(filepath.Join(f.m.Paths.State, name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		output += string(data)
	}
	for _, token := range []string{rotatedAccess, rotatedRefresh, "target-access-private", "target-refresh-private", "new-lineage-private", "injected-private"} {
		if strings.Contains(output, token) || strings.Contains(output, hex.EncodeToString([]byte(token))) {
			t.Fatal("refresh exposed credential text")
		}
	}
}

func assertFlock(t *testing.T, path string, held bool) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if held && !errors.Is(err, syscall.EWOULDBLOCK) || !held && err != nil {
		t.Error("wrong flock state during network request")
	}
}

// Slice 4b2 invariants 3, 5, 10: never refresh live; save rotation before using its access token.
func TestRefreshIdlePersistsBeforeUsage(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupRefresh(t, platform)
			for _, lock := range claudelock.Locks(f.loc) {
				if err := os.Mkdir(lock.Path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			tokenCalls, usageCalls := 0, 0
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertFlock(t, filepath.Join(f.m.Paths.State, "usage.lock"), false)
				if r.URL.Host == "token.test" {
					tokenCalls++
					assertFlock(t, filepath.Join(f.m.Paths.State, "accounts.lock"), true)
					if !bytes.Equal(f.rawBackup(t, "id-b", true), f.target) {
						t.Error("request preceded previous-login write")
					}
					io.WriteString(w, refreshReply)
					return
				}
				usageCalls++
				assertFlock(t, filepath.Join(f.m.Paths.State, "accounts.lock"), false)
				access, refresh, err := claudecfg.OAuthTokens(f.rawBackup(t, "id-b", false))
				if err != nil || access != rotatedAccess || refresh != rotatedRefresh || r.Header.Get("Authorization") != "Bearer "+rotatedAccess {
					t.Error("usage arrived before rotated backup was saved")
				}
				io.WriteString(w, `{}`)
			})
			live := f.m.Fetch([]string{"id-a"}, "id-a", f.live, client, f.loc)[0]
			if live.Skipped != "access token expired" || tokenCalls != 0 || usageCalls != 0 {
				t.Fatal("live login reached an endpoint")
			}
			result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
			if !result.Fetched || result.Error != "" || result.Skipped != "" || tokenCalls != 1 || usageCalls != 1 || !bytes.Equal(f.rawLive(t), f.live) {
				t.Fatalf("idle rotation failed: %+v", result)
			}
			encoded, _ := json.Marshal(result)
			assertRefreshPrivate(t, f, string(encoded))
		})
	}
}

// Slice 4b2 invariant 3: R2's locked live check wins over Fetch's stale hint.
func TestRefreshIdleRechecksLive(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupRefresh(t, platform)
			beforeRefreshLock = func() { put(t, f.loc.GlobalConfig, []byte(`{"oauthAccount":{"accountUuid":"id-b"}}`)) }
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("new live login reached endpoint") })
			result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
			if result.Skipped != "access token expired" || result.Error != "" || !bytes.Equal(f.rawBackup(t, "id-b", false), f.target) {
				t.Fatal("locked live check did not refuse rotation")
			}
			if _, err := os.Stat(f.backupPath("id-b", true)); !os.IsNotExist(err) {
				t.Fatal("live refusal wrote previous login")
			}
		})
	}
}

type failingRefreshStore struct {
	credstore.Backend
	writes, failures int
	failPrev         bool
	unreadable       bool
}

func (s *failingRefreshStore) Read(id string) ([]byte, error) {
	if s.unreadable {
		return nil, errors.New("injected-private " + rotatedRefresh)
	}
	return s.Backend.Read(id)
}

func (s *failingRefreshStore) Write(id string, blob []byte) error {
	s.writes++
	if s.writes <= s.failures {
		return errors.New("injected-private " + rotatedRefresh)
	}
	return s.Backend.Write(id, blob)
}

func (s *failingRefreshStore) WritePrev(id string, blob []byte) error {
	if s.failPrev {
		return errors.New("injected-private " + rotatedRefresh)
	}
	return s.Backend.WritePrev(id, blob)
}

// Slice 4b2 invariants 4, 5, 10: failure before HTTP aborts; post-rotation persistence retries once.
func TestRefreshIdleWriteFailures(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"previous", "once", "twice"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupRefresh(t, platform)
				store := &failingRefreshStore{Backend: f.m.Store, failures: 1, failPrev: failure == "previous"}
				if failure == "twice" {
					store.failures = 2
				}
				f.m.Store = store
				tokens, usages := 0, 0
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host == "token.test" {
						tokens++
						io.WriteString(w, refreshReply)
					} else {
						usages++
						io.WriteString(w, `{}`)
					}
				})
				result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				want := "refreshed login for b could not be saved; log in to Claude Code as b and run fasthands add"
				switch failure {
				case "previous":
					if tokens != 0 || usages != 0 || store.writes != 0 || result.Error != "cannot save previous login for b" {
						t.Fatal("previous write failure spent a refresh token")
					}
				case "once":
					if tokens != 1 || usages != 1 || store.writes != 2 || !result.Fetched {
						t.Fatal("failed persistence was not retried exactly once")
					}
				case "twice":
					if tokens != 1 || usages != 0 || store.writes != 2 || result.Error != want {
						t.Fatal("lost rotation did not stop usage with exact recovery message")
					}
				}
				if failure != "once" && !bytes.Equal(f.rawBackup(t, "id-b", false), f.target) {
					t.Fatal("failed write changed original backup")
				}
				assertRefreshPrivate(t, f, result.Error+result.Skipped)
			})
		}
	}
}

// Slice 4b2 invariant 6: both R5's CAS and R6's response identity refuse rotated credentials.
func TestRefreshIdleRefusesChangedLogin(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"cas", "uuid", "empty-uuid"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupRefresh(t, platform)
				want := f.target
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host != "token.test" {
						t.Error("refused rotation reached usage")
						return
					}
					reply := refreshReply
					if failure == "cas" {
						want = []byte(strings.Replace(targetLogin, "target-refresh-private", "new-lineage-private", 1))
						if err := f.m.Store.Write("id-b", want); err != nil {
							t.Error(err)
						}
					} else {
						other := "id-other"
						if failure == "empty-uuid" {
							other = ""
						}
						reply = strings.Replace(reply, "id-b", other, 1)
					}
					io.WriteString(w, reply)
				})
				result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				if result.Fetched || result.Error == "" || !strings.Contains(result.Error, "for b") || !strings.Contains(result.Error, "log in to Claude Code as b and run fasthands add") || !bytes.Equal(f.rawBackup(t, "id-b", false), want) {
					t.Fatal("refused rotation overwrote backup or lacked alias and recovery guidance")
				}
				assertRefreshPrivate(t, f, result.Error)
			})
		}
	}
}

// Slice 4b2 invariants 7, 10: persist only a hash; re-add implicitly unblocks a new lineage.
func TestRefreshIdleDeadLineage(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupRefresh(t, platform)
			calls, usages := 0, 0
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Host != "token.test" {
					usages++
					io.WriteString(w, `{}`)
					return
				}
				calls++
				if calls == 1 {
					w.WriteHeader(400)
					io.WriteString(w, `{"error":"invalid_grant","description":"target-refresh-private"}`)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if !bytes.Contains(body, []byte("new-lineage-private")) {
					t.Error("re-add did not refresh new lineage")
				}
				io.WriteString(w, refreshReply)
			})
			want := "stored login expired; log in to Claude Code as b and run fasthands add"
			for range 2 {
				result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				if result.Skipped != want || result.Error != "" || result.Fetched || calls != 1 || usages != 0 {
					t.Fatal("dead lineage retried or wrong guidance")
				}
			}
			state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
			digest := sha256.Sum256([]byte("target-refresh-private"))
			if err != nil || state.Accounts["id-b"].DeadRefresh != hex.EncodeToString(digest[:])[:16] || state.Accounts["id-b"].RefreshRetryAt != 0 {
				t.Fatal("wrong dead-lineage fingerprint")
			}
			c := capture("id-b", "b@example.com")
			c.Credentials = []byte(strings.Replace(targetLogin, "target-refresh-private", "new-lineage-private", 1))
			if _, err := f.m.Add(c, "b", true); err != nil {
				t.Fatal(err)
			}
			result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
			state, err = (usage.Store{Directory: f.m.Paths.State}).Read()
			if err != nil || !result.Fetched || calls != 2 || usages != 1 || state.Accounts["id-b"].DeadRefresh != "" {
				t.Fatal("new lineage stayed blocked")
			}
			assertRefreshPrivate(t, f, fmt.Sprint(result))
		})
	}
}

// Slice 4b2 invariant 8: server and invalid_client failures share persisted 600s backoff.
func TestRefreshIdleRetryDeadline(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"server", "invalid-client"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupRefresh(t, platform)
				clock := time.Unix(fetchNow, 0)
				now = func() time.Time { return clock }
				calls, usages := 0, 0
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host != "token.test" {
						usages++
						io.WriteString(w, `{}`)
						return
					}
					calls++
					if calls == 1 {
						status, code := 500, "server_error"
						if failure == "invalid-client" {
							status, code = 400, "invalid_client"
						}
						w.WriteHeader(status)
						io.WriteString(w, `{"error":"`+code+`","description":"target-refresh-private"}`)
						return
					}
					io.WriteString(w, refreshReply)
				})
				first := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				state, err := (usage.Store{Directory: f.m.Paths.State}).Read()
				if err != nil || first.Error == "" || state.Accounts["id-b"].RefreshRetryAt != fetchNow+600 || state.Accounts["id-b"].DeadRefresh != "" {
					t.Fatal("transient failure lacked backoff or killed lineage")
				}
				clock = clock.Add(599 * time.Second)
				second := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				want := "token refresh failed; retrying after " + time.Unix(fetchNow+600, 0).Local().Format("15:04")
				if second.Skipped != want || second.Error != "" || calls != 1 || usages != 0 {
					t.Fatal("backoff failed to suppress endpoints")
				}
				clock = clock.Add(time.Second)
				third := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				state, err = (usage.Store{Directory: f.m.Paths.State}).Read()
				if err != nil || !third.Fetched || calls != 2 || usages != 1 || state.Accounts["id-b"].RefreshRetryAt != 0 {
					t.Fatal("retry did not resume at deadline")
				}
				assertRefreshPrivate(t, f, first.Error+second.Skipped+third.Error)
			})
		}
	}
}

// Slice 4b2 invariant 9: requests hold the shared flock and never overlap, even for different accounts.
func TestRefreshIdleSerializesRequests(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupRefresh(t, platform)
			if _, err := f.m.Add(capture("id-c", "c@example.com"), "c", true); err != nil {
				t.Fatal(err)
			}
			var started, inFlight, maximum, calls atomic.Int32
			bothStarted := make(chan struct{})
			beforeRefreshLock = func() {
				if started.Add(1) == 2 {
					close(bothStarted)
				}
			}
			client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
				current := inFlight.Add(1)
				defer inFlight.Add(-1)
				if current != 1 {
					t.Error("token requests overlapped")
				}
				maximum.Store(max(maximum.Load(), current))
				calls.Add(1)
				select {
				case <-bothStarted:
				case <-r.Context().Done():
					t.Error("second caller did not start")
					return
				}
				assertFlock(t, filepath.Join(f.m.Paths.State, "accounts.lock"), true)
				io.WriteString(w, `{"access_token":"`+rotatedAccess+`","refresh_token":"`+rotatedRefresh+`","expires_in":28800}`)
			})
			var workers sync.WaitGroup
			for _, id := range []string{"id-b", "id-c"} {
				workers.Go(func() {
					if _, err := f.m.RefreshIdle(id, client, f.loc); err != nil {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			if maximum.Load() != 1 || calls.Load() != 2 {
				t.Fatal("token refresh requests overlapped or disappeared")
			}
		})
	}
}

// R2: a waiting caller reuses a login already refreshed before it acquired the flock.
func TestRefreshIdleUsesFreshBackup(t *testing.T) {
	f := setupRefresh(t, "linux")
	beforeRefreshLock = func() {
		if err := f.m.Store.Write("id-b", fetchBlob(rotatedAccess, (fetchNow+3600)*1000)); err != nil {
			t.Error(err)
		}
	}
	calls := 0
	client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Host != "usage.test" || r.Header.Get("Authorization") != "Bearer "+rotatedAccess {
			t.Error("fresh backup triggered refresh or used stale token")
		}
		io.WriteString(w, `{}`)
	})
	result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
	if !result.Fetched || calls != 1 {
		t.Fatal("fresh backup was not reused")
	}
}

// Slice 4b2 invariants 5, 6, 10: failures after rotation remain loud and never send usage.
func TestRefreshIdlePostResponseFailures(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"recheck", "expiry", "usage-state"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupRefresh(t, platform)
				store := &failingRefreshStore{Backend: f.m.Store}
				f.m.Store = store
				client := fetchClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host != "token.test" {
						t.Error("failed rotation reached usage")
						return
					}
					reply := refreshReply
					switch failure {
					case "recheck":
						store.unreadable = true
					case "expiry":
						reply = strings.Replace(reply, "28800", "9223372036854775807", 1)
					case "usage-state":
						put(t, filepath.Join(f.m.Paths.State, "usage.json"), []byte("torn"))
					}
					io.WriteString(w, reply)
				})
				result := f.m.Fetch([]string{"id-b"}, "id-a", nil, client, f.loc)[0]
				if result.Fetched || result.Error == "" || failure != "usage-state" && !strings.Contains(result.Error, "log in to Claude Code as b and run fasthands add") {
					t.Fatal("post-response failure lacked recovery guidance")
				}
				want := f.target
				if failure == "usage-state" {
					want, _ = claudecfg.RotateLogin(f.target, oauth.Tokens{AccessToken: rotatedAccess, RefreshToken: rotatedRefresh, ExpiresIn: 28800}, fetchNow*1000)
				}
				if !bytes.Equal(f.rawBackup(t, "id-b", false), want) {
					t.Fatal("wrong backup after post-response failure")
				}
				assertRefreshPrivate(t, f, result.Error)
			})
		}
	}
}
