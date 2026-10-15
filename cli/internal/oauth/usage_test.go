package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const privateToken = "oauth-access-distinctive-private"

func testClient(t *testing.T, handler http.HandlerFunc) Client {
	t.Helper()
	return Client{UsageURL: "http://usage.test", UserAgent: "fasthands/dev", HTTP: &http.Client{Transport: testTransport(handler)}}
}

type testTransport http.HandlerFunc

// O1 request assertions use httptest without binding a sandbox-blocked socket.
func (handler testTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	response := httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(response, r)
	return response.Result(), nil
}

// Slice 4b1 invariant 1: nulls, fractional offsets, mixed model limits, and unknown keys.
func TestUsageParsing(t *testing.T) {
	reset := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC).Unix()
	for _, tt := range []struct {
		name, body  string
		five, seven *Window
		models      map[string]*Window
	}{
		{"both", `{"five_hour":{"utilization":42,"resets_at":"2026-10-16T12:00:00.123456+03:00"},"seven_day":{"utilization":61.5,"resets_at":"2026-10-16T09:00:00.123456+00:00"},"seven_day_opus":{"utilization":99},"future":true}`, &Window{42, reset}, &Window{61.5, reset}, nil},
		{"null-window", `{"five_hour":null,"seven_day":{"utilization":0,"resets_at":null},"limits":null}`, nil, &Window{}, nil},
		{"null-utilization", `{"five_hour":{"utilization":null,"resets_at":"2026-10-16T09:00:00Z"}}`, nil, nil, nil},
		{"bad-reset", `{"five_hour":{"utilization":100,"resets_at":"unknown"}}`, &Window{Used: 100}, nil, nil},
		{"models", `{"limits":[null,42,{}, {"scope":{"model":{"display_name":"Fable"}},"percent":12.5,"resets_at":"2026-10-16T09:00:00.123456+00:00"},{"scope":{"model":{"display_name":"Unknown"}},"percent":0,"resets_at":null},{"scope":{"model":{"display_name":"BadReset"}},"percent":20,"resets_at":"bad"},{"percent":40},{"scope":{"model":{"display_name":""}},"percent":40},{"scope":{"model":{"display_name":"Null"}},"percent":null},{"scope":{"model":{"display_name":"Text"}},"percent":"30"},{"scope":{"model":{"display_name":123}},"percent":30},{"scope":{"model":{"display_name":"Over"}},"percent":101}]}`, nil, nil, map[string]*Window{"Fable": {12.5, reset}, "Unknown": {}, "BadReset": {Used: 20}, "Over": {Used: 101}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tt.body) })
			u, err := client.Usage(context.Background(), privateToken)
			if err != nil || !reflect.DeepEqual(u.FiveHour, tt.five) || !reflect.DeepEqual(u.SevenDay, tt.seven) || len(u.Models) != len(tt.models) {
				t.Fatalf("wrong parsed usage: %+v, %v", u, err)
			}
			for name, window := range tt.models {
				if !reflect.DeepEqual(u.Models[name], window) {
					t.Fatalf("wrong model %s: %+v", name, u.Models[name])
				}
			}
		})
	}
}

// Slice 4b1 invariant 2: use the account's token and our separate User-Agent class.
func TestUsageHeaders(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+privateToken ||
			r.Header.Get("anthropic-beta") != "oauth-2025-04-20" || r.Header.Get("Content-Type") != "application/json" ||
			!strings.HasPrefix(r.UserAgent(), "fasthands/") {
			t.Error("wrong usage request headers or method")
		}
		io.WriteString(w, `{}`)
	})
	if _, err := client.Usage(context.Background(), privateToken); err != nil {
		t.Fatal(err)
	}
}

// Slice 4b1 invariants 3, 10: typed failures never expose response or credential text.
func TestUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		retry  string
		known  bool
		wait   time.Duration
	}{
		{"limited", 429, "120", true, 120 * time.Second}, {"missing", 429, "", false, 0},
		{"zero", 429, "0", true, 0}, {"negative", 429, "-1", false, 0},
		{"decimal", 429, "1.5", false, 0}, {"date", 429, "Fri, 16 Oct 2026 09:00:00 GMT", false, 0},
		{"overflow", 429, "999999999999999999999999", false, 0},
		{"unauthorized", 401, "", false, 0}, {"forbidden", 403, "", false, 0}, {"server", 500, "", false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", tt.retry)
				w.WriteHeader(tt.status)
				io.WriteString(w, "distinctive-response-private "+privateToken)
			})
			_, err := client.Usage(context.Background(), privateToken)
			if err == nil || strings.Contains(err.Error(), privateToken) || strings.Contains(err.Error(), "distinctive-response-private") || calls != 1 {
				t.Fatal("usage failure leaked private text or retried")
			}
			var limited *RateLimited
			if tt.status == 429 && (!errors.As(err, &limited) || limited.Known != tt.known || limited.RetryAfter != tt.wait) {
				t.Fatal("wrong rate limit details")
			}
			if (tt.status == 401 || tt.status == 403) && !errors.Is(err, ErrUnauthorized) {
				t.Fatal("rejected token must be unauthorized")
			}
		})
	}
}

func TestUsageInvalidAndBoundedBody(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `broken-private`, `{} {}`, `{"five_hour":"bad"}`, `{"private":"` + strings.Repeat("x", 1<<20) + `"}`} {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		if _, err := client.Usage(context.Background(), privateToken); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid or oversized response accepted or exposed")
		}
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat(" ", 2<<20)) })
	var read int
	client.HTTP.Transport = bodyTransport{client.HTTP.Transport, &read}
	if _, err := client.Usage(context.Background(), privateToken); err == nil || read > 1<<20 {
		t.Fatal("client read more than 1 MiB or accepted oversized response")
	}
}

type bodyTransport struct {
	http.RoundTripper
	read *int
}

func (t bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(r)
	if err == nil {
		response.Body = countedBody{response.Body, t.read}
	}
	return response, err
}

type countedBody struct {
	io.ReadCloser
	read *int
}

func (b countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	*b.read += n
	return n, err
}

func TestUsageTransportAndRedirect(t *testing.T) {
	calls := 0
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/another", http.StatusFound)
	})
	if _, err := client.Usage(context.Background(), privateToken); err == nil || calls != 1 {
		t.Fatal("redirect spent an unreserved request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.UsageURL += "/" + privateToken
	if _, err := client.Usage(ctx, privateToken); err == nil || strings.Contains(err.Error(), privateToken) {
		t.Fatal("transport failure exposed token from URL")
	}
}
