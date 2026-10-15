// Package oauth reads usage with an account's own access token.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type Window struct {
	Used     float64
	ResetsAt int64
}

type Usage struct {
	FiveHour, SevenDay *Window
	Models             map[string]*Window
}

type Client struct {
	UsageURL, TokenURL, UserAgent string
	HTTP                          *http.Client
}

var ErrUnauthorized = errors.New("access token rejected")

type RateLimited struct {
	RetryAfter time.Duration
	Known      bool
}

func (*RateLimited) Error() string { return "usage request rate limited" }

type usageWindow struct {
	Utilization *float64
	ResetsAt    *string `json:"resets_at"`
}

func (c Client) Usage(ctx context.Context, accessToken string) (Usage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UsageURL, nil)
	if err != nil {
		return Usage{}, errors.New("cannot create usage request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20") // O1: OAuth usage requires this beta.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent) // O4: keep our budget separate from Claude's.
	httpClient := http.Client{}
	if c.HTTP != nil {
		httpClient = *c.HTTP
	}
	// O3: a reservation covers one request, never a redirect or retry.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		// Transport errors may quote URLs or headers; expose no underlying text.
		return Usage{}, errors.New("cannot request usage")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusTooManyRequests:
		seconds, err := strconv.ParseUint(response.Header.Get("Retry-After"), 10, 63)
		known := err == nil && seconds <= uint64((1<<63-1)/time.Second)
		limited := &RateLimited{Known: known}
		if known {
			limited.RetryAfter = time.Duration(seconds) * time.Second
		}
		return Usage{}, limited
	case http.StatusUnauthorized, http.StatusForbidden:
		return Usage{}, ErrUnauthorized // O6: never retry the rejected token.
	case http.StatusOK:
	default:
		return Usage{}, fmt.Errorf("usage request returned HTTP %d", response.StatusCode)
	}
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil || len(data) == limit {
		return Usage{}, errors.New("cannot read usage response")
	}
	var body *struct {
		FiveHour *usageWindow `json:"five_hour"`
		SevenDay *usageWindow `json:"seven_day"`
		Limits   []json.RawMessage
	}
	if json.Unmarshal(data, &body) != nil || body == nil {
		return Usage{}, errors.New("invalid usage response")
	}
	parseWindow := func(w *usageWindow) *Window {
		if w == nil {
			return nil
		}
		return window(w.Utilization, w.ResetsAt)
	}
	u := Usage{FiveHour: parseWindow(body.FiveHour), SevenDay: parseWindow(body.SevenDay), Models: map[string]*Window{}}
	for _, raw := range body.Limits {
		var entry struct {
			Scope struct {
				Model struct {
					DisplayName string `json:"display_name"`
				}
			}
			Percent  *float64
			ResetsAt *string `json:"resets_at"`
		}
		if json.Unmarshal(raw, &entry) == nil && entry.Scope.Model.DisplayName != "" {
			if w := window(entry.Percent, entry.ResetsAt); w != nil {
				u.Models[entry.Scope.Model.DisplayName] = w
			}
		}
	}
	return u, nil
}

func window(used *float64, reset *string) *Window {
	// Over 100 is kept: an account past its limit is exactly what the picker must see.
	if used == nil || *used < 0 {
		return nil
	}
	w := &Window{Used: *used}
	if reset != nil {
		if at, err := time.Parse(time.RFC3339, *reset); err == nil {
			w.ResetsAt = at.Unix() // O2: Unix discards fractional seconds after offset parsing.
		}
	}
	return w
}
