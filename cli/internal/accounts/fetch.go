package accounts

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/oauth"
	"fasthands/internal/usage"
)

type FetchResult struct {
	Alias       string `json:"alias"`
	AccountUUID string `json:"accountUuid"`
	Fetched     bool   `json:"fetched"`
	Skipped     string `json:"skipped"`
	Error       string `json:"error"`
}

func (m Manager) Fetch(ids []string, live string, liveBlob []byte, client oauth.Client) []FetchResult {
	metadata, readErr := m.Read()
	results := make([]FetchResult, len(ids))
	var workers sync.WaitGroup
	for i, id := range ids {
		workers.Go(func() {
			result := FetchResult{Alias: metadata[id].Alias, AccountUUID: id}
			defer func() { results[i] = result }()
			if readErr != nil {
				result.Error = readErr.Error()
				return
			}
			blob := liveBlob
			if id == live {
				if blob == nil {
					result.Skipped = "live login unreadable"
					return
				}
			} else {
				var err error
				blob, err = m.Store.Read(id)
				if errors.Is(err, credstore.ErrAbsent) {
					result.Skipped = "no stored login"
					return
				}
				if err != nil {
					result.Error = unreadableBackup(result.Alias).Error()
					return
				}
			}
			token, expires, err := claudecfg.AccessToken(blob)
			if err != nil {
				result.Error = unreadableBackup(result.Alias).Error()
				if id == live {
					result.Error = "active login is not a Claude OAuth login"
				}
				return
			}
			at := now()
			if token == "" || expires <= at.Add(60*time.Second).UnixMilli() {
				result.Skipped = "access token expired" // O5: allow Claude a 60s safety margin.
				return
			}
			store := usage.Store{Directory: m.Paths.State}
			ok, reason, err := store.Reserve(id, at.Unix())
			if err != nil {
				result.Error = err.Error()
				return
			}
			if !ok {
				result.Skipped = reason
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // O1: Claude's usage timeout.
			u, err := client.Usage(ctx, token)
			cancel()
			var limited *oauth.RateLimited
			switch {
			case err == nil:
				err = store.SaveFetched(id, u, now().Unix())
				result.Fetched = err == nil
			case errors.As(err, &limited):
				wait := int64(3600)
				if limited.Known {
					wait = int64(limited.RetryAfter/time.Second) + 900 // O3: avoid re-arming a block at its deadline.
				}
				until := now().Unix() + wait
				result.Error = "rate limited until " + time.Unix(until, 0).Local().Format("15:04")
				err = store.Block(id, until)
			case errors.Is(err, oauth.ErrUnauthorized):
				result.Error = "access token rejected"
				return
			}
			if err != nil {
				result.Error = err.Error()
			}
		})
	}
	workers.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Alias < results[j].Alias })
	return results
}
