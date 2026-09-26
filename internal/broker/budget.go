package broker

import (
	"context"
	"time"

	"shadow/internal/store"
)

func bindFixtureBudget(fetch *fetcher, st *store.Store, runID string, cleanup bool) {
	fetch.reserveRun = func(ctx context.Context) (func() error, error) {
		token, err := st.ReserveFixtureRequest(ctx, runID, cleanup, fetch.interval)
		if err != nil {
			return nil, err
		}
		return func() error {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return st.ReleaseFixtureRequest(releaseCtx, runID, token)
		}, nil
	}
}
