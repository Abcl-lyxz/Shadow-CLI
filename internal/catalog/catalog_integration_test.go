package catalog

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveCatalogShape(t *testing.T) {
	if os.Getenv("SHADOW_TEST_CATALOG_LIVE") == "" {
		t.Skip("set SHADOW_TEST_CATALOG_LIVE=1 for network integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := Fetch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 20 {
		t.Fatalf("unexpectedly small catalog: %d", len(data))
	}
	found := false
	for _, provider := range data {
		if provider.API != "" && len(provider.Models) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no provider had API URL and models")
	}
}
