package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/testutils"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestInitialiseMongo_TableDriven(t *testing.T) {
	fakeClient := &mongo.Client{}
	uri := "mongodb://u:pw@h:p/db?authSource=admin"
	config := app.MongoConfig{Host: "h", Port: "p", DBName: "db", Username: "u", Password: "pw"}

	cases := []testutils.TestCase{
		{
			Name:   "Immediate success",
			Config: config,
			Factory: func(ctx context.Context, inUri string) (*mongo.Client, error) {
				if inUri != uri {
					return nil, errors.New("bad uri")
				}
				return fakeClient, nil
			},
			Timeout:      60 * time.Second,
			WantClient:   true,
			WantAttempts: 1,
			WantSleeps:   0,
			WantErr:      false,
		},
		{
			Name:   "Retries then success (3rd try)",
			Config: config,
			Factory: func() func(ctx context.Context, inUri string) (*mongo.Client, error) {
				attempt := 0
				return func(ctx context.Context, inUri string) (*mongo.Client, error) {
					attempt++
					if attempt == 3 {
						return fakeClient, nil
					}
					return nil, fmt.Errorf("fail on attempt %d", attempt)
				}
			}(),
			Timeout:      60 * time.Second,
			WantClient:   true,
			WantAttempts: 3,
			WantSleeps:   2,
			WantErr:      false,
		},
		{
			Name:   "All retries fail (timeout)",
			Config: config,
			Factory: func(ctx context.Context, inUri string) (*mongo.Client, error) {
				return nil, errors.New("fail always")
			},
			Timeout:      6 * time.Second,
			WantClient:   false,
			WantAttempts: 3,
			WantSleeps:   3,
			WantErr:      true,
		},
		{
			Name:   "Success on last allowed try",
			Config: config,
			Factory: func() func(ctx context.Context, inUri string) (*mongo.Client, error) {
				attempt := 0
				return func(ctx context.Context, inUri string) (*mongo.Client, error) {
					attempt++
					if attempt == 4 {
						return fakeClient, nil
					}
					return nil, errors.New("fail")
				}
			}(),
			Timeout:      8 * time.Second,
			WantClient:   true,
			WantAttempts: 4,
			WantSleeps:   3,
			WantErr:      false,
		},
		{
			Name:   "Zero retries (timeout = 0)",
			Config: config,
			Factory: func(ctx context.Context, inUri string) (*mongo.Client, error) {
				return nil, errors.New("fail instantly")
			},
			Timeout:      0 * time.Second,
			WantClient:   false,
			WantAttempts: 1,
			WantSleeps:   1, // FIXED: sleep is called once after the failed attempt
			WantErr:      true,
		},
		{
			Name:   "Invalid URI",
			Config: app.MongoConfig{Host: "bad", Port: "bad", DBName: "bad", Username: "bad", Password: "bad"},
			Factory: func(ctx context.Context, inUri string) (*mongo.Client, error) {
				return nil, errors.New("bad uri")
			},
			Timeout:      2 * time.Second,
			WantClient:   false,
			WantAttempts: 1,
			WantSleeps:   1,
			WantErr:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			a := &app.App{Log: testutils.SetupLogger()}
			attempts := 0
			sleepCalls := 0

			start := time.Now()
			simulatedNow := start

			sleep := func(d time.Duration) {
				sleepCalls++
				simulatedNow = simulatedNow.Add(d)
			}

			now := func() time.Time {
				return simulatedNow
			}

			factory := func(ctx context.Context, uri string) (*mongo.Client, error) {
				attempts++
				return tc.Factory(ctx, uri)
			}

			err := a.InitialiseMongo(tc.Config, factory, sleep, now, tc.Timeout)

			if tc.WantErr && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tc.WantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.WantClient && a.Mongo == nil {
				t.Errorf("expected client to be set but was nil")
			}
			if !tc.WantClient && a.Mongo != nil {
				t.Errorf("expected no client but got one")
			}
			if attempts != tc.WantAttempts {
				t.Errorf("expected %d attempts, got %d", tc.WantAttempts, attempts)
			}
			if sleepCalls != tc.WantSleeps {
				t.Errorf("expected %d sleep calls, got %d", tc.WantSleeps, sleepCalls)
			}
		})
	}
}
