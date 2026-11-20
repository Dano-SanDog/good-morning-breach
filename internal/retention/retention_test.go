package retention

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	stories, deliveries   []int64
	storyCut, deliveryCut time.Time
	storyErr              error
	calls                 int
}

func (f *fakeStore) DeleteStoriesBefore(_ context.Context, cutoff time.Time, limit int) (int64, error) {
	f.storyCut = cutoff
	f.calls++
	if f.storyErr != nil {
		return 0, f.storyErr
	}
	if limit != BatchSize {
		panic("unexpected batch size")
	}
	if len(f.stories) == 0 {
		return 0, nil
	}
	n := f.stories[0]
	f.stories = f.stories[1:]
	return n, nil
}

func (f *fakeStore) DeleteDeliveriesBefore(_ context.Context, cutoff time.Time, _ int) (int64, error) {
	f.deliveryCut = cutoff
	if len(f.deliveries) == 0 {
		return 0, nil
	}
	n := f.deliveries[0]
	f.deliveries = f.deliveries[1:]
	return n, nil
}

func TestRunUsesRetentionWindowsAndDrainsBatches(t *testing.T) {
	store := &fakeStore{stories: []int64{BatchSize, BatchSize, 7}, deliveries: []int64{3}}
	svc, _ := NewService(store)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	result, err := svc.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Stories != 2*BatchSize+7 || result.Deliveries != 3 {
		t.Fatalf("result = %+v", result)
	}
	if !store.storyCut.Equal(now.AddDate(0, 0, -365)) || !store.deliveryCut.Equal(now.AddDate(0, 0, -90)) {
		t.Fatalf("cutoffs = %v, %v", store.storyCut, store.deliveryCut)
	}
}

func TestRunBoundsBatchesAndContinuesAfterStoryError(t *testing.T) {
	always := make([]int64, MaxBatches+50)
	for i := range always {
		always[i] = BatchSize
	}
	store := &fakeStore{stories: always, deliveries: []int64{1}}
	svc, _ := NewService(store)
	result, err := svc.Run(context.Background())
	if err != nil || store.calls != MaxBatches || result.Stories != int64(MaxBatches*BatchSize) {
		t.Fatalf("calls=%d result=%+v err=%v", store.calls, result, err)
	}

	failing := &fakeStore{storyErr: errors.New("boom"), deliveries: []int64{4}}
	svc, _ = NewService(failing)
	result, err = svc.Run(context.Background())
	if err == nil || result.Deliveries != 4 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
