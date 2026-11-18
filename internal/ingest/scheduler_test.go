package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRunPeriodicallyRunsImmediatelyAndRepeatsWithoutOverlap(t *testing.T) {
	runner := &countingRunner{calls: make(chan struct{}, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunPeriodically(ctx, runner, 10*time.Millisecond)
	}()

	for range 3 {
		select {
		case <-runner.calls:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("scheduled collection did not run")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunPeriodically() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
	if got := runner.maxActive(); got != 1 {
		t.Fatalf("maximum concurrent collection runs = %d; want 1", got)
	}
}

func TestRunPeriodicallyStopsImmediatelyWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &countingRunner{calls: make(chan struct{}, 1)}
	if err := RunPeriodically(ctx, runner, time.Hour); err != nil {
		t.Fatalf("RunPeriodically() error = %v", err)
	}
	select {
	case <-runner.calls:
		t.Fatal("collection ran after the context was canceled")
	default:
	}
}

func TestRunPeriodicallyRequiresRunnerAndPositiveInterval(t *testing.T) {
	ctx := context.Background()
	if err := RunPeriodically(ctx, nil, time.Second); err == nil {
		t.Fatal("nil runner was accepted")
	}
	runner := &countingRunner{calls: make(chan struct{}, 1)}
	if err := RunPeriodically(ctx, runner, 0); err == nil {
		t.Fatal("non-positive interval was accepted")
	}
}

type countingRunner struct {
	calls  chan struct{}
	mu     sync.Mutex
	runs   int
	active int
	max    int
}

func (r *countingRunner) Run(ctx context.Context) ([]Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, ctx.Err()
	}
	r.mu.Lock()
	r.runs++
	r.active++
	if r.active > r.max {
		r.max = r.active
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()
	r.calls <- struct{}{}
	time.Sleep(25 * time.Millisecond)
	return nil, errors.New("expected test runner failure")
}

func (r *countingRunner) maxActive() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}
