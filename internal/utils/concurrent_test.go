package utils

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()
	if cfg.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", cfg.MaxAttempts)
	}
	if cfg.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay = %v, want 1s", cfg.InitialDelay)
	}
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", cfg.MaxDelay)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", cfg.Multiplier)
	}
}

func TestNewConcurrentFileUploader(t *testing.T) {
	u := NewConcurrentFileUploader(5)
	if u.maxConcurrent != 5 {
		t.Errorf("maxConcurrent = %d, want 5", u.maxConcurrent)
	}
	if cap(u.semaphore) != 5 {
		t.Errorf("semaphore cap = %d, want 5", cap(u.semaphore))
	}

	u2 := NewConcurrentFileUploader(0)
	if u2.maxConcurrent != 25 {
		t.Errorf("maxConcurrent = %d, want 25 (default)", u2.maxConcurrent)
	}

	u3 := NewConcurrentFileUploader(-1)
	if u3.maxConcurrent != 25 {
		t.Errorf("maxConcurrent = %d, want 25 (default)", u3.maxConcurrent)
	}
}

func TestRetryWithBackoffSuccess(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  2,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	fn := func() error {
		attempts++
		return nil
	}

	err := RetryWithBackoff(context.Background(), cfg, fn)
	if err != nil {
		t.Errorf("RetryWithBackoff() = %v, want nil", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestRetryWithBackoffAllFailures(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	testErr := errors.New("always fails")
	fn := func() error {
		attempts++
		return testErr
	}

	err := RetryWithBackoff(context.Background(), cfg, fn)
	if err == nil {
		t.Fatal("RetryWithBackoff() should return an error")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("RetryWithBackoff() = %v, want %v", err, testErr)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRetryWithBackoffContextCancel(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	fn := func() error {
		attempts++
		cancel()
		return errors.New("fail")
	}

	err := RetryWithBackoff(ctx, cfg, fn)
	if err == nil {
		t.Fatal("RetryWithBackoff() should return an error when context is cancelled")
	}
}

func TestConcurrentFileUploaderUpload(t *testing.T) {
	uploader := NewConcurrentFileUploader(2)
	files := []string{"a.txt", "b.txt", "c.txt"}

	var mu sync.Mutex
	concurrent := 0
	maxConcurrent := 0

	uploadFunc := func(path string) error {
		mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		mu.Unlock()

		time.Sleep(5 * time.Millisecond)

		mu.Lock()
		concurrent--
		mu.Unlock()
		return nil
	}

	results := uploader.UploadFiles(context.Background(), files, uploadFunc)

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	for _, r := range results {
		if !r.Success {
			t.Errorf("upload of %s failed: %v", r.FilePath, r.Error)
		}
	}
	if maxConcurrent > 2 {
		t.Errorf("maxConcurrent = %d, want at most 2", maxConcurrent)
	}
}

func TestConcurrentFileUploaderContextCancel(t *testing.T) {
	uploader := NewConcurrentFileUploader(1)
	ctx, cancel := context.WithCancel(context.Background())

	uploader.semaphore <- struct{}{}

	files := []string{"blocked.txt"}
	done := make(chan struct{})
	go func() {
		uploader.UploadFiles(ctx, files, func(path string) error {
			return nil
		})
		close(done)
	}()

	cancel()
	<-uploader.semaphore

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("UploadFiles did not return within 500ms after context cancellation")
	}
}

func TestWorkerPoolBasic(t *testing.T) {
	pool := NewWorkerPool(context.Background(), 3)
	var counter int64

	for i := 0; i < 10; i++ {
		pool.Submit(func(ctx context.Context) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
	}

	if err := pool.Wait(); err != nil {
		t.Errorf("WorkerPool.Wait() = %v, want nil", err)
	}
	if got := atomic.LoadInt64(&counter); got != 10 {
		t.Errorf("counter = %d, want 10", got)
	}
}

func TestWorkerPoolConcurrencyLimit(t *testing.T) {
	maxWorkers := 2
	pool := NewWorkerPool(context.Background(), maxWorkers)

	var mu sync.Mutex
	running := 0
	peakRunning := 0

	for i := 0; i < 10; i++ {
		pool.Submit(func(ctx context.Context) error {
			mu.Lock()
			running++
			if running > peakRunning {
				peakRunning = running
			}
			mu.Unlock()

			time.Sleep(10 * time.Millisecond)

			mu.Lock()
			running--
			mu.Unlock()
			return nil
		})
	}

	if err := pool.Wait(); err != nil {
		t.Errorf("WorkerPool.Wait() = %v, want nil", err)
	}
	if peakRunning > maxWorkers {
		t.Errorf("peak running = %d, want at most %d", peakRunning, maxWorkers)
	}
}

func TestWorkerPoolErrorPropagation(t *testing.T) {
	pool := NewWorkerPool(context.Background(), 5)
	testErr := errors.New("worker error")

	pool.Submit(func(ctx context.Context) error {
		return testErr
	})
	pool.Submit(func(ctx context.Context) error {
		return nil
	})

	err := pool.Wait()
	if err == nil {
		t.Fatal("WorkerPool.Wait() should return error")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("WorkerPool.Wait() = %v, want %v", err, testErr)
	}
}

func TestWorkerPoolContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewWorkerPool(ctx, 2)

	started := make(chan struct{})
	pool.Submit(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})

	<-started
	cancel()

	err := pool.Wait()
	if err == nil {
		t.Fatal("WorkerPool.Wait() should return error after context cancellation")
	}
}

func TestInitGlobalSemaphore(t *testing.T) {
	// Re-init for testing (normally called once)
	globalSemOnce = sync.Once{}
	InitGlobalSemaphore(10)
	if globalSem == nil {
		t.Fatal("globalSem should be initialized")
	}
}

func TestAcquireReleaseGlobal(t *testing.T) {
	globalSemOnce = sync.Once{}
	InitGlobalSemaphore(2)

	ctx := context.Background()
	if err := AcquireGlobal(ctx); err != nil {
		t.Errorf("AcquireGlobal() = %v, want nil", err)
	}
	ReleaseGlobal()

	if err := AcquireGlobal(ctx); err != nil {
		t.Errorf("AcquireGlobal() after release = %v, want nil", err)
	}
	ReleaseGlobal()
}
