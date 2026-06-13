package utils

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// GlobalSemaphore is a process-wide bounded concurrency control.
// Call InitGlobalSemaphore once at startup; subsequent calls are no-ops.
var (
	globalSem     *semaphore.Weighted
	globalSemOnce sync.Once
)

// InitGlobalSemaphore initializes the global semaphore with the given weight.
// Safe to call multiple times — only the first call takes effect.
func InitGlobalSemaphore(weight int64) {
	globalSemOnce.Do(func() {
		if weight <= 0 {
			weight = 25 // safe fallback
		}
		globalSem = semaphore.NewWeighted(weight)
	})
}

// AcquireGlobal blocks until one unit of global concurrency is available.
func AcquireGlobal(ctx context.Context) error {
	if globalSem == nil {
		InitGlobalSemaphore(25)
	}
	return globalSem.Acquire(ctx, 1)
}

// ReleaseGlobal releases one unit of global concurrency.
func ReleaseGlobal() {
	if globalSem != nil {
		globalSem.Release(1)
	}
}

// WorkerPool provides bounded goroutine execution with errgroup.
type WorkerPool struct {
	g     *errgroup.Group
	ctx   context.Context
	sem   *semaphore.Weighted
}

// NewWorkerPool creates a pool bounded by maxWorkers.
// The pool's context is derived from ctx — cancelling ctx cancels all workers.
func NewWorkerPool(ctx context.Context, maxWorkers int) *WorkerPool {
	g, gctx := errgroup.WithContext(ctx)
	if maxWorkers <= 0 {
		maxWorkers = 25
	}
	return &WorkerPool{
		g:   g,
		ctx: gctx,
		sem: semaphore.NewWeighted(int64(maxWorkers)),
	}
}

// Submit queues fn for execution. Blocks if the pool is at capacity.
// Returns immediately if the pool's context is cancelled.
func (wp *WorkerPool) Submit(fn func(ctx context.Context) error) {
	wp.g.Go(func() error {
		if err := wp.sem.Acquire(wp.ctx, 1); err != nil {
			return err
		}
		defer wp.sem.Release(1)
		return fn(wp.ctx)
	})
}

// Wait blocks until all submitted work completes. Returns the first non-nil error.
func (wp *WorkerPool) Wait() error {
	return wp.g.Wait()
}

// --- Existing types preserved for backward compatibility ---

// ConcurrentFileUploader handles concurrent file uploads with rate limiting
type ConcurrentFileUploader struct {
	maxConcurrent int
	semaphore     chan struct{}
}

// NewConcurrentFileUploader creates a new concurrent file uploader.
// If maxConcurrent <= 0, uses global config default.
func NewConcurrentFileUploader(maxConcurrent int) *ConcurrentFileUploader {
	if maxConcurrent <= 0 {
		maxConcurrent = 25 // default aligned with global concurrency
	}
	return &ConcurrentFileUploader{
		maxConcurrent: maxConcurrent,
		semaphore:     make(chan struct{}, maxConcurrent),
	}
}

// UploadResult contains the result of a file upload
type UploadResult struct {
	FilePath string
	Success  bool
	Error    error
}

// UploadFiles uploads multiple files concurrently
func (u *ConcurrentFileUploader) UploadFiles(
	ctx context.Context,
	files []string,
	uploadFunc func(string) error,
) []UploadResult {
	var wg sync.WaitGroup
	results := make([]UploadResult, len(files))

	for i, file := range files {
		wg.Add(1)
		go func(index int, filePath string) {
			defer wg.Done()

			select {
			case u.semaphore <- struct{}{}:
				defer func() { <-u.semaphore }()
			case <-ctx.Done():
				results[index] = UploadResult{
					FilePath: filePath,
					Success:  false,
					Error:    ctx.Err(),
				}
				return
			}

			err := uploadFunc(filePath)
			results[index] = UploadResult{
				FilePath: filePath,
				Success:  err == nil,
				Error:    err,
			}
		}(i, file)
	}

	wg.Wait()
	return results
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

// RetryWithBackoff retries a function with exponential backoff
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt == config.MaxAttempts {
			break
		}

		GetLogger().WithError(err).Warnf("[RETRY] attempt %d/%d failed, retrying in %v",
			attempt, config.MaxAttempts, delay)

		select {
		case <-time.After(delay):
			delay = time.Duration(float64(delay) * config.Multiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", config.MaxAttempts, lastErr)
}
