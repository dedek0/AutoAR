package utils

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// ShutdownManager handles the lifecycle of the application during a termination event.
// It tracks active scans, manages child process cleanup, and ensures they complete
// (or timeout) before the process exits.
type ShutdownManager struct {
	mu              sync.RWMutex
	shutdownFlag    bool
	activeScans     int
	shutdownTimeout time.Duration
	logger          *logrus.Logger
	onShutdown      []func() error
	childPIDs       map[int32]bool
	childMu         sync.Mutex
}

var (
	// GlobalShutdownManager is the global shutdown manager
	GlobalShutdownManager *ShutdownManager
	shutdownOnce          sync.Once
)

// InitShutdownManager initializes the global singleton [ShutdownManager] instance.
func InitShutdownManager(timeout time.Duration, logger *logrus.Logger) *ShutdownManager {
	shutdownOnce.Do(func() {
		if timeout == 0 {
			timeout = 5 * time.Minute // Default 5 minutes
		}
		GlobalShutdownManager = &ShutdownManager{
			shutdownTimeout: timeout,
			logger:          logger,
			onShutdown:      make([]func() error, 0),
			childPIDs:       make(map[int32]bool),
		}
	})
	return GlobalShutdownManager
}

// GetShutdownManager returns the global singleton [ShutdownManager] instance.
func GetShutdownManager() *ShutdownManager {
	if GlobalShutdownManager == nil {
		return InitShutdownManager(5*time.Minute, GetLogger())
	}
	return GlobalShutdownManager
}

// RegisterChildProcess registers a child process PID for cleanup on shutdown.
func (sm *ShutdownManager) RegisterChildProcess(pid int32) {
	sm.childMu.Lock()
	sm.childPIDs[pid] = true
	sm.childMu.Unlock()
}

// UnregisterChildProcess removes a child process PID from the tracking list.
func (sm *ShutdownManager) UnregisterChildProcess(pid int32) {
	sm.childMu.Lock()
	delete(sm.childPIDs, pid)
	sm.childMu.Unlock()
}

// KillChildProcesses sends SIGTERM to all tracked child processes.
// After a 5-second grace period, remaining processes receive SIGKILL.
func (sm *ShutdownManager) KillChildProcesses() {
	sm.childMu.Lock()
	pids := make([]int32, 0, len(sm.childPIDs))
	for pid := range sm.childPIDs {
		pids = append(pids, pid)
	}
	sm.childPIDs = make(map[int32]bool)
	sm.childMu.Unlock()

	if len(pids) == 0 {
		return
	}

	if sm.logger != nil {
		sm.logger.Infof("Sending SIGTERM to %d child process(es)", len(pids))
	}

	for _, pid := range pids {
		if proc, err := os.FindProcess(int(pid)); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}

	// Grace period then SIGKILL
	time.Sleep(5 * time.Second)

	sm.childMu.Lock()
	remaining := make([]int32, 0)
	for _, pid := range pids {
		if proc, err := os.FindProcess(int(pid)); err == nil {
			remaining = append(remaining, pid)
			_ = proc.Signal(syscall.SIGKILL)
		}
	}
	sm.childMu.Unlock()

	if len(remaining) > 0 && sm.logger != nil {
		sm.logger.Warnf("Force-killed %d zombie child process(es)", len(remaining))
	}
}

// RegisterShutdownHook registers a function to be executed during the shutdown sequence.
func (sm *ShutdownManager) RegisterShutdownHook(fn func() error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onShutdown = append(sm.onShutdown, fn)
}

// IsShuttingDown returns true if the shutdown process has been initiated.
func (sm *ShutdownManager) IsShuttingDown() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.shutdownFlag
}

// IncrementActiveScans increments the active scan counter
func (sm *ShutdownManager) IncrementActiveScans() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.activeScans++
}

// DecrementActiveScans decrements the active scan counter
func (sm *ShutdownManager) DecrementActiveScans() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.activeScans > 0 {
		sm.activeScans--
	}
}

// GetActiveScans returns the number of active scans
func (sm *ShutdownManager) GetActiveScans() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeScans
}

// Shutdown initiates graceful shutdown
func (sm *ShutdownManager) Shutdown(ctx context.Context) error {
	sm.mu.Lock()
	sm.shutdownFlag = true
	activeScans := sm.activeScans
	sm.mu.Unlock()

	if sm.logger != nil {
		sm.logger.WithFields(logrus.Fields{
			"active_scans": activeScans,
			"timeout":      sm.shutdownTimeout,
		}).Info("Initiating graceful shutdown")
	}

	// Wait for active scans to complete or timeout
	if activeScans > 0 {
		if sm.logger != nil {
			sm.logger.Infof("Waiting for %d active scan(s) to complete...", activeScans)
		}

		shutdownCtx, cancel := context.WithTimeout(ctx, sm.shutdownTimeout)
		defer cancel()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-shutdownCtx.Done():
				remaining := sm.GetActiveScans()
				if sm.logger != nil {
					sm.logger.Warnf("Shutdown timeout reached, %d scan(s) still active", remaining)
				}
				goto cleanup
			case <-ticker.C:
				if sm.GetActiveScans() == 0 {
					if sm.logger != nil {
						sm.logger.Info("All active scans completed")
					}
					goto cleanup
				}
			}
		}
	}

cleanup:
	// Kill any remaining child processes (zombie prevention)
	sm.KillChildProcesses()

	// Execute shutdown hooks
	sm.mu.RLock()
	hooks := sm.onShutdown
	sm.mu.RUnlock()

	for _, hook := range hooks {
		if err := hook(); err != nil {
			if sm.logger != nil {
				sm.logger.WithError(err).Error("Shutdown hook failed")
			}
		}
	}

	if sm.logger != nil {
		sm.logger.Info("Graceful shutdown complete")
	}

	return nil
}

// WaitForShutdownSignal blocks until SIGTERM or SIGINT is received
func (sm *ShutdownManager) WaitForShutdownSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigChan
	if sm.logger != nil {
		sm.logger.WithField("signal", sig.String()).Info("Received shutdown signal")
	}

	// Initiate shutdown
	ctx := context.Background()
	if err := sm.Shutdown(ctx); err != nil {
		if sm.logger != nil {
			sm.logger.WithError(err).Error("Shutdown failed")
		}
		os.Exit(1)
	}

	os.Exit(0)
}
