package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

const accountLimit = 8
const accountBucketLimit = 4096
const accountWindow = 15 * time.Minute

type accountBucket struct {
	Failures int       `json:"failures"`
	Pending  int       `json:"pending"`
	Until    time.Time `json:"until"`
	Epoch    string    `json:"epoch"`
}
type accountLimitState struct {
	Version int                      `json:"version"`
	Buckets map[string]accountBucket `json:"buckets"`
}
type accountLimits struct {
	mu    sync.Mutex
	path  string
	state accountLimitState
	now   func() time.Time
}
type accountReservation struct{ key, epoch string }

// Bucket canonicalization deliberately does not change exact-name authentication.
// Keys are pseudonymous hashes, not encrypted or secret account identifiers.
func accountBucketKey(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(norm.NFKC.String(name)))))
	return hex.EncodeToString(sum[:])
}

func openAccountLimits(path string) (*accountLimits, error) {
	l := &accountLimits{path: path, now: time.Now, state: accountLimitState{Version: 1, Buckets: map[string]accountBucket{}}}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, errors.New("无法读取登录限额状态")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &l.state) != nil || l.state.Version != 1 || l.state.Buckets == nil || len(l.state.Buckets) > accountBucketLimit {
		return nil, errors.New("登录限额状态无效，拒绝清空限额启动")
	}
	for k, b := range l.state.Buckets {
		if _, err := hex.DecodeString(k); err != nil || len(k) != 64 || len(b.Epoch) != 64 || b.Failures < 0 || b.Pending < 0 || b.Failures+b.Pending > accountLimit || b.Until.IsZero() {
			return nil, errors.New("登录限额状态无效")
		}
	}
	// Pending reservations survive a crash conservatively until the fixed window
	// expires; they must never silently become free attempts after restart.
	return l, nil
}

// Caller holds l.mu, independently of the Server global mutex. All credentials,
// cookies, IPs and plaintext account names are excluded from this state file.
func (l *accountLimits) persist() error {
	raw, err := json.Marshal(l.state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(l.path), ".login-limits-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, l.path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(l.path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}

func (l *accountLimits) reserve(name string) (accountReservation, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.state.Buckets {
		if !now.Before(b.Until) {
			delete(l.state.Buckets, k)
		}
	}
	k := accountBucketKey(name)
	b, ok := l.state.Buckets[k]
	if b.Failures+b.Pending >= accountLimit {
		return accountReservation{}, true, nil
	}
	if !ok {
		if len(l.state.Buckets) >= accountBucketLimit {
			return accountReservation{}, false, errors.New("登录限额容量已满")
		}
		b = accountBucket{Until: now.Add(accountWindow), Epoch: random()}
	}
	b.Pending++
	l.state.Buckets[k] = b
	// On I/O error retain the conservative reservation and fail closed.
	if err := l.persist(); err != nil {
		return accountReservation{}, false, err
	}
	return accountReservation{k, b.Epoch}, false, nil
}

func (l *accountLimits) finish(r accountReservation, failed, success bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.state.Buckets[r.key]
	if !ok || b.Epoch != r.epoch {
		return nil
	} // Explicit admin reset/expiry owns a new epoch.
	if b.Pending <= 0 {
		return errors.New("登录限额预留状态无效")
	}
	old := b
	b.Pending--
	if failed {
		b.Failures++
	} else if success {
		b.Failures = 0
	}
	if b.Failures+b.Pending == 0 {
		delete(l.state.Buckets, r.key)
	} else {
		l.state.Buckets[r.key] = b
	}
	if err := l.persist(); err != nil {
		l.state.Buckets[r.key] = old
		return err
	}
	return nil
}

func (l *accountLimits) reset(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := accountBucketKey(name)
	old, ok := l.state.Buckets[k]
	delete(l.state.Buckets, k)
	if err := l.persist(); err != nil {
		if ok {
			l.state.Buckets[k] = old
		}
		return err
	}
	return nil
}
