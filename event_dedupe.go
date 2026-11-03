package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// This is a byte limit on the encoded evidence, not on the digest. Legal 64KiB
// evidence plus metadata fits; larger input is explicitly rejected, never cut.
const maxEventDetailBytes = 256 * 1024

var errEventDetailEncoding = errors.New("事件证据无法编码为合法 JSON")
var errEventDetailTooLarge = errors.New("事件证据超过 256 KiB 上限")

func canonicalEventDetail(kind string, raw []byte) ([]byte, error) {
	if len(raw) > maxEventDetailBytes {
		return nil, errEventDetailTooLarge
	}
	if !json.Valid(raw) {
		return nil, errEventDetailEncoding
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // Do not round large integers through float64.
	if d.Decode(&value) != nil {
		return nil, errEventDetailEncoding
	}
	if m, ok := value.(map[string]any); ok {
		// Only these documented fields are sets. Arbitrary evidence arrays keep
		// their order; before/after themselves must never be interchanged.
		fields := []string{}
		if kind == "IP_CHANGED" {
			fields = []string{"before", "after"}
		}
		if kind == "NEW_ASSET" {
			fields = []string{"sources"}
		}
		for _, field := range fields {
			items, ok := m[field].([]any)
			if !ok {
				continue
			}
			values := make([]string, len(items))
			allStrings := true
			for i, item := range items {
				var ok bool
				values[i], ok = item.(string)
				if !ok {
					allStrings = false
					break
				}
			}
			if allStrings {
				slices.Sort(values)
				m[field] = slices.Compact(values)
			}
		}
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errEventDetailEncoding
	}
	return canonical, nil
}

func eventDedupeKey(scope, asset int64, kind string, at time.Time, detail any) (key string, raw, canonical []byte, err error) {
	raw, err = json.Marshal(detail)
	if err != nil {
		return "", nil, nil, errEventDetailEncoding
	}
	canonical, err = canonicalEventDetail(kind, raw)
	if err != nil {
		return "", nil, nil, err
	}
	// Version, scope, asset, type and Shanghai natural day are all part of the
	// identity. A new job replay does not create a new identity on the same day.
	tuple, err := json.Marshal([]any{"scopedesk-event-v2", scope, asset, kind, at.In(shanghai).Format("2006-01-02"), json.RawMessage(canonical)})
	if err != nil {
		return "", nil, nil, errEventDetailEncoding
	}
	sum := sha256.Sum256(tuple)
	return "v2:" + hex.EncodeToString(sum[:]), raw, canonical, nil
}

func addEvent(ctx context.Context, tx pgx.Tx, scope, asset, job int64, kind string, detail any) error {
	return addEventAt(ctx, tx, scope, asset, job, kind, detail, time.Now())
}

func addEventAt(ctx context.Context, tx pgx.Tx, scope, asset, job int64, kind string, detail any, at time.Time) error {
	key, raw, canonical, err := eventDedupeKey(scope, asset, kind, at, detail)
	if err != nil {
		return err
	}
	// The unique ledger entry serializes concurrent upgraded writers. All work
	// stays in the caller's transaction; a rollback releases this reservation.
	tag, err := tx.Exec(ctx, "INSERT INTO event_dedupes(key)VALUES($1)ON CONFLICT DO NOTHING", key)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}

	// Legacy keys are immutable. Compare their decoded evidence rather than
	// rebuilding a single old key, which would miss object/set-order variants.
	// Migration 16 indexes these three lookups without rewriting historical rows.
	rows, err := tx.Query(ctx, `SELECT key FROM event_dedupes WHERE split_part(key,':',1)=$1 AND split_part(key,':',2)=$2 AND split_part(key,':',3)=$3`, strconv.FormatInt(asset, 10), kind, at.In(shanghai).Format("2006-01-02"))
	if err != nil {
		return err
	}
	legacyMatch := false
	for rows.Next() {
		var legacy string
		if err := rows.Scan(&legacy); err != nil {
			rows.Close()
			return err
		}
		parts := strings.SplitN(legacy, ":", 4)
		if len(parts) != 4 {
			rows.Close()
			return errors.New("历史事件去重证据格式无效")
		}
		decoded, err := hex.DecodeString(parts[3])
		if err != nil {
			rows.Close()
			return errors.New("历史事件去重证据格式无效")
		}
		old, err := canonicalEventDetail(kind, decoded)
		if err != nil {
			rows.Close()
			return errors.New("历史事件去重证据格式无效")
		}
		if bytes.Equal(old, canonical) {
			legacyMatch = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if legacyMatch {
		return nil
	}
	// Capture the event timestamp once, so the payload day and dedupe day cannot
	// disagree if the transaction crosses Shanghai midnight.
	_, err = tx.Exec(ctx, `INSERT INTO asset_events(scope_id,asset_id,job_id,type,detail,dedupe_key,created_at)VALUES($1,$2,$3,$4,$5,$6,$7)`, scope, asset, job, kind, raw, key, at)
	return err
}
