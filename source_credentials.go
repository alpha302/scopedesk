package main

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

type SourceQuota struct {
	Limit     int64      `json:"limit"`
	Remaining int64      `json:"remaining"`
	Used      int64      `json:"used"`
	ResetAt   *time.Time `json:"reset_at,omitempty"`
}
type SourceCredentialMetadata struct {
	Source    string      `json:"source"`
	Enabled   bool        `json:"enabled"`
	Quota     SourceQuota `json:"quota"`
	LastError string      `json:"last_error"`
	UpdatedAt time.Time   `json:"updated_at"`
	KeySet    bool        `json:"key_set"`
}

var sourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func credentialContext(source string) string { return "source_credentials:" + source }

// These internal methods intentionally expose no HTTP endpoint for secret reads.
func (s *Store) putSourceCredential(ctx context.Context, source string, key []byte, enabled bool, quota SourceQuota) error {
	if !sourceNamePattern.MatchString(source) || len(key) == 0 || len(key) > 65536 {
		return errors.New("来源名称或凭据长度无效")
	}
	if quota.Limit < 0 || quota.Remaining < 0 || quota.Used < 0 {
		return errors.New("来源配额无效")
	}
	encrypted, err := s.encrypt(credentialContext(source), key)
	if err != nil {
		return errors.New("来源凭据加密失败")
	}
	raw, err := json.Marshal(quota)
	if err != nil {
		return errors.New("来源配额无效")
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO source_credentials(source,key_encrypted,enabled,quota)VALUES($1,$2,$3,$4)
 ON CONFLICT(source)DO UPDATE SET key_encrypted=excluded.key_encrypted,enabled=excluded.enabled,quota=excluded.quota,last_error='',updated_at=now()`, source, encrypted, enabled, raw)
	if err != nil {
		return errors.New("来源凭据保存失败")
	}
	return nil
}
func (s *Store) sourceCredentialKey(ctx context.Context, source string) ([]byte, error) {
	var encrypted []byte
	var enabled bool
	if err := s.DB.QueryRow(ctx, "SELECT key_encrypted,enabled FROM source_credentials WHERE source=$1", source).Scan(&encrypted, &enabled); err != nil {
		return nil, errors.New("来源凭据不可用")
	}
	if !enabled {
		return nil, errors.New("来源凭据未启用")
	}
	key, err := s.decrypt(credentialContext(source), encrypted)
	if err != nil {
		return nil, errors.New("来源凭据解密失败")
	}
	return key, nil
}

// Do not persist upstream error text: providers can echo keys or credential URLs.
func (s *Store) setSourceCredentialFailure(ctx context.Context, source string, failed bool) error {
	message := ""
	if failed {
		message = "来源最近执行失败，请检查配置与配额"
	}
	_, err := s.DB.Exec(ctx, "UPDATE source_credentials SET last_error=$2,updated_at=now()WHERE source=$1", source, message)
	if err != nil {
		return errors.New("来源状态更新失败")
	}
	return nil
}
func (s *Store) sourceCredentialList(ctx context.Context) ([]SourceCredentialMetadata, error) {
	rows, err := s.DB.Query(ctx, "SELECT source,enabled,quota,last_error<>'',updated_at,octet_length(key_encrypted)>0 FROM source_credentials ORDER BY source")
	if err != nil {
		return nil, errors.New("来源配置读取失败")
	}
	defer rows.Close()
	out := []SourceCredentialMetadata{}
	for rows.Next() {
		var m SourceCredentialMetadata
		var raw []byte
		var failed bool
		if err = rows.Scan(&m.Source, &m.Enabled, &raw, &failed, &m.UpdatedAt, &m.KeySet); err != nil {
			return nil, errors.New("来源配置读取失败")
		}
		// Explicit typed projection also excludes unknown metadata fields from output.
		if err = json.Unmarshal(raw, &m.Quota); err != nil {
			return nil, errors.New("来源配额格式无效")
		}
		if failed {
			m.LastError = "来源最近执行失败，请检查配置与配额"
		}
		out = append(out, m)
	}
	if rows.Err() != nil {
		return nil, errors.New("来源配置读取失败")
	}
	return out, nil
}
