package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Mode        string   `json:"mode"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	From        string   `json:"from"`
	Recipients  []string `json:"recipients"`
	Time        string   `json:"time"`
	Enabled     bool     `json:"enabled"`
	SendEmpty   bool     `json:"send_empty"`
	ScopeIDs    []int64  `json:"scope_ids"`
	PasswordSet bool     `json:"password_set"`
}

func defaultSMTP() SMTPConfig {
	return SMTPConfig{Port: 587, Mode: "starttls", Time: "09:00", Recipients: []string{}, ScopeIDs: []int64{}}
}
func (c SMTPConfig) validate() error {
	if strings.ContainsAny(c.Host, "\r\n/: ") || c.Host == "" {
		return errors.New("SMTP 主机应为域名或 IPv4，不含协议和端口")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("SMTP 端口无效")
	}
	if c.Mode != "tls" && c.Mode != "starttls" {
		return errors.New("SMTP 必须使用 TLS 或 STARTTLS")
	}
	if _, e := mail.ParseAddress(c.From); e != nil || strings.ContainsAny(c.From, "\r\n") {
		return errors.New("发件地址无效")
	}
	if len(c.Recipients) == 0 || len(c.Recipients) > 20 {
		return errors.New("收件人须为 1–20 个授权地址")
	}
	for _, r := range c.Recipients {
		if _, e := mail.ParseAddress(r); e != nil || strings.ContainsAny(r, "\r\n") {
			return errors.New("收件地址无效")
		}
	}
	if _, e := time.Parse("15:04", c.Time); e != nil {
		return errors.New("发送时间格式须为 HH:MM")
	}
	return nil
}

type DigestAsset struct {
	Host         string
	IPs          []string
	Status       int
	Title        string
	Fingerprints []string
	Category     string
	Score        int
}
type DigestEvent struct {
	Type   string
	Host   string
	Detail string
}
type Digest struct {
	Date     string
	New      int
	Down     int
	Changed  int
	Assets   []DigestAsset
	Events   []DigestEvent
	Failures []string
	Expiring []string
	URL      string
	More     bool
	HTML     string
}

var digestTemplate = template.Must(template.New("digest").Parse(`<!doctype html><html lang="zh-CN"><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#f4f7f5;font-family:Arial,sans-serif;color:#254237"><div style="max-width:850px;margin:auto;padding:24px"><h1 style="font-size:24px">ScopeDesk 每日资产摘要</h1><p>{{.Date}} · Asia/Shanghai</p><div style="background:white;padding:20px;border-radius:8px"><b>新增 {{.New}}　连续未发现 / 探测未成功 {{.Down}}　其他变化 {{.Changed}}</b><h2 style="font-size:18px">新增资产（最多 50 条）</h2><div style="overflow-x:auto"><table cellpadding="8" style="border-collapse:collapse;width:100%;font-size:12px"><thead><tr><th>域名</th><th>IP</th><th>状态码</th><th>标题 / 指纹</th><th>分类 / 评分</th></tr></thead><tbody>{{range .Assets}}<tr style="border-top:1px solid #e6ece8"><td>{{.Host}}</td><td>{{range .IPs}}{{.}}<br>{{end}}</td><td>{{.Status}}</td><td>{{.Title}}<br>{{range .Fingerprints}}{{.}} {{end}}</td><td>{{.Category}} / {{.Score}}</td></tr>{{else}}<tr><td colspan="5">暂无新增资产</td></tr>{{end}}</tbody></table></div>{{if .More}}<p>结果超过 50 条，请在工作台查看全部。</p>{{end}}<h2 style="font-size:18px">重要变化</h2>{{range .Events}}<p>{{.Type}} · {{.Host}}<br><small>{{.Detail}}</small></p>{{else}}<p>暂无变化</p>{{end}}<h2 style="font-size:18px">任务与数据源提醒</h2>{{range .Failures}}<p>{{.}}</p>{{else}}<p>无失败记录</p>{{end}}<h2 style="font-size:18px">授权即将到期 / 已到期</h2>{{range .Expiring}}<p>{{.}}</p>{{else}}<p>未来 7 天无到期授权</p>{{end}}<p><a href="{{.URL}}">打开工作台查看全部</a></p><small>证书记录缺失不等于服务下线。请在授权范围内研究，邮件不含密钥和登录令牌。</small></div></div></body></html>`))

func (e *Engine) digest(ctx context.Context, c SMTPConfig) (Digest, error) {
	now := time.Now().In(shanghai)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, shanghai)
	d := Digest{Date: start.Format("2006-01-02"), URL: os.Getenv("RECON_PUBLIC_URL"), Assets: []DigestAsset{}, Events: []DigestEvent{}, Failures: []string{}, Expiring: []string{}}
	if d.URL == "" {
		d.URL = "http://47.103.214.77:8080/"
	}
	rows, err := e.Store.DB.Query(ctx, `SELECT type,count(*) FROM asset_events WHERE created_at>=$1 AND (cardinality($2::bigint[])=0 OR scope_id=ANY($2::bigint[]))GROUP BY type`, start, c.ScopeIDs)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var kind string
		var count int
		if rows.Scan(&kind, &count) != nil {
			rows.Close()
			return d, errors.New("摘要统计失败")
		}
		switch kind {
		case "NEW_ASSET":
			d.New = count
		case "ASSET_DOWN":
			d.Down = count
		default:
			d.Changed += count
		}
	}
	rows.Close()
	rows, err = e.Store.DB.Query(ctx, `SELECT host,ips,status_code,title,fingerprints,category,score FROM assets WHERE first_seen>=$1 AND (cardinality($2::bigint[])=0 OR scope_id=ANY($2::bigint[]))ORDER BY score DESC,host LIMIT 51`, start, c.ScopeIDs)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var a DigestAsset
		if err = rows.Scan(&a.Host, &a.IPs, &a.Status, &a.Title, &a.Fingerprints, &a.Category, &a.Score); err != nil {
			rows.Close()
			return d, err
		}
		d.Assets = append(d.Assets, a)
	}
	rows.Close()
	if len(d.Assets) > 50 {
		d.More = true
		d.Assets = d.Assets[:50]
	}
	rows, err = e.Store.DB.Query(ctx, `SELECT ev.type,a.host,ev.detail::text FROM asset_events ev JOIN assets a ON a.id=ev.asset_id WHERE ev.created_at>=$1 AND ev.type!='NEW_ASSET' AND (cardinality($2::bigint[])=0 OR ev.scope_id=ANY($2::bigint[]))ORDER BY ev.created_at DESC LIMIT 50`, start, c.ScopeIDs)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v DigestEvent
		if err = rows.Scan(&v.Type, &v.Host, &v.Detail); err != nil {
			rows.Close()
			return d, err
		}
		d.Events = append(d.Events, v)
	}
	rows.Close()
	rows, err = e.Store.DB.Query(ctx, `SELECT s.domain||': '||CASE WHEN j.error='' THEN '部分数据源失败或结果不完整' ELSE j.error END FROM jobs j JOIN scopes s ON s.id=j.scope_id WHERE j.created_at>=$1 AND (j.status IN('failed','retrying','cancelled') OR j.stats->>'complete'='false') AND (cardinality($2::bigint[])=0 OR j.scope_id=ANY($2::bigint[]))ORDER BY j.id DESC LIMIT 20`, start, c.ScopeIDs)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		d.Failures = append(d.Failures, v)
	}
	rows.Close()
	rows, err = e.Store.DB.Query(ctx, `SELECT domain||' · '||expires_at::text FROM scopes WHERE expires_at<now()+interval '7 days' AND (cardinality($1::bigint[])=0 OR id=ANY($1::bigint[]))ORDER BY expires_at LIMIT 50`, c.ScopeIDs)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		d.Expiring = append(d.Expiring, v)
	}
	rows.Close()
	var out bytes.Buffer
	if err = digestTemplate.Execute(&out, d); err != nil {
		return d, err
	}
	d.HTML = out.String()
	return d, nil
}

type deliveryError struct {
	error
	Uncertain bool
}

func sendSMTP(c SMTPConfig, subject, body string) error {
	if e := c.validate(); e != nil {
		return e
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	tlsConfig := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.Mode == "tls" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return &deliveryError{errors.New("SMTP 连接失败"), false}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return &deliveryError{errors.New("SMTP 握手失败"), false}
	}
	defer client.Close()
	if c.Mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return &deliveryError{errors.New("SMTP 服务不支持 STARTTLS"), false}
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return &deliveryError{errors.New("SMTP TLS 验证失败"), false}
		}
	}
	if c.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return &deliveryError{errors.New("SMTP 认证失败，请检查账号及授权码"), false}
		}
	}
	from, _ := mail.ParseAddress(c.From)
	if err = client.Mail(from.Address); err != nil {
		return &deliveryError{errors.New("SMTP 发件地址被拒绝"), false}
	}
	recipients := []string{}
	for _, r := range c.Recipients {
		parsed, _ := mail.ParseAddress(r)
		recipients = append(recipients, parsed.Address)
		if err = client.Rcpt(parsed.Address); err != nil {
			return &deliveryError{errors.New("SMTP 收件地址被拒绝"), false}
		}
	}
	writer, err := client.Data()
	if err != nil {
		return &deliveryError{errors.New("SMTP 不接受邮件正文"), false}
	}
	header := "From: " + from.String() + "\r\nTo: " + strings.Join(recipients, ", ") + "\r\nSubject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
	if _, err = io.WriteString(writer, header+body); err != nil {
		return &deliveryError{errors.New("邮件正文提交中断，请人工核对是否已送达"), true}
	}
	if err = writer.Close(); err != nil {
		return &deliveryError{errors.New("SMTP 最终应答不确定，请人工核对，系统不会自动重发"), true}
	}
	client.Quit()
	return nil
}
func (e *Engine) sendDigest(ctx context.Context, c SMTPConfig, manual bool) (map[string]any, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	d, err := e.digest(ctx, c)
	if err != nil {
		return nil, err
	}
	if !c.SendEmpty && d.New+d.Down+d.Changed+len(d.Failures)+len(d.Expiring) == 0 {
		return map[string]any{"status": "skipped", "message": "当日无变化，按设置不发送"}, nil
	}
	stable, _ := json.Marshal(c.ScopeIDs)
	sum := sha256.Sum256(stable)
	key := d.Date + ":smtp:" + hex.EncodeToString(sum[:8])
	var status string
	var attempts int
	// Reserve before SMTP. A crash after reservation never causes an automatic duplicate.
	tag, err := e.Store.DB.Exec(ctx, "INSERT INTO digest_logs(idempotency_key,status,recipient_count,attempts)VALUES($1,'sending',$2,1)ON CONFLICT DO NOTHING", key, len(c.Recipients))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		err = e.Store.DB.QueryRow(ctx, "SELECT status,attempts FROM digest_logs WHERE idempotency_key=$1", key).Scan(&status, &attempts)
		if err != nil {
			return nil, err
		}
		if status != "failed" || attempts >= 3 {
			return map[string]any{"status": "duplicate", "message": "本摘要已发送或正在发送 / 待人工核对，已阻止重复发送"}, nil
		}
		tag, err = e.Store.DB.Exec(ctx, "UPDATE digest_logs SET status='sending',attempts=attempts+1,updated_at=now() WHERE idempotency_key=$1 AND status='failed' AND attempts<3 AND (next_attempt_at<=now() OR $2) ", key, manual)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return map[string]any{"status": "waiting", "message": "等待邮件重试时间"}, nil
		}
	}
	sender := e.SendMail
	if sender == nil {
		sender = sendSMTP
	}
	err = sender(c, "ScopeDesk 每日资产摘要 · "+d.Date, d.HTML)
	status = "sent"
	message := ""
	if err != nil {
		status = "failed"
		var delivery *deliveryError
		if errors.As(err, &delivery) && delivery.Uncertain {
			status = "uncertain"
		}
		message = safeError(err)
	}
	_, saveErr := e.Store.DB.Exec(context.Background(), "UPDATE digest_logs SET status=$2,error=$3,updated_at=now(),next_attempt_at=now()+interval '5 minutes' WHERE idempotency_key=$1", key, status, message)
	if saveErr != nil {
		return nil, errors.New("发送结果保存失败，请人工核对，禁止自动重发")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": status, "message": "摘要已提交 SMTP 服务"}, nil
}
func (e *Engine) digestScheduler() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-e.root.Done():
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(e.root, 50*time.Second)
			c := defaultSMTP()
			if e.Store.setting(ctx, "smtp", &c) == nil && c.Enabled {
				now := time.Now().In(shanghai)
				if now.Format("15:04") >= c.Time {
					if _, err := e.sendDigest(ctx, c, false); err != nil { /* SMTP error is persisted with no credential text. */
					}
				}
			}
			cancel()
		}
	}
}

var _ = fmt.Sprintf
