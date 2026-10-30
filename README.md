# ScopeDesk v0.3 · 持续资产监控与插件框架

Go + Vue 3 / PostgreSQL 16。公网入口 **http://47.103.214.77:8080/**；原账号不变。浏览器缓存旧页面时请强制刷新并重新登录。

包含第一阶段平台、E1-a 可配置设备规则、E2 发现数据模型/多服务兼容层，以及 E3 manifest 插件框架。E1-b～E1-f 尚未实施；商业 API、主动端口扫描、网页截图、漏洞插件、云节点管理尚未启用。具体交付与测试见 E1-a-delivery.md、E2-delivery.md、E3-delivery.md。

## 使用顺序

1. 在“授权与计划”登记明确的域名、授权粒度和排除项。默认仅单个域名；`*.example.com` 仅包含子域，不包含根域。
2. 被动采集源可选 crt.sh、CertSpotter、subfinder。subfinder 只用于明确授权子域的范围。基础 DNS 查询默认进行；主动 HTTP 探测须按范围单独勾选，并遵守上海时区的允许窗口。
3. 保存每 6/12/24 小时或 5 位 cron 的计划，或手动立即执行。开启计划后按下次执行时间运行，未开启不会自动扫描。新安装未自动添加目标或启用计划。
4. 在资产页搜索、筛选、按页查看和导出 CSV/XLSX；批量设置新发现/待测试/测试中/已测试/忽略、标签、备注、负责人。空白批量备注等字段保持原值。
5. 在“邮件通知”填写 SMTP、发件人与授权收件人，保存后测试发送。预览摘要不发送；每日时间默认 09:00 Asia/Shanghai。未填写 SMTP 和收件人时不会发送真实邮件。

## 授权与网络边界

- 黑名单 > 排除列表 > 授权范围。全局黑名单裸域名包括所有子域；范围排除中的裸域名只排除此主机，通配符排除其子域。
- ScopeGuard 支持 IDNA/punycode、URL 主机归一化、域名边界、IP/CIDR 排除、授权过期；处理插件输出、DNS、HTTP 与入库时重新校验。
- 主动连接拒绝私有、回环、链路本地、保留 IP。HTTP 使用已验证 IP 进行连接；重定向重新校验域名、端口、协议与授权，不使用不可信的代理环境变量。
- CNAME 超出授权范围时保留别名信息，不继续解析或连接该第三方名称。因此部分 CDN 资产只有别名而没有 IP/HTTP 画像，这是范围保护的预期结果。
- 第一阶段主动 HTTP 只使用 80/443；设备规则只做标记，资产和 favicon 采集保留，不进行深度扫描。
- 全局平台上限 5 RPS，范围 0.1–5 RPS，采用 PostgreSQL 槽位跨 worker 协调。请求预算计入平台自身的 DNS、源请求和 HTTP；subfinder 的内部供应商请求只能使用其自身 `-rl` 限速，不能声称逐个计入平台精确预算。外部工具应优先使用不低于 1 RPS 的配置，其有效工具速率为整数。
- 外部程序固定在 `/opt/scopedesk-tools`，参数数组执行，无 shell 拼接；使用 prlimit、超时、输出限制和服务 cgroup 限制。

## 任务、事件与邮件语义

任务在 PostgreSQL，领取使用 SKIP LOCKED；45 秒租约、10 秒续期。租约失效的任务可接管，旧 worker 不能提交。每个范围同时至多一个未结束任务；来源最多尝试 3 次，任务失败指数退避重试，最长运行 15 分钟。接口支持取消。

证书源返回不等于服务存活。所有源成功且结果处理完整时才累计被动缺失；连续 3 次才生成 ASSET_DOWN，明确说明为“连续未发现”，不声称网站已下线。部分失败、预算耗尽或任务取消不累计缺失。支持 NEW_ASSET、ASSET_BACK、IP_CHANGED，按资产与事件内容、上海自然日去重。变化才写快照，事件和快照按月分区。

单次结果受预算与时限约束，大范围可能仅处理部分画像；执行记录显示 `complete=false`，不对未处理资产做缺失判断。可缩小范围、选择单来源或合理调整预算。来源接口的超时、限流和订阅限制会影响覆盖率。

SMTP 仅支持验证证书的 TLS/STARTTLS。配置使用 AES-GCM 加密，主密钥由环境提供，读取接口只返回“已设置”，密码留空不修改。摘要包含新增最多 50 条、变化、任务失败、到期提醒及工作台链接；无变化可跳过。同一日期与范围组合有幂等键。失败最多重试 3 次；SMTP DATA 最终应答不确定或保留发送状态时需人工核对，不自动重发，避免重复投递。SMTP 在接收邮件后崩溃无法保证理论上的 exactly-once。

8080 为用户要求的 HTTP 入口，没有 TLS 传输加密。配置 SMTP 授权码可使用 SSH 隧道：

```powershell
ssh -N -L 18765:127.0.0.1:18765 root@47.103.214.77
```

随后访问 http://127.0.0.1:18765 。原域名 HTTPS 路由保留，但外网曾遇到阿里云备案拦截。

## 部署与备份

- 程序：`/opt/scopedesk-go/scopedesk`，systemd 服务 `scopedesk`，用户 `scopedesk`。
- 数据库：Docker Compose `deploy/compose.yaml`，PostgreSQL 16，仅回环端口 15432，独立卷 `/var/lib/scopedesk-postgres`，384 MB 容器上限。
- 环境：`/etc/scopedesk/app.env`、`database.env`（root 600）；含数据库连接和 Base64 AES 主密钥。不要提交到 Git 或在聊天中粘贴。
- 用户数据由旧 JSON 一次性幂等迁移入 PostgreSQL，之后以 PostgreSQL 为准；旧 JSON 仅留作初始迁移/回滚依据。
- 备份：每天上海时区 03:15 执行 `pg_dump`，保存到 root 700 的 `/var/backups/scopedesk`。同时保留环境配置备份以恢复 AES 密钥。旧二进制及 JSON 位于 `before-v2-*` 目录。
- 备份当前不自动删除，须监控磁盘。安装后剩余约 9 GB，不足以容纳预期 10 GB 数据库及备份，扩大资产规模前需扩容。
- 快照/事件自动按月建分区；自动保留策略属后续阶段，当前不删除历史分区。

```bash
systemctl status scopedesk
docker compose -f /opt/scopedesk-go/deploy/compose.yaml ps
journalctl -u scopedesk -n 50
systemctl list-timers scopedesk-backup.timer
python3 /opt/scopedesk-go/deploy/backup.py
```

恢复需先停止服务、保护当前数据库，然后将备份导入 PostgreSQL，并恢复匹配的主密钥。不要仅恢复加密设置而遗漏主密钥。退回 v0.1 只能恢复切换前 JSON，不能保留之后新增的数据库数据。

## 构建与验证

需要 Go 1.26+、PostgreSQL 14+，当前服务器 Go 1.27.1 / PostgreSQL 16。Vue 本地托管，无运行时 CDN。依赖版本固定在 go.mod/go.sum。

```bash
go test -race -v ./...
go vet ./...
go build -o scopedesk .
```

数据库集成测试需要 `DATABASE_URL` 和 `RECON_MASTER_KEY`，每个测试创建并删除独立 `test_*` schema；实际部署中版本表已有时也隔离版本表，避免读取 public 的迁移状态。测试不运行外部目标扫描或真实邮件。

验证包含权限、ScopeGuard、IDNA/CIDR、私有 DNS 与重定向、限速、三 worker 争抢及租约接管、旧 worker 写入隔离、重复结果/事件/快照、部分失败抑制、邮件加密/幂等/不确定投递、导入分拣、工作状态与计划配置。10 万条资产测试的分页/筛选约 148–755 ms（本机测试结果，不是所有硬件与复杂条件下的 SLA）。

插件管理入口位于“SRC 与工具”旁；从 `plugins/*.yaml` 加载 manifest，新增插件默认停用，subfinder 保留启用状态。管理员可编辑声明的默认参数并对自己名下范围运行队列测试；测试只展示解析结果，不写入资产。主动外部插件因缺少逐请求受控出口而拒绝启用。完整规则和新增插件步骤见 E3-delivery.md。

独立 worker 可用同一环境运行 `./scopedesk worker --labels=default`，需要专用标签时使用 `--labels=raw-socket,default`，不读取本地 JSON；队列、任务、输出和限速都在 PostgreSQL。尚未部署多机节点、Redis/NATS 或对象存储服务。


2026-10-28 范围表单简化：已移除依据链接和到期时间输入，范围不再设置到期。兼容字段保留，历史到期值归档并清空；详见 SCOPE-FORM-CHANGE.md。

2026-10-28 E3 审计高优先级修复：监控计划显示调度异常及重试时间；插件测试独立排队，等待超过 10 分钟自动取消；外部插件使用 manifest 超时并仍受任务总时限约束。迁移版本 6，详见 E3-AUDIT-FIXES.md。

2026-10-28 E3 observer 修复：第三方画像单独保存，不推断实时存活；无效字段不丢弃合法域名，失败尝试不写入资产，详情展示插件证据与来源，运行记录保留拒绝字段统计。迁移版本 7，详见 E3-OBSERVER-FIXES.md。

2026-10-28 E3 插件容错与管理：JSONL 允许少量坏行并记录统计，超过 20 行或最终比例超过 10% 则失败；插件配置展示计划引用，未保存修改不能测试，样例改为表格。无数据库迁移，仍为版本 7。详见 E3-PLUGIN-QUALITY-FIXES.md。

2026-10-28 执行策略：迁移 00008 新增作业预算、截止时间和失败分类。作业预算按来源超时、限次尝试、画像与提交预算计算，全局默认 2h（RECON_MAX_JOB_DURATION 可配置）；确定性失败不重试，普通非零退出默认不重试，可由 exec.retry_exit_codes 声明；提交局部重试不重新启动插件。详见 EXECUTION-POLICY-CHANGE.md。本次仅交付源码。
