# W26：独立 DNS 响应证据发布

2026-11-03（Asia/Shanghai），`batch-p0-p1`。本轮完成独立 DNS 结果、持久化、前端说明、定向复现及发布；没有新增以 DNS 负面结果修改 HTTP 存活状态的阈值。

## 产品效果与语义

资产详情新增“DNS 最近观测”，展示状态及取得时间。历史资产显示尚未取得独立证据，不推测或回填。原 IP/CNAME、`dns_at`、`is_alive`、`miss_count` 和 HTTP 事件字段含义保持。

- `nxdomain_pending`：同一原始主机的 A、AAAA 都取得明确 RCODE 3，且无 NOERROR/别名/错误冲突；显示“域名不存在，待复核”。这是已配置递归解析器的响应证据，不宣称权威 DNSSEC 证明或已确认站点下线。
- `nodata`：A/AAAA 均 NOERROR、无相应地址/别名；与 NXDOMAIN 区分。
- `servfail`、`refused`、`timeout`：保留失败类别，不当作域名不存在。
- `answer`：取得地址记录；A 无记录而 AAAA 有地址仍为有效结果。
- `unknown`：别名终点 NXDOMAIN、冲突、截断但无有效终答、仅单一类型负面、缺少 wire 证据或证据达到上限，均保守保持未知。系统 hosts 文件产生的结果也可能无 wire 证据。

不依据 `DNSError.IsNotFound` 或错误文本猜测 NXDOMAIN。单次负面结果不清除原 IP/CNAME 或 HTTP 存活事实，不产生 HTTP `ASSET_DOWN`/`ASSET_BACK`。真实解析恢复只更新 DNS 状态；HTTP 恢复仍要求实际响应。第三方 `evidence_only` 输入不能覆盖真实 DNS 观测。

## 文件

- 新增 `dns_evidence.go`：对现有 Resolver 流量记录请求/响应 ID、问题名/类型、RCODE、地址答案数、截断和别名标记。保留 UDP PacketConn 接口与 TCP 长度分帧，不改变实际连接地址；匹配请求身份后才接纳响应。每次解析至多保存 64 个摘要，超出时保持 unknown，不记录原始包、凭据或完整响应载荷。
- `pipeline.go`：增加内部带证据解析结果，Probe 保存首次解析阶段的独立观测。原 `dns()` 调用接口保持兼容。记录现有调用，不增加第二次验证查询或收费操作；不承诺每次实际报文数恒定。启用 Go Resolver 以观测 wire，保留配置的 Dial/StrictErrors，不复制 Resolver 内部锁。固定 IP 和减少重复解析的 W28 未实施。
- `services.go`、`results.go`：仅内部确认的实测结果写入 `dns_observation`，与分组/旧服务字段合并兼容。提交仍复核当前授权/租约。未将时间变化强行加入原快照键；本项保存资产最新 DNS 证据，不提供逐包无限历史。
- 新增迁移 `00017_dns_observation.sql`：仅新增 nullable JSONB 列和 32KiB 对象约束；历史为 NULL，不改旧迁移。
- `web/app.js`、`web/index.html`：状态中文说明及资产详情展示，明确单次负面结果不代表 HTTP 下线。
- 新增 `w26_dns_test.go`、`.github/workflows/w26-dns.yml`；修正 `event_dedupe_test.go` 的 v15→v16 专项测试，明确用 `UpToContext(...,16)`，而非把“升级到最新”硬断言为 16。
- 新增 `deploy/deploy_w26_20261103.py`：恢复演练 16→17、历史 NULL 检查、源码/二进制校验、备份、切换及回退。回退只恢复旧源码/二进制，保留向后兼容的新 nullable 列，不自动 down 迁移或删除用户数据。

## 测试证据

红色源码 `e1a1cfb4575dad205b9710c7983bad0166ff0599`（记录连接的 helper 尚未接入产品）；[41572756566](https://github.com/alpha302/scopedesk/actions/runs/41572756566) 的 4 个协议子例及父测试共 **5 FAIL、0 PASS、0 SKIP**，证明现有 Probe 无独立 wire DNS 证据。制品 `evidence/w26-red-41572756566/`。

产品源码 `0f8d16b6fe72311cf3a9a268183d12ffb90aa1c9`，初次 [41573003530](https://github.com/alpha302/scopedesk/actions/runs/41573003530) 12 个 W26 结果通过、25 个回归通过；补充 TCP/响应身份的测试源码 `6c521706417d3aa243849afa611257991eb83143`，最终 [41573171834](https://github.com/alpha302/scopedesk/actions/runs/41573171834)：

- **13 PASS、0 FAIL、0 SKIP**（父测试/子例均计数），race 通过。覆盖 NXDOMAIN/NODATA/SERVFAIL/REFUSED、timeout、A 空/AAAA 有、CNAME→负面、解析波动恢复、UDP/TCP 分帧、冲突/截断/不同问题名与 ID、PG 持久化、第三方不能覆盖，以及不改变已有 HTTP 状态/事件。
- **25 个相关回归结果 PASS、0 FAIL、0 SKIP**，race 通过；含 W04、旧 DNS 负面用例、私网 DNS 零 HTTP、重定向、证书部分页、证据隔离、ScopeGuard、预算、队列租约和写入等指定范围。
- 所有 DNS/HTTP fixture 在本机受控监听或内存传输器中执行，PG16 使用临时 CI 库/独立 schema，100% 合成数据，未调用供应商或真实目标。

W01 首次运行 [41573003499](https://github.com/alpha302/scopedesk/actions/runs/41573003499) 因旧测试把最新迁移版本硬编码为 16 而失败（6 PASS/1 FAIL）；改为仅升级到其命名要求的版本 16 后，[41573401663](https://github.com/alpha302/scopedesk/actions/runs/41573401663) **7 个 W01 PASS、11 个相关回归 PASS、0 FAIL/SKIP**。没有修改旧迁移来让版本断言通过。红绿制品均保留。

原始 JSONL、源码摘要、校验清单位于 `evidence/w26-*/`。未执行全历史回归或生产压测，不作性能结论。补充测试提交不改运行文件，实际发布固定到上述产品源码。

## 生产

**2026-11-03 11:40:06 完成发布**。正式目录 `/opt/scopedesk-go/`；演练 `/opt/scopedesk-w26-integration-20261103/`。安装/核对 84 个运行文件，测试源码和 CI 未复制到生产目录。

- PostgreSQL 16 迁移版本 **16→17**；临时生产快照恢复演练通过，原核心表计数一致；迁移后历史 DNS 列均为 NULL，没有伪造观测。
- 运行二进制 SHA-256：`df564631687ee2949d87c901213905e63290580efaa6f0a90e34dcfd42638c43`，与演练构建及实际进程一致。
- 首页 200、未登录受保护设置 401，新 DNS 页面模板已经由代理提供；这不等同于登录后浏览器验收。
- 配置和监控计划内容不变；没有提高速率上限，没有修改 ScopeGuard、黑名单、预算或租约；生产测试目标请求 0。
- 备份 `/var/backups/scopedesk/before-w26-v17-20261103-033959/`（root 保护目录）；脱敏部署记录、演练结果和无网络认证 fixture 在 `evidence/production-w26-20261103/`。未在生产制造 DNS 故障或触发测试采集。

服务重启使内存会话失效，需重新登录。未实现 W28 固定 IP、W09 完整别名链合同或 W38 持久会话；不能由本项通过推定这些完成。
