# P0 复现与基线执行记录

开始：2026-10-30（Asia/Shanghai）。状态：**实施中，P0 未退出；P1–P9 未实施。**

依据：`ScopeDesk-分批实施计划-20261030.md` 第 8–10 节。原计划不是完成证据。本批只新增测试、CI 和契约，不修改生产业务代码、旧迁移或 API 字段含义。

## 核对结果

- 本地工作目录为 `recon-go/`；它原先属于父目录的空 Git 仓库，无提交、无 remote，全部文件未跟踪。不能把当前源码对应到某个已知历史 Git commit。
- 已在 `recon-go/.git/` 初始化独立源码仓库，使用 `codex/scopedesk-p0-baseline-20261030` 分支。首个提交 `2871042` 为原有业务源码/测试/嵌入资源快照（迁移至 15），P0 测试为后续独立提交 `f7329c1`。父级空仓库不含本项目历史。已推送至用户指定的 [alpha302/scopedesk](https://github.com/alpha302/scopedesk/tree/codex/scopedesk-p0-baseline-20261030)；仓库原本为空，首次推送自动以该分支作为默认分支，未覆盖已有 main。
- 本地有 00001–00015 共 15 个迁移。未改旧迁移，未新增业务迁移。
- `PRODUCTION-PASSIVE-DEPLOYMENT-20261029.md` 记载生产由 v9 到 v15，正式目录 `/opt/scopedesk-go/`；隔离目录不是生产。**本轮未连接生产，当前运行版本、数据库版本、来源账户数及健康状态未在线核实。**
- 历史记录仅证明当时的定向测试、构建及迁移/就绪检查；不证明完整回归或登录后浏览器验收。
- 本机有 Go 1.26.0 和现有 GitHub CLI 登录；无 Docker/psql，WSL 未安装。本轮不安装/部署本地服务。
- 全部历史与新增测试源码已在 Windows 主机上以 linux/amd64 目标交叉编译通过。随后在 GitHub Linux/PG16 上完成下述定向测试；没有执行完整历史回归或登录后浏览器验收。JSON 与 workflow YAML 语法已检查。
- 源码提交采用允许列表，排除历史压缩包、运行日志、本机配置及部署脚本；这些原文件仍在本地。候选源码未发现 GitHub token/私钥块/带口令 PG URL 的常见模式，但该静态检查不证明不存在其他格式的秘密。未使用聊天 Token。

## 安全边界（现在固定）

测试不启动应用 server、worker、scheduler，不连接真实目标，不调用真实供应商，不导入聊天密钥，不执行生产迁移/部署。数据库仅允许显式 `P0_ISOLATED=ephemeral-ci`、localhost/127.0.0.1、数据库名 `scopedesk_p0` 的临时 PG16 实例；每例另建随机 schema 并清理。不要在已有业务库用这个名称绕过环境边界。

测试仍使用现有 ScopeGuard、黑名单、平台/项目/范围限速和预算代码；不增加默认速率。文档网段只作为合成资产证据入库，不用于探测。后续固定 IP 也不替代每次实际请求前的最新授权复核。无法确认租约时不能外发；撤销/预算/范围测试必须零漏放。NXDOMAIN 必须有独立可解释证据，`DNSError.IsNotFound` 不足以区分 NXDOMAIN/NODATA，单次负面结果不能判 HTTP 下线。

## 可重复数据集 v1

固定时间锚 `2026-10-30T00:00:00Z`；固定算术分配，无随机目标数据。先 1k、后 10k，各运行均匀和单范围恰占 90% 两种分布。每组 20 范围、4 项目、每资产 2 条 TCP 服务（80/443）、候选数等于资产数。10k 组因此有 20k 服务、10k 候选。

5% 双栈（同时属于多 IP）、另外 15% 多 IPv4；10% 长中文标题；1% 宽合成 JSON 证据；按三类循环分配 crtsh、certspotter、manual+hunter 历史来源；20% CDN 标记；25% 尚未画像。每范围 30 天完成任务历史，按任务奇偶分别记录来源完整/部分状态；每资产一个事件和快照，日期分布覆盖 30 天。所有比例为**合成假设，未声称来自生产统计**。

当前事件/快照是 30 天分布而不是每资产每天一行，不代表高频历史写入负载；后续写路径基线须补高重复事件、多次 IP 轮转、宽 detail 和保留跨度。50k 可选，1m 和 24h 稳态不属于 P0 必须条件。

## 执行及证据

独立源码仓库根目录使用 `.github/workflows/p0-baseline.yml`。GitHub 分支推送/手动触发后，由临时 Linux runner 和 PG16 service 执行。临时密钥在 runner 现场生成并屏蔽，不使用生产 secret。

`go test -run '^TestP0'` 采集每组 3 轮的原始耗时、pgx QueryTracer 观测到的 SQL 往返、响应字节；实际调用资产/概览 handler 和 `Store.scopes()`。范围数另测 0/1/100/1000。EXPLAIN 使用当前资产首屏 SQL 的副本，保留权限谓词和完整 JSON payload，记录 ANALYZE/BUFFERS/SETTINGS；后续改 handler 时必须同步核对 SQL，不能用简化查询代替实际路径。

制品记录 commit、迁移/测试摘要、Go/CPU/内存和 PG 参数。当前每组只收集首屏 EXPLAIN，深页/score/范围计数/概览 EXPLAIN 仍需补齐。三轮是基础重复性样本，**不计算或宣称 p95/p99**，也不据此做性能改善结论。HTTP handler 在进程内调用，不含 TCP/TLS/Caddy/浏览器和真实并发成本。

`TestP0Characterize*` 和 `TestP0LongEventKey` 是旧行为复现：通过表示旧问题仍可观测，并非修复验收通过。W01/W02/W05 修复后须替换相应旧预期。

### 2026-10-30 首次实跑

[Actions run 41025367560](https://github.com/alpha302/scopedesk/actions/runs/41025367560) 成功，测试 commit 为 `f7329c11478ec26eb2bc547ec354df3a90370b4f`。原始制品归档在 `evidence/run-41025367560/`，不是运行于生产的数据。环境为 GitHub ubuntu-24.04 runner、Go 1.26.0、PostgreSQL 16.15；数据库参数和 CPU/内存快照见制品。未设置容器 CPU/内存硬上限，不能把这次 runner 耗时作为生产容量。该次未保存容器镜像 digest，后续严格同条件比较需补齐镜像标识。

- 历史测试源码编译通过；7 项指定离线安全测试通过，零跳过。这仅覆盖 workflow 列出的范围/预算/私网 DNS/被动来源等用例。
- 5 个 P0 顶层测试及其 8 个数据子用例全部通过，零跳过；含 1k/10k × 均匀/90% 倾斜、0/1/100/1000 范围，各 3 轮读取计量。
- W01 已在 PG16 复现：64KiB 合成 detail 导致去重键写入 SQLSTATE 54000，测试事务回滚；不是已修复。
- W02 已复现分类器接受 4 个嵌入私网/回环 IPv4 的 NAT64/6to4 样例。尚未验证其实际路由/拨号效果。
- W05 已复现 contest/capital 子串误报。NXDOMAIN/CDN/来源限定缺失仍没有新增端到端复现。
- W30 的实际 SQL 往返：0/1/100/1000 范围分别为 1/2/101/1001 次，三轮一致，证明该代码路径存在逐范围 plan 查询。资产列表各测试路径为 2 次、概览为 3 次、20 范围列表为 21 次；不能把资产列表内部服务聚合叫做应用级 N+1。
- 两种 10k 分布均核对 10k 资产/20k 服务，首屏 EXPLAIN 实际输出 50 行，原始 plans/loops/buffers 已留存。没有前后优化对照，不做速度提升、并发容量、p95/p99 或 SLO 达标结论。

## 完整 B16 复现台账

1. 默认来源完整性 → W04：`collectors.go` crtsh 返回 incomplete_source；已有完整性 fixture，待运行及状态解释合同。
2. 单来源缺失误伤 → W04/W10：`results.go` complete 分支按全范围未 seen 资产增 miss_count；来源×历史资产复现矩阵待补。
3. NXDOMAIN → W26：`pipeline.go` 无独立 RCODE 证据；可控权威 DNS 的 NXDOMAIN/NODATA/SERVFAIL 真值表待补。
4. CDN IP 变化/长键 → W27/W01：`results.go` 不区分 CDN 比较 IP 列表，detail 十六进制拼入键；64KiB 事件索引键失败已在 PG16 复现；CDN 事件量对照待补。
5. 分类 → W05：`pipeline.go:categoryScore` 使用 Contains；contest/capital 误报已复现。
6. 画像饥饿 → W06：`queue.go` 字母序主机列表顺序 Probe；有限预算的等待上界复现待补。
7. 重复解析/串行 → W28/W08：`pipeline.go` 初次 DNS 与 DialContext 再解析，`queue.go` 顺序 Probe；逐请求 DNS/HTTP/PG 计量 fixture 待补，不能假定固定次数。
8. PG 限速往返/占槽 → W29：`guard.go:PGRateLimiter.Wait`；保持原速率的 1/2/10/50 worker 时间序列待测。
9. 巨型事务/HOT → W10：`results.go` WriteResults 单事务；WAL/HOT/锁等待和心跳争用待测，尚无写放大结论。
10. 列表/范围/轮询 → W11/W30/W31：资产单 SQL 相关服务聚合与 scopes 逐项 plan 是不同问题；已完成读取计量、首屏 EXPLAIN 和原始耗时采集；多用户 10 秒轮询混合负载待补。
11. 小项 → W32/W03/W33/W34/W35/W36：前缀每次解析、全局锁内哈希、统一 no-store、unsafe-eval、同步导出、每 worker 每秒领取的源码路径存在；相关资源/互斥锁/浏览器/导出/idle 测量待补。
12. 历史/循环日志 → W12/W39：每主机操作日志写入与历史增长影响待测，保留/保护窗口待定，不执行清理。
13. 心跳失败 → W07：`queue.go` 单次错误即取消；短断连/池耗尽/租约接管故障注入待补。
14. 分区维护 → W13：`queue.go:scheduleTick` 末调用 ensurePartitions；10 秒周期/多实例 DDL 计量待补。
15. 登录/会话 → W37/W38：`main.go:login` attempts 仅按 IP、session 内存映射；分布 IP/重启/跨实例撤销待复现，未声称已支持持久会话。
16. IPv6 → W02：NAT64/6to4 嵌入回环/私网的 publicIP 分类已复现；受控实际路由/拨号待验，分类接受不等于实际已可达或已越权。

## SLO 与退出闸门

指标定义见 `contract.json`。安全零容忍门槛已固定；性能数值阈值全部为 null（待验/待签），不得用建议数字假装已签定。性能统计须明确单位、分位数、测量窗口、角色/项目、混合负载、样本量及资源配置；至少三轮同条件对照。后续增加足够请求样本后才给 p95/p99。

从 2026-10-30 开始，最迟两周日历期结束（2026-11-13），或第 10 个实际工作日，以先到者为准，冻结有证据的阈值；未取得样本者留待验并指定后续批次日期。当前这不是已签定的性能 SLO。

P0 仍欠：写入/登录/idle/请求计量与并发混合负载；DNS/CDN/来源真值表；范围和概览完整 EXPLAIN；安全故障矩阵；固定镜像和资源约束后的同条件对照；SLO 数值签定。全部具备后才能关闭 P0，再进入 P1。39 项 W 工单仍保持开放，不能因本文或 CI 成功而关闭。
