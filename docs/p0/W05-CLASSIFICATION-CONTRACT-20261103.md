# W05 分类合同：实现与验证跟踪

2026-11-03，Asia/Shanghai。**本合同已验收并发布，W05 关闭**。生产源码 `19f51a92fc57f5ca64249e802b1175cf197b91fd`、迁移 18。先前边界子项发布记录作为历史证据独立保留。

## 本轮源码

- 新增 `classification.go`：保存 `subdomain-tokens-v2`、自动/人工模式、根域、命中关键词与标签、自动类别、基础/关键词/HTTP 存活三项加分。人工类别只覆盖显示名称，评分保留自动依据，不表示漏洞或归属置信度。
- 新增迁移 `00018_asset_classification.sql`：仅新增 nullable `classification`/`category_override` 及长度约束；历史均为 NULL，保持原 `category`/`score`，不推断旧值来源、不批量回填。
- `results.go`：新资产取得合同；已取得合同者按当前规则和持久 HTTP 状态刷新，人工名称优先。第三方 `evidence_only` 不改变已有分类或评分。历史 NULL 不自动加入新合同；用户显式保存分类或恢复自动分类后才加入。评分中的 HTTP 项遵守既有连续失败门槛，不增加新的下线判断。
- `security_api.go`：单资产和批量 PATCH 新增 `category_override`；非空单行文本（最多 128 UTF-8 字节）为人工覆盖，显式 `null` 为恢复自动，缺省保持原值。权限复用当前项目写权限，批次任何资产无权则整体回滚；排序行锁与画像写入串行，重复同值不增加分类快照。分类变更有操作日志和快照。
- `import.go`：当前手工导入入口对新行创建分类合同，冲突行保留原分类与人工覆盖。
- 资产详情显示来源未知提示、规则版本/命中/加分依据和人工编辑入口；入口按资产所属范围写权限显示。Vue 文本插值保持转义。

首次创建并发问题独立复现：画像任务初次 SELECT 不存在时，并发创建者提交人工分类，旧后置 `INSERT ON CONFLICT` 取得现有 ID 后会使用空旧状态覆盖人工值。修复改为先 `INSERT DO NOTHING RETURNING id` 占行；冲突后重新 `SELECT FOR UPDATE` 读取真实旧值，再推导新状态。没有改变授权、预算、速率或租约。

## 已完成与待完成验证

以下是 Linux 隔离目录 `/opt/scopedesk-w05-fixture-20261103/`、临时 PG16/独立 schema 的定向结果，全部为合成数据，没有真实目标或供应商请求。JSONL 位于 `evidence/w05-contract-20261103/`：

- `red.jsonl`：34 PASS、2 FAIL、0 SKIP。证明缺少分类合同、旧接口不能显式恢复自动分类。
- `attempt-1.jsonl`：35 PASS、1 FAIL、0 SKIP。唯一失败是测试将 JSON `null` 与 SQL NULL 混为一谈；已修正断言，未改产品来满足此断言。
- `green-first.jsonl`：36 PASS、0 FAIL/SKIP。覆盖分类边界、人工覆盖/恢复、旧分类显式加入、HTTP 故障/恢复与第三方证据隔离，并包含 W04/W26/授权及写入回归。
- `concurrent-red.jsonl`：36 PASS、1 FAIL、0 SKIP。精确命中两事务唯一键等待，人工值被覆盖为 `API/<nil>/40`。修复后的 `concurrent-green.jsonl` 已取回：38 PASS、0 FAIL/SKIP。最终 CI 再次覆盖该场景。
- 登录后合成账号页面已手动确认：`api2.example.com` 显示自动 API/40 和规则依据；保存“业务入口”后显示人工优先；恢复后回到 API/40。`contest.example.com` 显示旧分类/77 和历史来源未知，主动恢复后为未分类/10。测试页面监听回环地址，经本机 SSH 转发访问，未启动 worker/scheduler；不代表完整 W25 浏览器验收。

本地只读复核确认首次创建冲突修复闭合，未发现剩余具体产品缺陷。旧写入兼容 fixture 存为 `.go.txt`，避免证据目录被递归 Go 构建误当成独立包。

最终 [Actions 41589146132](https://github.com/alpha302/scopedesk/actions/runs/41589146132) 的测试源码和发布源码均为 `19f51a92fc57f5ca64249e802b1175cf197b91fd`：

- **28 个 W05 结果 PASS、0 FAIL/SKIP**（包含父测试和子例），race 通过。包含新增迁移 17→18、重放/长度约束、并发首次创建冲突、批量整体回滚/重复提交、规则版本刷新、控制字符和 UTF-8 字节限长。
- **21 个相关回归 PASS、0 FAIL/SKIP**，race 通过。涵盖 W04 HTTP/被动状态、W26 DNS 持久化、候选授权边界、租约领取、项目权限、安全设备覆盖、W01 长证据与专项迁移、范围/预算、私网 DNS 和重定向。不是完整历史回归。
- **1 个实际旧写入兼容 PASS、0 FAIL/SKIP**：从固定 `c8242e0` 源码构建旧程序，保持其内嵌迁移最高为 17；由外部迁移目录升级临时 schema 到 18，旧 `openStore` 和 HTTP `WriteResults` 均成功，新列和人工类别保持。旧版评分仍按旧逻辑保持，回滚期间不能宣称继续按新合同刷新。

首次 [Actions 41588754748](https://github.com/alpha302/scopedesk/actions/runs/41588754748) 的分类/回归已通过，旧兼容 fixture 失败：HTTP 样例缺少原产品要求的非 NULL `fingerprints`/`redirects` 数组。只补齐 fixture 后重跑，未改运行产品文件。两轮原始制品均保留在 `evidence/w05-ci-*/`，最终源码 SHA-256 与 Git 对象逐一核对。

登录后的最终合成环境还验证了只读账号可查看依据、无编辑入口，管理员可保存人工分类及恢复自动。截图和 AX 记录 `browser-readonly.*`、`browser-manual.*` 已保留。浏览器验收环境运行的是与最终发布相同的产品文件；后续 CI 提交只修正旧版兼容测试。没有使用生产账号进行测试，也不等同于完整 W25 验收。

## 生产发布与回退

**2026-11-03 14:23:42 发布完成**。正式目录 `/opt/scopedesk-go/`，演练目录 `/opt/scopedesk-w05-contract-integration-20261103/`，不是并行生产实例。固定到上述完整源码，86 个运行文件校验一致；二进制 SHA-256：`0df9b7f83a310ea514251704df8d6b5634ba8643db70c5a0b8773af6c2b13e0a`，实际进程一致。

切换前在临时 PG16 恢复生产快照，完成 17→18 迁移；核心表计数和移除新增字段后的资产整体摘要一致，历史新增列全部为 NULL。实际旧生产二进制对该 v18 副本执行 migrate 成功；未启动副本 worker/scheduler。切换前再次核对源码与旧运行二进制、无活动作业/临近计划及单写者。停止后备份，再迁移和切换；正式库同样验证计数、资产旧字段摘要和历史 NULL。

数据库 **17→18**；配置和计划保持一致。首页 200、受保护设置未登录 401，未创建生产测试采集、真实目标请求 0。备份 `/var/backups/scopedesk/before-w05-contract-v18-20261103-062334/`。新增迁移向后兼容，失败回退只恢复源码/二进制，不自动破坏性还原数据库。脚本 `deploy/deploy_w05_contract_20261103.py`；脱敏记录位于 `evidence/production-w05-contract-20261103/`。服务重启会使内存会话失效，W38 尚未实现。

本项闭项不代表 W04 来源状态、W27 CDN 降噪、W24/W25 完整验收或 P0/SLO 缺口已解决。

## 执行条件变化

历史执行记录：会话权限曾切换为受限模式，一条“取回并发结果、上传新增测试并执行临时 PG16 复测”的命令被执行工具拒绝，返回 `rejected by user`，没有更具体理由。没有据此绕过权限或切换生产。随后恢复完整执行权限，推送并完成了隔离 Actions、生产演练和发布；此前拒绝没有被绕过，现已不再阻塞。

本机 Go 1.25.4 低于项目要求 1.26，离线 Linux 交叉编译检查被版本门槛阻止；这不是产品编译失败证据。继续使用 Go 1.26 的隔离环境，不降低项目 Go 版本或修改 Linux 专用实现。
