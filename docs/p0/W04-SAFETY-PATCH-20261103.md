# W04 防误判子项：源码、测试与生产发布

日期：2026-11-03（Asia/Shanghai）。用户要求优先高频、高优先级、可见效果，自主实施和部署；低频低优先级暂不测。按此交付 W04 的防误判子项，**不将完整 W04 关闭**。39 项中 W01–W03 整项已关闭，36 项未关闭；W37 单实例已发布、跨实例仍开放，W04 本次部分交付。逐项清单见 [W01–W39 状态及优先级](W01-W39-STATUS-20261103.md)。

## 实际效果

- 第三方被动索引连续未发现某资产，不再增加原 `miss_count`、修改 `is_alive` 或产生 HTTP `ASSET_DOWN`。人工/Hunter/crt.sh/CertSpotter 历史来源都不能被一个不相关查询判为下线。
- 只有重新发现域名、DNS 结果或第三方证据时，保持已有 HTTP 失败计数和存活状态，不产生 `ASSET_BACK`。
- 实际 HTTP 探测失败仍递增原失败计数、达到 3 次保持原下线事件行为；实际成功响应仍清零并产生恢复事件。事件恢复原因明确为“实际 HTTP 探测响应恢复”。
- **执行记录页**为本版本新运行显示“缺失判定”说明：被动索引和分页完成不证明实时覆盖，本轮仅保留发现证据。新增 summary 字段 `absence_eligible=false`、`coverage_complete=false`、`absence_reason`；原 `complete` 字段含义不变。
- 不回填旧任务 summary，不清空历史计数、不自动恢复过去已标为下线的资产。旧混合计数无法推断来源；以后获得真实 HTTP 成功证据后才按正常路径恢复。

## 修改文件

- `results.go`：移除以 legacy `complete` 对全范围未见资产执行的缺失/下线写入；仅实际非 evidence-only 的 Alive 结果改变 HTTP 状态，取消未知结果清零/虚假恢复；增加判定说明。
- `collectors.go`：CertSpotter 空终页仍代表 `Complete=true`，但 `AbsenceUsable=false`，不把分页终止提升为实时覆盖证明。
- `queue.go`：不再为一般成功 collector 自动赋予 `absence_usable=true`；来源成功不等同于可信缺失资格。
- `web/index.html`：执行记录显示新任务的判定说明。没有增加采集按钮或请求外部目标。
- 新增 `w04_missing_test.go`、`.github/workflows/w04-safety.yml`：仅针对高优先级常见误判路径和相关安全/写入回归。
- `p0_correctness_test.go`：旧“错误下线”特征测试改为安全回归；`store_integration_test.go`：原上下线回归改为明确的真实 HTTP 失败/恢复输入。
- `plugin_evidence_integration_test.go`：修正旧 fixture，显式标记 CDN 分类已经测量，避免把未测状态当成已确认 CDN。没有修改产品网络分类逻辑。
- 新增 `deploy/deploy_w04_20261103.py`：沿用受控备份、源码摘要、快照恢复演练、无活动作业、切换/回退和就绪鉴权检查。

## 先失败，再通过

失败复现源码 `4855e0ef46181545dd15d77c68170d3f10cb2a56`；[红色运行 41571348513](https://github.com/alpha302/scopedesk/actions/runs/41571348513) 的 3 个顶层验收测试全部失败，0 跳过，分别证明被动缺失改存活状态、被动发现清 HTTP 失败、分页完成提升为缺失资格。原始数据 `evidence/w04-red-41571348513/`。

产品修复源码 `5be3e5e6e7407aae5f66f9357a742467d855efe7`。首轮修复后运行 [41571472259](https://github.com/alpha302/scopedesk/actions/runs/41571472259)：4 个 W04 验收通过；扩展回归 14 PASS、2 FAIL，不能记为全绿。一个旧 CDN fixture 缺 `NetworkMeasured`，已修 fixture；另一个插件执行回归需要 cgroup v2 pids 委派，普通 runner 不具备，实际在插件启动前失败，不能冒称验证了候选刷新失败路径。最终本次定向回归集合不含该需委派的插件执行用例；它仍是未完成的额外验收，**没有修改 cgroup 或插件保护让测试通过**。首轮失败制品保留在 `evidence/w04-attempt-41571472259/`。

最终 CI 源码 `c9f80b0b527d44bb58c7339211b988b7970a7b23`；[绿色运行 41571775469](https://github.com/alpha302/scopedesk/actions/runs/41571775469)：

- **4 个 W04 PASS、0 FAIL、0 SKIP**，race 通过。覆盖四类历史来源、三轮未发现、DNS/发现未知、第三方存活证据、真实 HTTP 三次失败及恢复、明确 summary 原因、证书分页与覆盖区别。
- **15 个相关回归结果 PASS、0 FAIL、0 SKIP**（包含父测试与子例），race 通过。包括原 P0 错误下线回归、证书分页/部分页、第三方证据不覆盖实时状态、ScopeGuard、预算原子性、事件差分、队列租约、跨 worker 限速及候选快照不能授权提交。
- PostgreSQL 16 临时 CI 库，100% 合成数据，未访问生产库或真实目标。每个数据库测试使用独立 schema，`p0Store` 额外检查隔离目标边界。
- 同产品源码的 [W01 运行 41571472408](https://github.com/alpha302/scopedesk/actions/runs/41571472408) 通过事件与相关写入回归。未据此声称完整历史回归通过。

原始 JSONL/源码摘要及 SHA-256 清单：`evidence/w04-green-41571775469/`。源码修复后又提交了 fixture/CI 修正；逐字节核对最终 CI 与实际发布 commit 的 **82 个运行文件完全一致**，差别只在测试与 CI，证明在 `evidence/production-w04-20261103/tested-runtime-equivalence.json`。

## 生产发布结果

**2026-11-03 11:23:55（上海时间）发布完成**，生产运行源码 `5be3e5e6e7407aae5f66f9357a742467d855efe7`。正式目录 `/opt/scopedesk-go/`；隔离演练目录 `/opt/scopedesk-w04-integration-20261103/`。

- PostgreSQL 16 迁移版本 **16→16**；没有新增或修改迁移，核心表计数一致。
- 发布及运行二进制 SHA-256：`c5dd442f7835d0ea99864b4bce77d3cc85c1ef493ea5bbfae0c6f90d1464250b`；82 个安装文件逐一验证。
- 首页和鉴权就绪检查通过；既有配置和监控计划保持一致。没有导入密钥，没有发出测试目标请求，没有主动触发生产采集。
- 演练先恢复生产快照到临时 PostgreSQL 16，仅执行 migrate 初始化，不启动副本 worker/scheduler；版本/表计数一致。服务器另用无网络容器执行 W37/W03 认证 fixture，12 个 PASS；这不代替 W04 的 PG CI。
- 恢复点 `/var/backups/scopedesk/before-w04-v16-20261103-032348/`（root 保护目录）。脱敏结果、离线认证输出和清单在 `evidence/production-w04-20261103/`。

服务重启会使原内存会话失效，需重新登录。未执行登录后浏览器验收，没有使用真实生产账户/资产制造测试事件；页面模板发布核对不能称作浏览器业务验收。

## W04 仍未完成的验收

本次是保守停止错误判定的子项。按来源独立的被动缺失状态、完整查询/覆盖/资格持久合同、查询版本/运行代次、重复 finalizer 的幂等计数、历史混合计数未知标注及独立 active_failure 数据模型仍待新增迁移/接口设计，不将 `complete` bool 替代这些合同。目前没有可证明实时完整覆盖的来源，因此拒绝被动下线；不伪造“可信来源三轮缺失”样本。

ScopeGuard、黑名单、平台/项目/范围限速、预算和租约保持；没有为快交付提高速率或扩大扫描范围。未做性能改造或容量结论，不宣称未执行的 EXPLAIN/压测已完成。后续仍优先 W26（独立 DNS 负面证据，单次负面不判 HTTP 下线）、W27（CDN IP_CHANGED 降噪）、W05（分类误报），再按完整依赖推进。
