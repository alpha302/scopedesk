# batch-p0-p1：P0 第 1 项验收记录

完成范围：可重复合成数据集及受控 DNS/HTTP fixture 就绪验证。测试运行于 2026-10-30，原始制品于 2026-11-03 重新核对并归档。**本项完成后停止；P0 第 2–4 项与 P1 尚未进入。**

分支：`batch-p0-p1`。代码提交：`20af9daaa3e986614a2e36ecc9d34e41db3369c7`。

## 文件与测试

- `p0_dataset_test.go`：新增 `TestP0DatasetV1`，检查行数、合成比例和重复建库的 9 组 SHA-256 指纹；新增 `TestP0PositiveDNSHTTPFixture`，验证双栈 DNS、HTTP 200、同源重定向和 favicon。
- `p0_baseline_test.go`：只更正合成比例注释；复用既有建库和造数方法，未改产品逻辑。
- `.github/workflows/p0-dataset.yml`：只运行本项和既有 `TestP0DatabaseBoundary`。临时 PostgreSQL 16 镜像固定 digest，数据库容器限制 2 CPU/1 GiB，Go GOMAXPROCS=2。
- `docs/p0/evidence/run-41031753949/`：保存测试 JSONL、12 份数据集清单、源码摘要、Go 版本、测试 commit 和制品校验清单。

没有修改产品源码、API 字段或迁移；没有连接生产、真实供应商或外部探测目标。

## 合成数据合同

全部为合成数据，不代表生产分布。固定时间锚 `2026-10-30T00:00:00Z`。

- 先验证 1k 资产冒烟，再验证 10k 资产；每资产 2 服务，分别为 2k/20k 服务行。20 范围、4 项目，候选数量等于资产数量。
- 均匀和单范围占 90% 两组分布；每组独立建库三次，不是重复读取同一份库。
- 5% 双栈，另 15% 多 IPv4，即 20% 资产含多个 IP；10% 长中文标题；1% 宽 JSON；25% 未画像；20% 合成 CDN 标记。
- 来源按 i%3 分配 crtsh、certspotter、manual+hunter，约各三分之一；10k 时分别 3333、3334、3333。它们是历史来源标签，不调用真实来源。
- 每范围 30 天任务记录，共 600 个完成任务；完整/部分来源统计交替记录。每资产一个事件和快照，时间分布覆盖 30 天，不代表每资产每天都有历史。
- 资产、服务、范围、项目、候选、作业、来源统计、事件、快照共 9 组按固定顺序计算指纹；服务 first_seen/last_seen、范围/项目 created_at/updated_at、候选 first_seen/last_seen、作业 available_at 等运行时记账字段显式排除。未宣称数据库物理文件逐字节一致。

## 测试输出与证据

[Actions 41031753949](https://github.com/alpha302/scopedesk/actions/runs/41031753949) 成功。原始 JSONL 核对结果：18 PASS（3 个顶层测试、15 个数据/fixture 子用例），0 FAIL，0 SKIP。

```text
assets=1000,  skew90=false, rounds=3: nine fingerprints identical; services=2000
assets=1000,  skew90=true,  rounds=3: nine fingerprints identical; services=2000
assets=10000, skew90=false, rounds=3: nine fingerprints identical; services=20000
assets=10000, skew90=true,  rounds=3: nine fingerprints identical; services=20000
controlled DNS/HTTP fixture: 3 rounds PASS
```

每轮 JSON 原始数据及其摘要已落盘；本项没有性能测量结论，不输出请求次数、PG 往返、锁等待、idle QPS 的中位数或 p95/p99。这些属于后续第 2–3 项。

## 已知限制与停止点

DNS 在 loopback UDP 上运行，返回文档网段的 A/AAAA；HTTP 客户端只访问 httptest loopback 地址。二者分别验证就绪，未把文档 IP 作为实际拨号地址，未改变 ScopeGuard 来允许测试地址。**本项不证明产品从 DNS 到 HTTP 的完整拨号链正确，也不证明请求计费、限速、预算或租约的性能行为。**后续计量必须建立保持授权边界的受控连接方案，不能用绕过产品拨号的结果代表真实请求计量。

容器资源限制在 workflow 中指定，尚未保存运行时 cgroup 实效快照；测试进程所在 runner 也非整体 2 CPU 容器。这不是生产容量验收。固定镜像引用和 CI 配置可复用，但完整 Go/runner/PG 参数、负载窗口及足够尾延迟样本仍须在后续测量中记录。

W01–W39 的三态清单未在本项生成，P1 的红测/修复未执行；全部留在用户指定的后续顺序。此处停下，等待用户指示进入 P0 第 2 项。
