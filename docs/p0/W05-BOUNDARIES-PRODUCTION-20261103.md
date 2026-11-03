# W05：新资产分类边界修复（部分交付）

2026-11-03，Asia/Shanghai，`batch-p0-p1`。本次只交付新资产分类词边界，**W05 不关闭**。分类解释/规则版本持久化、明确的人工覆盖标记和版本化自动重算仍未交付；不把保留历史值等同于完整人工覆盖合同。

## 行为

`categoryScore` 先复用域名规范化（IDNA、大小写、尾点），再排除可注册域；写入新资产时同时传入当前授权范围根域，只检查根域以下子域标签。使用项目已有 Public Suffix List，包含 private suffix。IP 和无效域名不推测分类。

关键词仅匹配完整标签或连字符分段，允许末尾 ASCII 数字：`api`、`api2`、`my-api`、`api-v2` 命中；`capital`、`contest`、`myapi`、`devops`、`2api` 不命中。跳过整个 `xn--` 标签，避免把编码内容当作关键词。多个命中保持原 API→SSO→admin→dev/test/uat 优先顺序，基础/关键词/存活加分仍为 10/20/10，评分不是漏洞或归属置信度。

范围为 `admin.example.com` 时，根域自身和 `www.admin.example.com` 不因根域 admin 获得分类；`api.admin.example.com` 为 API。不使用未经标签边界校验的后缀。历史资产分类/评分完全保留，不批量更正历史误报，也不根据本次 HTTP 状态变化自动重算。ScopeGuard、预算、限速和租约没有调整。

文件：`pipeline.go`、`results.go`、`w05_category_test.go`；原 `TestP0CharacterizeClassification` 改为修复回归断言，旧红色证据仍保留。

## 验证

红色运行基线 `e534d19a6e88a5ddb544f95beab9e98b5357864e` 加入 20 个分类正反例：11 PASS、10 FAIL（包含失败父测试），零跳过。保留 `evidence/w05-boundaries-20261103/red.jsonl`，不是靠改掉验收期望变绿。

发布源码 `c8242e06a34e14188900a5d4f027567a0b3aa5c3`。隔离 Linux 构建目录 `/opt/scopedesk-w05-fixture-20261103/`，race 定向分类及范围、预算、私网 DNS、重定向回归：**27 PASS、0 FAIL/SKIP**。追加真实写入测试后的临时 PG16 race 回归 **34 PASS、0 FAIL/SKIP**，包含新资产、历史/人工值保留、W04、W26 DNS 持久化、候选快照不能授权提交、差异幂等写入；测试源码追加部分随后提交，运行产品文件与发布相同。原始 JSONL 与隔离运行器在同一证据目录。

仅受控 fixture、临时 PG16/独立 schema，无供应商付费请求、无真实外部目标。没有完整历史回归、浏览器登录后验收或性能结论。

## 发布

**2026-11-03 11:56:30 发布完成**。生产 `/opt/scopedesk-go/`；演练 `/opt/scopedesk-w05-integration-20261103/`。源码固定到上述完整 commit，校验 84 个运行文件，构建、无网络登录 fixture、生产快照临时恢复及迁移演练通过。切换前重新核对旧源码、单写者、无活动作业/临近计划；停止后备份，再切换。

数据库仍为 **17→17**，核心表计数一致，配置和计划保持一致。二进制 SHA-256 `b7d613c795651a4009ce94525e0a6b4f750e74b177375eda5a678c70593f99fc`，实际进程一致；首页和鉴权检查通过。备份 `/var/backups/scopedesk/before-w05-v17-20261103-035622/`。生产测试目标请求 0；重启使内存会话失效。

发布脚本 `deploy/deploy_w05_20261103.py`，失败只恢复旧源码/二进制，不自动破坏性还原数据库。脱敏记录 `evidence/production-w05-20261103/deployment-result.json`。

## 后续

完整 W05 仍需新增可审计分类版本/解释、明确人工覆盖及历史兼容合同后再做状态变化重算。W33 已核对现状：统一 no-store、未版本化资源引用，无 ETag/应用压缩；本次未改变该路径，也未把它标为完成。下一批仍可在 W04/W27 与常用页面独立项间按依赖推进。

后续状态：本文件为 11:56 边界子项发布时的历史记录；14:23 已完成完整 W05 合同和迁移 18 发布，见 [最终验收与发布](W05-CLASSIFICATION-CONTRACT-20261103.md)。
