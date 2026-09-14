# 安全能力运行与部署说明

**赛题：** XA-202620 面向政企场景的大模型智能体安全关键技术研究
**适用代码：** `industry_information_assistant`

本文件说明安全相关能力的**环境准备、启动、测试、评测与演示**步骤，以及各项能力的代码位置索引。
文中所有命令均在本机实际执行验证过（验证日期 2026-09-14）。

---

## 一、安全能力总览

| 能力 | 代码位置 | 是否在生产链路生效 |
| --- | --- | --- |
| 多源输入攻击检测（含变形/编码归一化） | `backend/app/security_hooks/detectors.py`、`normalize.py`、`config/security_config.py` | ✅ 聊天入口 |
| RAG 召回内容过滤（注入 + 投毒填充） | `backend/app/security_hooks/detectors.py` | ✅ Milvus / 远端知识库 / Web 检索 |
| 提示封装与数据标记（数据/指令分离） | `backend/app/security_hooks/envelope.py` | ✅ 聊天提示词构造 |
| **跨阶段污点传播（关联分析）** | `backend/app/security_hooks/taint.py` | ✅ 检索/结果/工具三阶段联动 |
| 工具调用安全网关（注册表/RBAC/审批/审计） | `backend/app/security_tools/gateway.py`、`registry.py` | ✅ 工具问答、隔离入库、投标任务、报告递送 |
| 沙箱执行 | `backend/app/security_tools/sandbox.py` | ✅ 演示工具 |
| 输出敏感信息脱敏（含 URL 凭据 / OAuth 片段 / JWT） | `backend/app/security_hooks/detectors.py` | ✅ 工具结果 |
| 知识库隔离入库 + 审批 | `backend/app/router/knowledge_router.py` | ✅ |
| 哈希链审计与完整性校验 | `backend/app/security_hooks/audit.py`、`security_tools/gateway.py` | ✅ |
| **结构化安全日志（JSON Lines，可被 SIEM 采集）** | `backend/app/security_hooks/security_log.py` | ✅ 全链路（hook 汇聚点自动落盘） |
| **审计证据包（攻击复现 / 问题定位）** | `backend/app/security_hooks/evidence.py` | ✅ `GET /security/traces/{id}/evidence` |
| **多维安全指标（对齐赛题五维）** | `backend/app/security_hooks/evidence.py` | ✅ `GET /security/metrics` |
| 工具调用问答（ReAct 式） | `backend/app/service/tool_qa_service.py` | ✅ `POST /chat/completion/tools` |

---

## 二、环境准备

### 2.1 依赖安装

```bash
cd backend
python -m pip install -r app/requirements.txt
```

安全相关能力**不引入额外第三方依赖**：检测、归一化、信封、污点传播均基于标准库实现。
`hanziconv` 若已安装则用于完整繁简转换，未安装时自动退回内置高频字表，不影响运行。

### 2.2 环境变量

复制并填写：

```bash
cd backend
cp .env.example .env
```

必填项（`.env.example` 中已有说明）：

| 变量 | 用途 |
| --- | --- |
| `DASHSCOPE_API_KEY` | 模型调用（含工具调用问答） |
| `DASHSCOPE_BASE_URL` | 默认为百炼兼容模式地址 |
| `OPENAI_MODEL` | 模型名，**工具调用问答需选用支持 function calling 的模型**（如 `qwen-max` / `qwen3-max`） |
| `BOCHA_API_KEY` | 联网搜索工具 |
| `POSTGRES_*` / `REDIS_*` / `MILVUS_*` | 数据库、缓存与向量库 |

**安全策略相关（可选，缺省值即可运行）：**

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `SECURITY_APPROVAL_MODE` | `auto_deny` | 轻量策略引擎的审批模式：`manual`（转人工）/ `auto_deny`（直接拒绝）/ `auto_approve`（放行）。注意：**数据库化审批工作流不走此开关**，它由 `security_tools` 网关独立处理 |
| `SECURITY_MAX_HIGH_RISK_CALLS` | `3` | 单会话高危调用上限 |
| `SECURITY_MAX_TOTAL_CALLS` | `20` | 单会话工具调用总数上限 |
| `SECURITY_MAX_PATH_TRAVERSAL` | `2` | 路径穿越尝试上限 |
| `SECURITY_MAX_REPEATED_CALL` | `4` | 同一工具+参数重复调用上限 |

### 2.3 启动依赖服务

```bash
cd ..
docker compose up -d          # PostgreSQL / Redis / Milvus
```

---

## 三、启动后端

```bash
cd backend/app
python -m uvicorn app_main:app --host 0.0.0.0 --port 8000 --reload
```

启动后可访问 `http://localhost:8000/docs` 查看接口。

---

## 四、运行测试

**⚠️ 注意：命令必须在 `backend/app` 目录下执行**，且需把 `backend/test` 加入 `PYTHONPATH`
（安全模块位于 `backend/app` 下，仓库没有 `conftest.py`/`pytest.ini` 做路径修复）。

```bash
cd backend/app

# Windows PowerShell
$env:PYTHONPATH="<仓库绝对路径>/backend/test"
python -m unittest discover -s "<仓库绝对路径>/backend/test" -p "test_security*.py" -v

# Git Bash / macOS / Linux
PYTHONPATH=<仓库绝对路径>/backend/test python -m unittest discover \
  -s <仓库绝对路径>/backend/test -p "test_security*.py" -v
```

预期输出：**104 条测试全部通过**。

测试文件分工：

| 文件 | 覆盖内容 |
| --- | --- |
| `test_security_hooks.py` | Hook 三段（检索/工具/结果）基础行为与审计链 |
| `test_security_envelope.py` | 提示封装、数据标记、反自动抓取剥离、ReDoS 自检 |
| `test_security_taint.py` | 跨阶段污点传播与关联策略 |
| `test_security_normalize.py` | 输入归一化、变形展开、统计特征 |
| `test_security_false_positives.py` | **误报回归**（业务高频词不得被拦） |
| `test_security_tool_qa.py` | 工具调用问答的安全接入 |
| `test_security_sandbox.py` / `test_security_attack_samples.py` | 沙箱边界与拒绝用例 |

---

## 五、运行安全评测

```bash
cd backend
PYTHONPATH=app:test python app/scripts/evaluate_security_business_samples.py
```

输出示例（92 条业务样例）：

```json
{
  "sample_count": 92,
  "decision_pass_count": 92,
  "duplicate_execution_count": 0,
  "hash_chain_verified": true,
  "audit_field_completeness_rate": 1.0
}
```

**指标口径说明：** 该脚本验证的是**逻辑正确性与审计机制正确性**，语料为针对检测规则构造的
合成样例，**不等价于真实场景的准确率/误报率**。真实误报率请用 `test_security_false_positives.py`
的 20 条业务提问回归集，以及自行扩充的评测集测量。

---

## 六、工具调用问答

### 6.1 接口

```
POST /chat/completion/tools
Content-Type: application/json

{ "session_id": "可选", "question": "帮我查一下这家供应商的资质和近期招投标记录" }
```

响应为 SSE 流，事件类型：

| 事件 | 载荷 | 含义 |
| --- | --- | --- |
| `message` | `{"type":"react_start"}` | 进入工具调用问答模式 |
| `message` | `{"type":"content","role":"assistant","content":"…"}` | 回答正文增量 |
| `tool_call` | `{"type":"action","tool":"knowledge_search","params":{…},"step":1}` | 模型发起工具调用 |
| `tool_result` | `{"type":"observation","tool":"…","blocked":false}` | 工具返回；`blocked=true` 表示被安全策略拦截 |
| `security` | `{"type":"security","content":"…","policy_decision":{…}}` | 安全拦截通知 |
| `message` | `{"type":"done","tool_calls":[…],"trace_id":"…"}` | 结束，附带本次工具链与可审计 trace |
| `end` | `[DONE]` | 流结束 |

### 6.2 与纯 RAG 问答的区别

| | `/chat/completion`（纯 RAG） | `/chat/completion/tools`（工具问答） |
| --- | --- | --- |
| 检索 | 先检索再拼提示词 | 由模型决定是否检索、检索什么 |
| 工具 | 不调用 | 联网搜索 / 知识库 / Text2SQL / 数据分析 / 图表 / 行情 / 招投标 |
| 安全控制 | 输入 Hook + 检索 Hook + 提示词信封 | **额外**经过工具安全网关（工具注册表、RBAC、单任务调用次数、任务链累计风险、审批）与跨阶段污点关联 |
| 审计 | 内存链 | **数据库审计链**（按会话 trace 关联） |

### 6.3 curl 示例

```bash
curl -N -X POST http://localhost:8000/chat/completion/tools \
  -H "Content-Type: application/json" \
  -d '{"question":"帮我统计一下知识库里的项目数量"}'
```

### 6.4 前端入口

聊天输入框左下角 **搜索模式** 下拉里勾选 **工具调用问答**，按钮会显示为「工具问答」；
此后发送的消息走工具调用链路，工具链会以步骤形式展示，被拦截的工具会标注拦截原因。

---

## 六·五、审计、安全日志与证据导出（赛题方向四）

### 6.5.1 设计：hook 一处埋点，全链路产出

所有审计能力都从 hook 层的**唯一汇聚点**产出：

```
所有业务入口 → guard_*() → run_security_hooks() → _record_hook_event() ─┬→ 内存哈希链
                                                                        └→ 结构化安全日志
                                    _mark_taint() → _append_taint_event() ─┴→ （同上两处）
```

因此 **7 个业务入口**（聊天输入 / 远端知识库检索 / Web 检索 / Milvus 检索 /
工具调用 / 工具结果 / 工具问答输入）**一经接入即全覆盖**，不需要在各处重复埋点。

> **覆盖边界（如实说明）：** 隔离入库、投标任务、报告递送三条链路走的是
> `ToolSecurityGateway`（数据库化网关），**不经过 hook 层**——它们有自己的
> `ToolSecurityEvent` 哈希链。两条链都具备完整性校验，但目前是**两套**。

### 6.5.2 结构化安全日志

- 落盘：`logs/security_events.jsonl`（JSON Lines，默认上限 10MB 后轮转）
- 字段：`ts` / `event_type` / `trace_id` / `stage` / `decision` / `risk_score` /
  `risk_level` / `labels` / `evidence` / `metadata` / `pid`
- 可被 SIEM / ELK / Filebeat 直接采集
- **写入失败不阻断业务**，只记录错误

```bash
# 查看最近 50 条
curl -H "Authorization: Bearer <token>" "http://localhost:8000/security/logs/tail?limit=50"
```

### 6.5.3 审计证据包（攻击复现 / 问题定位）

```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/security/traces/<trace_id>/evidence"
```

返回结构：

| 字段 | 内容 |
| --- | --- |
| `summary` | 事件数、阻断数、净化数、是否被污染、最高风险分、涉及阶段与标签 |
| `timeline` | 按 seq 排序的完整时间线，**每一步的 decision / labels / evidence 都可还原** |
| `taint` | 该 trace 的污点标记与证据（跨阶段关联状态） |
| `integrity.hash_chain` | 哈希链完整性校验（`valid` 为 false 即说明事件被改、删或换序） |
| `metrics` | 该 trace 的分项指标 |

**攻击复现示例**（一条真实链路，见 `.analysis/audit_demo.py`）：

```
seq=1 [user_input ] allow          -
seq=2 [retrieval  ] taint_flagged  retrieval_prompt_injection
seq=3 [retrieval  ] modified       retrieval_prompt_injection
seq=4 [tool_result] taint_flagged  sensitive_output_redacted
seq=5 [tool_result] allow          sensitive_output_redacted
seq=6 [tool_call  ] block          taint_escalation
      依据: TAINT-CHAIN-001: 本任务链已检索到污染内容，禁止执行出网/落地动作 report_export_delivery
```

改动其中任一事件后重新校验：`{'valid': False, 'event_count': 6, 'seq': 2}` —— 精确指到被篡改的事件序号。

### 6.5.4 多维安全指标

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:8000/security/metrics"
```

按五个角度汇总：`by_stage`（阶段）、`by_decision`（决策）、`by_label`（攻击类型）、
`by_risk_level`（风险等级）、`by_dimension`（安全维度）。

`by_dimension` 对齐赛题要求的五维：

| 维度 | 覆盖的标签 |
| --- | --- |
| `content_safety` 内容安全 | 提示注入 / 越狱 / 角色扮演 / 目标劫持 / 社会工程 / 规避 / 探测 |
| `data_security` 数据安全 | 信息泄露 / 数据投毒 / 数据破坏 / 脱敏 / 召回注入 / 填充投毒 |
| `execution_safety` 执行安全 | 命令执行 / 代码注入 / SQL 注入 / 权限绕过 / 危险工具参数 / 跨阶段升级 |
| `supply_chain` 供应链安全 | 动态执行 / 子进程 / 隐蔽外联 / 密钥读取 / 文件越权 / 混淆 / 声明不符 |
| `compliance` 合规风险 | 跨阶段升级 / 网关不可用 / 转人工审批 |

> **`supply_chain` 当前恒为 0**——本系统未加载第三方 MCP 组件，该维度无数据。
> 如实返回 0 而不是省略键位，本身就是可审计的信息。

---

## 七、演示建议

按「能真实复现」优先排序：

1. **知识库隔离入库 + 审批**（`POST /knowledge/{kb_id}/upload` → 审批 → 入库）
   最完整的政企治理闭环：上传后进隔离区，审批通过前不解析、不向量化、不检索。
2. **报告递送人工审批**（`POST /security/tools/invoke` → 审批队列 → 批准/拒绝）
   工具安全网关在此路径上完整生效。
3. **跨阶段关联阻断**（工具问答链路）
   提问 → 检索到投毒文档 → 后续导出动作被 `TAINT-CHAIN-001` 阻断；
   对照：干净任务链上同一动作仅要求审批（`TAINT-CHAIN-002`）。
4. **变形攻击检出**
   空格拆字 / 繁体 / base64 编码的注入指令仍被拦；对照归一化前的漏报。
5. **Trace 审计回放**（`GET /security/traces/{trace_id}`）
   含事件哈希链完整性校验与污点状态快照。

> **注意：** 演示请使用聊天入口与上述审批链路。深度调研模块已整体移除。

---

## 八、常见问题

**Q：`ModuleNotFoundError: No module named 'security_hooks'`**
A：命令要在 `backend/app` 下执行，或把 `backend/app` 加入 `PYTHONPATH`。

**Q：工具问答返回「模型调用失败」**
A：`OPENAI_MODEL` 需为支持 function calling 的模型；`deepseek-r1` 等推理模型可能不支持工具调用。

**Q：工具调用全部返回「工具未注册，禁止执行」**
A：该工具不在 `security_tools/registry.py` 的 `TOOL_REGISTRY` 中。新增工具需先注册并声明
`base_risk`、允许角色、单 trace 最大调用次数与是否需审批。

**Q：审计里同一条 trace 查不到工具调用事件**
A：工具调用需把 `db` 传入上下文才会写数据库审计链。`tool_qa_service` 已自动注入；
自行接入新链路时请一并设置 `context.metadata["db"]` 与 `["security_trace_id"]`。

---

## 九、安全能力的代码索引

```
backend/app/security_hooks/
├── types.py         Hook 阶段与结果类型
├── detectors.py     文本/工具参数/召回内容检测、敏感信息脱敏
├── normalize.py     输入归一化、变形展开、统计特征（投毒填充）
├── envelope.py      提示封装、数据标记、反自动抓取剥离、ReDoS 自检
├── taint.py         跨阶段污点账本与关联策略
├── pipeline.py      统一 Hook 入口与审计落点
└── audit.py         内存追加式哈希链

backend/app/security_tools/
├── registry.py      工具注册表（风险等级/角色/调用次数/审批）
├── gateway.py       工具安全网关（RBAC/审批/任务链/DB 审计链）
└── sandbox.py       路径 jail、扩展名与命令白名单、受限代码执行

backend/app/service/
├── tool_qa_service.py   工具调用问答（ReAct 式，含安全接入）
└── security/            轻量策略引擎（保留为可复用方案，未纳入演示主线）

backend/app/router/
├── security_router.py   安全控制台接口（审批、trace、攻击检测）
└── knowledge_router.py  知识库隔离入库与审批
```
