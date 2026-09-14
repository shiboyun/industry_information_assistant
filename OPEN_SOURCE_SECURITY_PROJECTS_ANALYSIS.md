# 开源 Agent/RAG 安全项目分析与融合建议

分析范围：`D:\competition` 下新增的 `ai-defense-langchain-middleware`、`Guardrails`、`guardrails_ai`、`invariant`、`raptor`、`智能体安全`。

## 一、分类总览

| 类别 | 项目 | 解决的问题 | 与当前竞赛系统关系 |
| --- | --- | --- | --- |
| LangChain/LangGraph Hook 型运行时防护 | `ai-defense-langchain-middleware` | 在 Agent 执行链中拦截 LLM 输入、LLM 输出、工具调用请求、工具调用结果 | 最贴近“hook 安全技术”，可借鉴为 `before_model / after_model / wrap_tool_call` 四点拦截架构 |
| MCP/Agent Trace 规则引擎 | `invariant` | 基于消息与工具调用 trace 写规则，识别跨工具攻击链 | 适合增强现有 `ToolSecurityGateway.verify_trace` 和任务链风险判断 |
| 可编程对话/RAG 护栏 | `Guardrails`，NVIDIA NeMo Guardrails | Input/Dialog/Retrieval/Execution/Output 五类 rails，覆盖注入、越狱、敏感数据、事实核查、幻觉检测 | 适合增强 RAG 输入、召回 chunk、输出事实性和工具执行边界 |
| Validator/结构化输出护栏 | `guardrails_ai` | 用 validator 校验输入输出风险，也支持结构化输出约束 | 当前本地目录缺源码，只能作为概念参考；不建议直接集成本地代码 |
| 攻防评测/安全研究自动化 | `raptor` | 静态分析、漏洞验证、攻击面理解、补丁生成、沙箱、提示注入防御 | 不适合整体嵌入产品，但适合抽取“提示封装、脱敏、规则扫描、安全评测”思想 |
| 论文/Benchmark 资料 | `智能体安全` | Agent 安全论文与 benchmark，包括 AgentDojo、AgentHarm、Agent Security Bench 等 | 适合支撑答辩中的理论依据、评测集设计和攻击场景设计 |

## 二、项目详解

### 1. ai-defense-langchain-middleware

项目定位：Cisco AI Defense 面向 LangChain/LangGraph Agent 的安全中间件。它不是单纯关键词检测，而是把安全检测挂在 Agent 执行生命周期里。

核心能力：

- `AIDefenseMiddleware`：通过 LangChain `before_model` 和 `after_model` hook 检查 LLM 输入/输出。
- `AIDefenseToolMiddleware`：通过 `wrap_tool_call` 检查工具调用请求和工具调用结果。
- `AIDefenseHooks`：给 LangGraph `create_react_agent` 提供 `pre_model_hook`、`post_model_hook`。
- `AIDefenseToolNode`：继承 LangGraph `ToolNode`，对每个工具调用做前置/后置检测。
- 支持 `enforce / monitor / off` 三种模式，以及 `fail_open` 配置。

对当前系统的价值：非常适合作为“Hook 型 Agent 安全网关”的参考架构。我们现有系统已经有 `ToolSecurityGateway`，但更偏工具层；这个项目提示我们可以把拦截点扩展为四层：用户输入前置检测、模型输出后置检测、工具调用前置审批、工具结果后置脱敏/检测。

融合建议：高优先级。不要依赖 Cisco 云服务本身，建议借鉴它的中间件接口设计，在我们系统中实现本地版：`before_llm`、`after_llm`、`before_tool`、`after_tool`。这样答辩时可以明确说我们采用“Agent 生命周期 Hook 防护”。

### 2. invariant

项目定位：Invariant Guardrails 是面向 LLM/MCP Agent 的上下文规则护栏。它把 Agent 的消息、工具调用、工具输出看成一条 trace，然后用 Python 风格规则匹配危险行为。

核心能力：

- `LocalPolicy.from_string()` / `from_file()`：加载本地规则。
- `policy.analyze(messages)`：分析完整 Agent trace。
- `analyze_pending(past_events, pending_events)`：只分析新增事件，适合运行时拦截。
- 支持跨工具流规则，例如“先读取收件箱，再向外部邮箱发送邮件”。
- 支持工具输出中的 prompt injection 检测，再联动阻止后续敏感工具调用。

对当前系统的价值：我们已经有 `ToolInvocation.trace_id`、`ToolSecurityEvent` 和哈希链审计，但当前风险判断主要是单次工具 profile + 累计风险分。Invariant 的价值是补上“跨步骤语义规则”：不是某个工具本身危险，而是工具组合形成风险。

融合建议：高优先级。可以先不引入完整 Invariant 依赖，而是在我们 `ToolSecurityGateway` 中增加一层 `TracePolicyEngine`：把当前 trace 中的工具调用序列转成 Invariant 风格事件，然后配置规则，例如：

- 知识库检索到疑似注入文本后，禁止直接调用报告递送。
- 读取内部资料后，外发/导出必须进入人工审批。
- 同一 trace 内多次检索不同知识库后调用导出，提高风险分。
- 工具输出含手机号、邮箱、密钥形态时，后续导出自动要求审批。

### 3. Guardrails，NVIDIA NeMo Guardrails

项目定位：可编程 LLM 护栏框架。它不只做安全分类，还能定义对话流程、输入护栏、检索护栏、执行护栏和输出护栏。

核心能力：

- Input rails：用户输入进入模型前检测、拒绝或改写。
- Dialog rails：控制对话流程和可执行动作。
- Retrieval rails：RAG 检索 chunk 进入 prompt 前过滤或脱敏。
- Execution rails：工具/action 调用前后检测。
- Output rails：模型输出返回用户前检测、事实核查、敏感信息处理。
- 内置库包含 `injection_detection`、`jailbreak_detection`、`sensitive_data_detection`、`factchecking`、`hallucination`、`llama_guard`、`ai_defense` 等。

对当前系统的价值：它是最完整的“RAG + 对话 + 工具”护栏参考。当前竞赛系统已经有多源攻击检测和 RAG 评测，但检索 chunk 过滤、输出事实核查和对话流程约束还可以强化。

融合建议：中高优先级。短期不建议完整引入 NeMo Guardrails，因为依赖重、配置体系较大；建议抽取理念并落到我们系统：

- 在 `retrieval_service` 后加 `retrieval_guard`，过滤知识库召回中的间接提示注入。
- 在 `chat_service` 返回前加 `output_guard`，做敏感信息脱敏和安全提示。
- 在深度调研 `writer` 输出前加事实核查/幻觉评分，对接已合入的 RAG 评测模块。

### 4. guardrails_ai

项目定位：Guardrails AI 框架，用 validator 检查输入/输出风险，并约束 LLM 结构化输出。

当前本地状态：目录里只有 README、pyproject、Makefile 和测试骨架，没有实际 `guardrails` 源码包。因此它更像一个不完整 checkout 或元信息包，不能直接从本地复制实现。

核心能力，从 README/pyproject 判断：

- Input/Output Guards：组合多个 validators 检测风险。
- Guardrails Hub：可安装独立 validator 包，例如正则匹配、竞品检查、毒性语言检测等。
- 结构化输出：用 Pydantic schema 约束 LLM 输出，并校验/修复。
- 可作为服务启动，通过 REST 或 OpenAI-compatible endpoint 调用。

对当前系统的价值：它适合作为“输出结构化与 validator 机制”的参考。我们的深度调研报告、RAG 评测结果、安全检测结果都可以用 Pydantic schema 固化格式，减少前端解析脆弱性。

融合建议：中优先级。不要直接集成本地目录；建议在我们系统中实现轻量 validator 抽象，先覆盖：手机号/邮箱/密钥脱敏、JSON schema 校验、报告字段完整性校验。

### 5. raptor

项目定位：自动化安全研究框架。它面向代码库/二进制的漏洞发现、验证、利用和修复，不是普通在线聊天安全网关。

核心能力：

- `/scan`：Semgrep/CodeQL 静态扫描，输出 SARIF。
- `/agentic`：扫描、漏洞验证、利用生成、补丁生成的自动化流程。
- `/understand`：攻击面、数据流和信任边界分析。
- `/sca`：依赖和供应链安全分析，支持 SBOM、OSV、CISA KEV、EPSS 等。
- `core/security`：包含提示注入预检、提示 envelope、非可信内容隔离、输出清洗、日志脱敏、密钥脱敏、HITL Rule of Two、CI 安全门禁等。
- `engine/semgrep/rules`：本地安全规则，覆盖 SQL 注入、命令注入、XSS、SSRF、路径穿越、反序列化、弱密码学、硬编码密钥等。

对当前系统的价值：RAPTOR 不适合整体嵌入政企助手，但它的防御工程细节很强，适合提炼成我们系统的“安全增强模块”。特别是：非可信内容提示封装、Markdown/HTML 自动加载链接清洗、密钥脱敏、命令/文件操作前置检查、Rule of Two。

融合建议：中高优先级。建议抽取三类能力：

- 把 `prompt_input_preflight` 的模式库思想融合进当前 `attack_detect_service`，作为更细的英文/编码绕过/Unicode 隐写检测。
- 把 `redaction.py` 的密钥脱敏思路融合进报告递送、日志和工具返回结果。
- 把 Semgrep 规则作为赛前自检工具，对最终项目做一次供应链和后端代码安全扫描，而不是运行时依赖。

### 6. 智能体安全论文资料

项目定位：不是代码库，是论文/benchmark 资料集合。

包含方向：

- AgentDojo：动态环境下评估 prompt injection 攻击与防御。
- Agent Security Bench：形式化和评测 LLM Agent 攻防。
- AgentHarm：评估 Agent 有害行为能力。
- LM-emulated sandbox：用语言模型模拟沙箱识别 Agent 风险。
- AgentAuditor：面向 Agent 的安全评估方法。

对当前系统的价值：适合支撑竞赛答辩中的“研究依据”和“评测场景设计”。我们可以把论文里的攻击场景映射到当前系统：知识库投毒、网页间接提示注入、工具越权、敏感信息外发、跨工具链攻击。

融合建议：高优先级但不是代码融合。建议将其用于：

- 设计攻击样例集。
- 设计演示脚本。
- 给安全控制台指标命名和分层。
- 解释为什么需要 RAG 检索护栏、工具调用审批、trace 审计和人工确认。

## 三、建议融合路线

### 第一阶段：最适合快速落地

1. 借鉴 `ai-defense-langchain-middleware`，把现有安全网关扩展成四类 hook：`before_llm`、`after_llm`、`before_tool`、`after_tool`。
2. 借鉴 `Invariant`，在现有 trace 审计基础上增加跨工具规则，例如“检索到可疑内容后禁止直接导出”。
3. 借鉴 `RAPTOR redaction`，给工具参数、工具输出、报告递送、审计日志增加更强的密钥/PII 脱敏。

### 第二阶段：增强 RAG 安全

1. 借鉴 NeMo Guardrails 的 retrieval rails，在知识库召回 chunk 进入 prompt 前做注入检测和脱敏。
2. 借鉴 NeMo hallucination/factchecking，把深度调研最终报告接入评测模块，生成安全与可信度评分。
3. 借鉴 Guardrails AI validator，把深度调研结构化输出变成可校验 schema。

### 第三阶段：竞赛答辩增强

1. 用 RAPTOR/Semgrep 对最终项目做自检，产出“系统自身安全加固报告”。
2. 用 `智能体安全` 论文资料设计 benchmark：正常任务、提示注入、间接注入、知识库投毒、工具越权、敏感信息外发。
3. 在前端安全控制台增加“防护层命中位置”：输入护栏、检索护栏、工具护栏、输出护栏、审计护栏。

## 四、优先级结论

最值得融合：`ai-defense-langchain-middleware` 的 hook 架构、`Invariant` 的 trace 规则、`RAPTOR` 的脱敏/非可信内容隔离、`NeMo Guardrails` 的 retrieval/output rails。

不建议直接整体融合：`raptor` 全框架、`Guardrails` 全框架、`guardrails_ai` 本地目录。它们依赖重、侵入大，容易影响演示稳定性。对竞赛项目而言，最稳妥的是“吸收架构和关键机制，落到我们已有 FastAPI + 自研多智能体系统中”。

## 五、已落地融合点

本次实现将参考项目中的成熟机制落到 `backend/app/security_hooks/`，形成不依赖多智能体模块的通用安全 hook 层：

| 参考项目机制 | 本系统落点 | 竞赛报告表述 |
| --- | --- | --- |
| `ai-defense-langchain-middleware` 生命周期 hook | `run_security_hooks()`，覆盖 `user_input / retrieval / tool_call / tool_result / output` 阶段 | “采用生命周期 Hook 型防护，可快速适配不同智能体和平台” |
| NeMo Guardrails retrieval rails | `guard_retrieval_results()` 接入本地 Milvus 检索、远端知识库检索和 Web 检索 | “RAG 召回内容进入提示词前先过滤间接提示注入和污染片段” |
| Invariant trace 思想 | 所有 hook 事件写入同一 trace，并提供 `/security/hooks/verify/{trace_id}` 验证 | “即使工具数量少，也能展示输入、检索、工具、结果的完整可追溯链路” |
| RAPTOR redaction / preflight 思路 | `guard_tool_result()` 对手机号、邮箱、token/API key 等输出做脱敏 | “工具结果和报告递送前做敏感信息治理” |
| Guardrails AI validator 思路 | hook 结果统一返回 `decision / risk_score / labels / evidence / sanitized_payload` | “检测结果结构化，便于前端展示、审计和批量评测” |

现阶段没有整体复制这些项目的重依赖框架，而是把成熟方案压缩成轻量实现，覆盖 RAG 和工具调用两个竞赛主线。这样后续删除或弱化多智能体深度调研模块时，安全能力仍可独立保留。

## 六、报告可用验证指标

本地业务样例评测脚本：`backend/app/scripts/evaluate_security_business_samples.py`。

当前输出指标：

- `sample_count`: 92
- `decision_pass_count`: 92
- `duplicate_execution_count`: 0
- `hash_chain_verified`: true
- `audit_field_completeness_rate`: 1.0
- `audit_event_count`: 92

这些指标适合放在报告的“实验验证”部分，说明系统不仅做了单点检测，也验证了审计链完整性、重复执行防护和字段可追溯性。
