# 政企 RAG 与 Tool Use 安全集成说明

## 基线系统

基线目录：`D:\competition\industry_information_assistant`

系统原有能力包括行业 RAG、知识库管理、行业资讯/招投标检索、Text2SQL、图表生成、长期记忆，以及 `deep_research_v2` 多智能体深度调研流程。

## 组员工作归纳

| 组员 | 方向 | 主要新增能力 | 集成取舍 |
| --- | --- | --- | --- |
| 邓云天 | Tool Use 标注包，但内容与向洪波 RAG 包一致 | RAGEval/MIRAGE 评测模块、评测路由、批量评测脚本、行业评测数据集 | 与向洪波代码哈希一致，按同一份 RAG 评测能力合入 |
| 向洪波 | RAG | `service/evaluation`、`router/evaluation_router.py`、`config/eval_schema.py`、`scripts/run_batch_eval.py`、多行业评测样例 | 已合入，形成 `/evaluate/single`、`/evaluate/session`、`/evaluate/batch` |
| 张文睿 | RAG | 攻击关键词库、攻击类型映射、攻击样例、拦截率测试脚本 | 词库合入 `config/security_config.py`，供统一攻击检测服务使用 |
| 张悦童 | RAG | 用户输入、网页内容、知识库文本三源提示注入/投毒检测接口 | 已整合为 `/security/attack-detect`，避免单独注册重复 `/security` 路由 |
| 何祯豪 | Tool Use | 数据库化工具安全网关、工具注册表、RBAC、人工审批、审批领取、撤回/关闭、哈希链审计、受限沙箱、隔离知识库入库、投标证据任务、报告本地模拟递送、安全控制台前端 | 作为最终演示主线合入 |
| 梁萧涵 | Tool Use | 轻量 `SecurityManager`、策略引擎、内存审批队列、任务链异常阻断、测试/示例文档 | 保留 `service/security` 模块作为可复用轻量方案；最终演示以何祯豪的可落库方案为主 |

## 已合入的演示主线

1. RAG 质量评测闭环：支持单条回答评估、从深度调研 checkpoint 评估、JSON 数据集批量评估，指标覆盖完整性、幻觉率、不相关度和可选 Exact Match。
2. 多源攻击检测：融合张悦童的三源检测入口和张文睿的高/中/低风险词库，可识别提示注入、越狱、数据投毒、SQL 注入、命令执行、信息泄露等风险。
3. Tool Use 安全网关：所有演示工具调用先经过工具注册表、RBAC、参数校验、风险评分、调用链累计风险和人工审批判断。
4. 知识库隔离入库：上传资料先进入隔离区，审批前不解析、不向量化、不参与检索；审批通过后才进入正式 DocMind/Milvus 流程。
5. 投标任务与证据快照：投标分析任务只能引用已审批内部资料和本地公开招投标/资讯记录，引用过程写入工具调用审计。
6. 报告受控导出：聊天页可发起报告导出与本地模拟递送申请，高风险内容需审批，批准后仅写入本机沙箱和模拟回执，不真实外发。
7. 安全控制台：审批员/安全管理员可查看审批队列、领取审批、批准/拒绝/关闭请求，并查看 trace 哈希链完整性。
8. 通用安全 Hook：新增不依赖多智能体的 `security_hooks` 层，统一拦截用户输入、RAG 召回内容、工具调用请求、工具返回结果，并把事件写入可验证审计链。

## 关键代码位置

- RAG 评测：`backend/app/service/evaluation/`，`backend/app/router/evaluation_router.py`
- 攻击检测：`backend/app/service/attack_detect_service.py`，`backend/app/config/security_config.py`
- 工具安全网关：`backend/app/security_tools/`，`backend/app/router/security_router.py`
- 通用安全 Hook：`backend/app/security_hooks/`，接入 `backend/app/service/retrieval_service.py`、`backend/app/service/chat_service.py`、`backend/app/service/tool_executor.py`
- 隔离入库：`backend/app/router/knowledge_router.py`，`backend/app/models/knowledge.py`
- 投标任务：`backend/app/router/tender_analysis_router.py`，`backend/app/models/tender_analysis.py`
- 前端安全与投标页：`frontend/src/pages/security/`，`frontend/src/pages/tender-analysis/`
- 聊天报告递送入口：`frontend/src/pages/chat/component/report-delivery.tsx`

## 验证结果

- 后端 Python 编译检查通过：`python -m compileall app/security_hooks app/service/retrieval_service.py app/service/chat_service.py app/service/tool_executor.py app/security_tools/gateway.py app/router/security_router.py test/security_business_samples.py test/test_security_hooks.py`
- 本地安全测试通过：`python -m unittest discover -s test -p "test_security*.py"`，共 11 条测试。
- 业务样例评测通过：92 条样例，安全决策通过 92 条，重复执行数 0，hook 审计哈希链验证通过，审计字段完整率 1.0。
- 未合入任何组员包中的 `.env` 文件。
- 前端完整构建未执行：基线 `frontend/node_modules` 不存在，`npm install --offline` 因本机 npm 缓存缺少 `react` 失败。联网安装依赖后应执行 `npm run build` 做最终验证。
