import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Alert, Button, Card, Col, Descriptions, Drawer, Empty, Input, Row, Select, Space,
  Statistic, Switch, Tag, Timeline, Tooltip, Typography, message,
} from 'antd'
import { ReloadOutlined, FileSearchOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import * as api from '@/api'
import type { EvidenceBundle, SecurityLogLine, SecurityMetrics } from '@/api/security'

const { Text, Paragraph } = Typography

/**
 * 按阶段渲染：日志的价值在于「一眼看出问题出在链路的哪一环」，
 * 因此每个阶段有固定的序号与配色，与后端 hook 的五个阶段一一对应。
 */
const STAGE_META: Record<string, { label: string; color: string; order: number }> = {
  user_input: { label: '① 输入检测', color: '#1677ff', order: 1 },
  retrieval: { label: '② 检索过滤', color: '#13c2c2', order: 2 },
  tool_call: { label: '③ 工具调用', color: '#722ed1', order: 3 },
  tool_result: { label: '④ 结果脱敏', color: '#52c41a', order: 4 },
}
const TAINT_META = { label: '⛓ 跨阶段关联', color: '#fa8c16', order: 9 }

const DECISION_META: Record<string, { label: string; color: string }> = {
  allow: { label: '放行', color: 'green' },
  modified: { label: '已净化', color: 'blue' },
  block: { label: '已阻断', color: 'red' },
  approval_required: { label: '转人工审批', color: 'orange' },
  taint_flagged: { label: '标记污染', color: 'purple' },
  taint: { label: '标记污染', color: 'purple' },
}

const DIMENSION_LABEL: Record<string, string> = {
  content_safety: '内容安全',
  data_security: '数据安全',
  execution_safety: '执行安全',
  supply_chain: '供应链安全',
  compliance: '合规风险',
}

function stageOf(line: { event_type?: string; stage?: string | null }) {
  if (line.event_type === 'taint_marked') return TAINT_META
  return STAGE_META[line.stage || ''] || { label: line.stage || '其他', color: '#8c8c8c', order: 5 }
}

function decisionOf(decision?: string) {
  return DECISION_META[decision || ''] || { label: decision || '-', color: 'default' }
}

function formatTime(value?: string) {
  if (!value) return '-'
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(new Date(value))
}

/** 错误信息提取：避免 `catch (error: any)`，同时保持提示可读。 */
function errorMessage(error: unknown, fallback: string) {
  const message = (error as { message?: string } | null)?.message
  return message || fallback
}

export default function SecurityLogsPage() {
  const navigate = useNavigate()
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null)
  const [logs, setLogs] = useState<SecurityLogLine[]>([])
  const [logPath, setLogPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [stageFilter, setStageFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [traceFilter, setTraceFilter] = useState('')
  const [evidence, setEvidence] = useState<EvidenceBundle | null>(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const timerRef = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const me = await api.security.getSecurityMe()
      if (me.data.role === 'operator') {
        message.info('安全日志仅供数据安全专员和安全管理员查看。')
        navigate('/chat', { replace: true })
        return
      }
      const [metricsResult, logsResult] = await Promise.all([
        api.security.getSecurityMetrics(),
        api.security.getSecurityLogs(200),
      ])
      setMetrics(metricsResult.data)
      setLogs([...logsResult.data.events].reverse())
      setLogPath(logsResult.data.path)
    } catch (error: unknown) {
      message.error(errorMessage(error, '加载安全日志失败'))
    } finally {
      setLoading(false)
    }
  }, [navigate])

  useEffect(() => { void refresh() }, [refresh])

  useEffect(() => {
    if (!autoRefresh) {
      if (timerRef.current) window.clearInterval(timerRef.current)
      timerRef.current = null
      return
    }
    timerRef.current = window.setInterval(() => { void refresh() }, 5000)
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [autoRefresh, refresh])

  const openEvidence = useCallback(async (traceId: string) => {
    if (!traceId) { message.info('该事件没有 trace 归属'); return }
    setEvidenceLoading(true)
    try {
      const result = await api.security.getTraceEvidence(traceId)
      setEvidence(result.data)
    } catch (error: unknown) {
      message.error(errorMessage(error, '导出审计证据失败'))
    } finally {
      setEvidenceLoading(false)
    }
  }, [])

  const filtered = useMemo(() => logs.filter((line) => {
    const meta = stageOf(line)
    if (stageFilter === 'taint' && line.event_type !== 'taint_marked') return false
    if (stageFilter && stageFilter !== 'taint' && line.stage !== stageFilter) return false
    if (decisionFilter && (line.decision || '') !== decisionFilter) return false
    if (traceFilter && !(line.trace_id || '').includes(traceFilter.trim())) return false
    return Boolean(meta)
  }), [logs, stageFilter, decisionFilter, traceFilter])

  /** 问题定位：第一条阻断（其次净化）就是「出错的地方」。 */
  const firstProblem = useMemo(
    () => evidence?.timeline.find((item) => item.decision === 'block')
      || evidence?.timeline.find((item) => item.decision === 'modified')
      || null,
    [evidence],
  )

  const integrity = evidence?.integrity?.hash_chain

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }} align="center">
        <Space align="center">
          <SafetyCertificateOutlined style={{ fontSize: 20 }} />
          <Text strong style={{ fontSize: 18 }}>安全日志与审计溯源</Text>
          <Tag color="blue">赛题方向四</Tag>
        </Space>
        <Space>
          <Tooltip title="每 5 秒自动拉取最新日志">
            <Space size={6}>
              <Text type="secondary">自动刷新</Text>
              <Switch checked={autoRefresh} onChange={setAutoRefresh} size="small" />
            </Space>
          </Tooltip>
          <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void refresh()}>刷新</Button>
        </Space>
      </Space>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="日志由 hook 层唯一汇聚点产出，覆盖输入检测 / 检索过滤 / 工具调用 / 结果脱敏 / 跨阶段关联五个阶段"
        description={
          <Text type="secondary">
            结构化日志以 JSON Lines 落盘，可被 SIEM 采集；点击任意一条可导出该任务链的完整审计证据包。
            {logPath ? <Text code style={{ marginLeft: 8 }}>{logPath}</Text> : null}
          </Text>
        }
      />

      {/* ---------- 多维指标 ---------- */}
      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        <Col xs={12} md={4}><Card size="small"><Statistic title="事件总数" value={metrics?.total_events ?? 0} /></Card></Col>
        <Col xs={12} md={4}><Card size="small"><Statistic title="任务链数" value={metrics?.trace_count ?? 0} /></Card></Col>
        <Col xs={12} md={4}>
          <Card size="small">
            <Statistic title="已阻断" value={metrics?.by_decision?.block ?? 0} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
        <Col xs={12} md={4}>
          <Card size="small">
            <Statistic title="已净化" value={metrics?.by_decision?.modified ?? 0} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col xs={12} md={4}>
          <Card size="small">
            <Statistic title="转人工审批" value={metrics?.by_decision?.approval_required ?? 0} valueStyle={{ color: '#d46b08' }} />
          </Card>
        </Col>
        <Col xs={12} md={4}>
          <Card size="small">
            <Statistic title="标记污染的链路" value={metrics?.by_decision?.taint_flagged ?? 0} valueStyle={{ color: '#531dab' }} />
          </Card>
        </Col>
      </Row>

      <Card size="small" title="安全维度分布（对齐赛题五维）" style={{ marginBottom: 16 }}>
        <Space wrap size={[8, 8]}>
          {Object.entries(metrics?.by_dimension || {}).map(([dimension, count]) => (
            <Tag key={dimension} color={count > 0 ? 'processing' : 'default'}>
              {DIMENSION_LABEL[dimension] || dimension}：{count}
            </Tag>
          ))}
        </Space>
        {(metrics?.by_dimension?.supply_chain ?? 0) === 0 && (
          <Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
            供应链安全维度为 0：本系统未加载第三方 MCP / Skill 组件，该维度无数据——如实呈现而非省略。
          </Paragraph>
        )}
      </Card>

      {/* ---------- 过滤 + 日志流 ---------- */}
      <Card
        size="small"
        title={`安全日志（${filtered.length} / ${logs.length} 条）`}
        extra={
          <Space>
            <Select
              size="small" style={{ width: 150 }} placeholder="全部阶段" allowClear value={stageFilter || undefined}
              onChange={(value) => setStageFilter(value || '')}
              options={[
                ...Object.entries(STAGE_META).map(([value, meta]) => ({ value, label: meta.label })),
                { value: 'taint', label: TAINT_META.label },
              ]}
            />
            <Select
              size="small" style={{ width: 140 }} placeholder="全部决策" allowClear value={decisionFilter || undefined}
              onChange={(value) => setDecisionFilter(value || '')}
              options={Object.entries(DECISION_META).map(([value, meta]) => ({ value, label: meta.label }))}
            />
            <Input
              size="small" style={{ width: 180 }} placeholder="按 trace_id 搜索" allowClear
              value={traceFilter} onChange={(event) => setTraceFilter(event.target.value)}
            />
          </Space>
        }
      >
        {filtered.length === 0 ? (
          <Empty description={logs.length === 0 ? '暂无安全日志。发起一次问答或工具调用后即可看到。' : '没有匹配的日志'} />
        ) : (
          <div style={{ maxHeight: 520, overflowY: 'auto' }}>
            {filtered.map((line, index) => {
              const meta = stageOf(line)
              const decision = decisionOf(line.decision)
              const isProblem = line.decision === 'block'
              return (
                <div
                  key={`${line.trace_id}-${line.ts}-${index}`}
                  onClick={() => void openEvidence(line.trace_id)}
                  style={{
                    display: 'flex', gap: 12, padding: '10px 12px', marginBottom: 6, cursor: 'pointer',
                    borderLeft: `4px solid ${meta.color}`,
                    background: isProblem ? '#fff1f0' : '#fafafa',
                    borderRadius: 4,
                  }}
                >
                  <div style={{ minWidth: 108 }}>
                    <Tag color={meta.color} style={{ marginBottom: 4 }}>{meta.label}</Tag>
                    <div><Text type="secondary" style={{ fontSize: 12 }}>{formatTime(line.ts)}</Text></div>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <Space size={6} wrap style={{ marginBottom: 4 }}>
                      <Tag color={decision.color}>{decision.label}</Tag>
                      {line.tool_name ? <Tag>{line.tool_name}</Tag> : null}
                      {(line.labels || []).map((label) => <Tag key={label} color="default">{label}</Tag>)}
                      {line.risk_level ? <Tag color={line.risk_level === 'high' || line.risk_level === 'critical' ? 'red' : 'default'}>风险 {line.risk_level}</Tag> : null}
                    </Space>
                    {(line.evidence || []).slice(0, 2).map((item, evidenceIndex) => (
                      <Paragraph key={evidenceIndex} type="secondary" ellipsis={{ rows: 1 }} style={{ marginBottom: 0, fontSize: 12 }}>
                        依据：{item}
                      </Paragraph>
                    ))}
                    <Text type="secondary" style={{ fontSize: 12 }}>trace: {line.trace_id || '-'}</Text>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Tooltip title="导出该任务链的审计证据包">
                      <FileSearchOutlined />
                    </Tooltip>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      {/* ---------- 审计证据包 ---------- */}
      <Drawer
        width={720}
        open={Boolean(evidence) || evidenceLoading}
        onClose={() => setEvidence(null)}
        title={evidence ? `审计证据包 · ${evidence.trace_id}` : '正在导出证据包…'}
      >
        {evidence && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            {integrity && (
              <Alert
                type={integrity.valid ? 'success' : 'error'}
                showIcon
                message={integrity.valid
                  ? `哈希链校验通过（${integrity.event_count} 条事件，未被篡改）`
                  : `哈希链校验失败：第 ${integrity.seq} 条事件已被改动、删除或换序`}
              />
            )}

            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label="事件数">{evidence.summary.event_count}</Descriptions.Item>
              <Descriptions.Item label="最高风险分">{evidence.summary.max_risk_score}</Descriptions.Item>
              <Descriptions.Item label="阻断">{evidence.summary.blocked_count}</Descriptions.Item>
              <Descriptions.Item label="净化">{evidence.summary.modified_count}</Descriptions.Item>
              <Descriptions.Item label="污点标记" span={2}>
                {evidence.taint.flags.length ? evidence.taint.flags.map((flag) => <Tag color="orange" key={flag}>{flag}</Tag>) : <Text type="secondary">无</Text>}
              </Descriptions.Item>
            </Descriptions>

            {firstProblem && (
              <Alert
                type={firstProblem.decision === 'block' ? 'error' : 'warning'}
                showIcon
                message={`问题定位：链路在第 ${firstProblem.seq} 步（${stageOf(firstProblem).label}）${firstProblem.decision === 'block' ? '被阻断' : '被净化'}`}
                description={
                  <div>
                    {(firstProblem.evidence || []).slice(0, 3).map((item, index) => (
                      <div key={index}><Text code>{item}</Text></div>
                    ))}
                  </div>
                }
              />
            )}

            <div>
              <Text strong>完整时间线</Text>
              <Timeline
                style={{ marginTop: 12 }}
                items={evidence.timeline.map((item) => {
                  const meta = stageOf(item)
                  const decision = decisionOf(item.decision)
                  return {
                    color: item.decision === 'block' ? 'red' : (item.decision === 'modified' ? 'blue' : 'gray'),
                    children: (
                      <div>
                        <Space size={6} wrap>
                          <Text type="secondary">seq {item.seq}</Text>
                          <Tag color={meta.color}>{meta.label}</Tag>
                          <Tag color={decision.color}>{decision.label}</Tag>
                          {item.tool_name ? <Tag>{item.tool_name}</Tag> : null}
                          {(item.labels || []).map((label) => <Tag key={label} color="default">{label}</Tag>)}
                        </Space>
                        {(item.evidence || []).slice(0, 3).map((text, index) => (
                          <Paragraph key={index} type="secondary" style={{ margin: '4px 0 0', fontSize: 12 }}>
                            依据：{text}
                          </Paragraph>
                        ))}
                        <Text type="secondary" style={{ fontSize: 11 }}>
                          哈希 {String(item.event_hash || '').slice(0, 16)}… ← 前序 {String(item.previous_event_hash || '∅').slice(0, 16)}
                        </Text>
                      </div>
                    ),
                  }
                })}
              />
            </div>
          </Space>
        )}
      </Drawer>
    </div>
  )
}
