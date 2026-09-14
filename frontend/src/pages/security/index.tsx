import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Alert, Button, Card, Descriptions, Empty, Input, List, Modal, Select, Space, Spin, Tag, Timeline, Typography, message } from 'antd'
import { CheckOutlined, CloseOutlined, EyeOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import * as api from '@/api'
import type { ApprovalRequest, SecurityRole, ToolInvocation } from '@/api/security'

const { Text, Paragraph } = Typography

const riskColor: Record<string, string> = { low: 'green', medium: 'gold', high: 'orange', critical: 'red' }
const approvalStatusColor: Record<string, string> = {
  pending: 'orange', claimed: 'blue', approved: 'green', rejected: 'red', withdrawn: 'default', closed: 'default',
}
const statusText: Record<string, string> = {
  pending: '待领取', claimed: '已领取', approved: '已批准', rejected: '已拒绝', withdrawn: '已撤回', closed: '已关闭', executed: '已执行', failed: '执行失败',
}
const toolText: Record<string, string> = {
  knowledge_base_ingest: '资料隔离入库', report_export_delivery: '报告导出与模拟递送', code_execution: '受限代码执行',
  sandbox_file_write: '受限文件写入', sandbox_command: '白名单命令',
}
const eventText: Record<string, string> = {
  tool_authorized: '策略已完成判断', approval_requested: '已提交人工审批', approval_claimed: '安全专员已领取',
  approval_approved: '审批已通过', approval_rejected: '审批已拒绝', approval_withdrawn: '发起人已撤回',
  approval_closed: '安全管理员已关闭', tool_executed: '受控操作已完成', tool_failed: '受控操作执行失败',
}

function formatTime(value?: string) {
  if (!value) return '-'
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(new Date(value))
}

function summarizeParams(params: Record<string, unknown> = {}) {
  return Object.entries(params).filter(([key]) => !['report_content', 'content', 'code'].includes(key)).map(([key, value]) => `${key}: ${String(value)}`).join('；') || '无额外参数'
}

function approvalOutcomeText(approval: ApprovalRequest) {
  if (approval.status === 'approved') return approval.comment || '审批已通过，受控资料已进入正式处理流程。'
  if (approval.status === 'rejected') return approval.comment || '审批已拒绝，目标操作不会执行。'
  if (approval.status === 'withdrawn') return approval.comment || '发起人已撤回，目标操作不会执行。'
  if (approval.status === 'closed') return approval.comment || '安全管理员已关闭，目标操作不会执行。'
  return approval.invocation?.evidence?.join('；') || '等待人工复核'
}

export default function SecurityPage() {
  const navigate = useNavigate()
  const [role, setRole] = useState<SecurityRole | null>(null)
  const [currentUserId, setCurrentUserId] = useState('')
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [refreshing, setRefreshing] = useState(false)
  const [selected, setSelected] = useState<ApprovalRequest | null>(null)
  const [comment, setComment] = useState('')
  const [actingId, setActingId] = useState<string | null>(null)
  const [showAllMine, setShowAllMine] = useState(false)
  const [showAllPending, setShowAllPending] = useState(false)
  const decisionLockRef = useRef<string | null>(null)
  const [filters, setFilters] = useState({ statuses: '', tool_name: '', requester_id: '', risk_level: '' })
  const [trace, setTrace] = useState<Awaited<ReturnType<typeof api.security.getTrace>>['data'] | null>(null)
  const traceRef = useRef<HTMLDivElement | null>(null)

  const refresh = useCallback(async (showLoading = true) => {
    if (showLoading) setRefreshing(true)
    try {
      const me = await api.security.getSecurityMe()
      if (me.data.role === 'operator') {
        message.info('安全专员工作台仅供数据安全专员和安全管理员使用。')
        navigate('/chat', { replace: true })
        return
      }
      setRole(me.data.role)
      setCurrentUserId(me.data.user_id)
      const result = await api.security.getApprovals({
        statuses: filters.statuses,
        tool_name: filters.tool_name || undefined,
        requester_id: filters.requester_id || undefined,
        risk_level: filters.risk_level || undefined,
      })
      setApprovals(result.data)
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '无法加载审批队列，请检查后端服务后重试。')
    } finally {
      if (showLoading) setRefreshing(false)
    }
  }, [filters, navigate])

  useEffect(() => { void refresh() }, [refresh])

  useEffect(() => {
    const timer = window.setInterval(() => { void refresh(false) }, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const isAdmin = role === 'security_admin'

  const claim = async (approval: ApprovalRequest) => {
    setActingId(approval.id)
    try {
      const result = await api.security.claimApproval(approval.id)
      message.success('已领取该审批请求，其他审批员将只能查看。')
      setSelected(result.data.approval)
      await refresh()
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '领取失败，该请求可能已被其他审批员处理。')
    } finally { setActingId(null) }
  }

  const decide = async (approved: boolean) => {
    if (!selected) return
    // 在 React 更新 loading 状态前阻止双击或连续点击产生第二次审批请求。
    if (decisionLockRef.current === selected.id) return
    decisionLockRef.current = selected.id
    setActingId(selected.id)
    try {
      await api.security.decideApproval(selected.id, approved, comment || (approved ? '安全专员审核通过' : '安全专员审核拒绝'))
      message.success(approved ? '审批已通过，资料正在后台入库，可继续处理其他申请。' : '已拒绝，该操作不会执行。')
      setComment('')
      setSelected(null)
      void refresh(false)
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '审批失败，请确认该请求由当前账号领取。')
    } finally {
      decisionLockRef.current = null
      setActingId(null)
    }
  }

  const close = async () => {
    if (!selected) return
    setActingId(selected.id)
    try {
      await api.security.closeApproval(selected.id, comment || '安全管理员关闭该请求')
      message.success('请求已关闭，不会执行受控操作。')
      setComment('')
      setSelected(null)
      await refresh()
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '关闭失败。')
    } finally { setActingId(null) }
  }

  const loadTrace = async (approval: ApprovalRequest) => {
    const traceId = approval.invocation?.trace_id
    if (!traceId) return
    try {
      const result = await api.security.getTrace(traceId)
      setTrace(result.data)
      setSelected(null)
      window.setTimeout(() => traceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0)
    } catch {
      message.error('无法读取该业务任务的审计时间线。')
    }
  }

  const detail = selected?.invocation
  const isClaimedByCurrentUser = selected?.status === 'claimed' && selected.claimant_id === currentUserId
  const myApprovals = approvals.filter((item) => item.claimant_id === currentUserId)
  const visibleMyApprovals = showAllMine ? myApprovals : myApprovals.slice(0, 5)
  const pendingApprovals = approvals.filter((item) => item.status === 'pending')
  const visiblePendingApprovals = showAllPending ? pendingApprovals : pendingApprovals.slice(0, 5)

  const renderApprovalItem = (item: ApprovalRequest, showClaim = false) => (
    <List.Item actions={[
      <Button key="detail" size="small" icon={<EyeOutlined />} onClick={() => { setSelected(item); setComment('') }}>查看材料</Button>,
      ...(showClaim && item.status === 'pending' ? [<Button key="claim" type="primary" size="small" loading={actingId === item.id} onClick={() => void claim(item)}>领取</Button>] : []),
    ]}>
      <List.Item.Meta
        title={<Space><Text strong>{toolText[item.invocation?.tool_name || ''] || item.invocation?.tool_name || '受控操作'}</Text><Tag color={riskColor[item.invocation?.risk_level || 'high']}>{item.invocation?.risk_level}</Tag><Tag color={approvalStatusColor[item.status] || 'default'}>{statusText[item.status] || item.status}</Tag></Space>}
        description={<Space direction="vertical" size={1}><Text type="secondary">发起人：{item.requester_name || item.requester_id || '系统'}；提交时间：{formatTime(item.created_at)}</Text><Text>{approvalOutcomeText(item)}</Text>{item.claimant_name && <Text type="secondary">已由 {item.claimant_name} 于 {formatTime(item.claimed_at)} 领取</Text>}</Space>}
      />
    </List.Item>
  )

  if (role === null) return <div style={{ padding: 48, textAlign: 'center' }}><Spin tip="正在核验安全角色..." /></div>

  return <div style={{ padding: 24, maxWidth: 1320, margin: '0 auto' }}>
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div><h2 style={{ marginBottom: 4 }}>数据安全专员工作台</h2><Text type="secondary">审核资料入库与智能体高风险行动，所有判断均保留可验证审计链。</Text></div>
        <Space><Tag color="blue">{role === 'security_admin' ? '安全管理员' : '数据安全专员'}</Tag><Button icon={<ReloadOutlined />} onClick={() => void refresh()} loading={refreshing}>刷新队列</Button></Space>
      </div>
      <Alert showIcon type="info" icon={<SafetyCertificateOutlined />} message="原始资料和报告正文不会在此页面展示或下载。请依据受控预览、业务上下文、风险证据和影响范围完成审核。" />
      <Card title="审批队列" extra={<Text type="secondary">共 {approvals.length} 条，5 秒自动更新</Text>}>
        <Space wrap style={{ marginBottom: 16 }}>
          <Select value={filters.statuses} style={{ width: 170 }} onChange={(value) => setFilters((old) => ({ ...old, statuses: value }))} options={[{ value: '', label: '全部状态' }, { value: 'pending', label: '仅待领取' }, { value: 'claimed', label: '仅审核中' }, { value: 'approved,rejected,withdrawn,closed', label: '已结束记录' }]} />
          <Select allowClear placeholder="工具类型" style={{ width: 190 }} value={filters.tool_name || undefined} onChange={(value) => setFilters((old) => ({ ...old, tool_name: value || '' }))} options={Object.entries(toolText).map(([value, label]) => ({ value, label }))} />
          <Select allowClear placeholder="风险等级" style={{ width: 130 }} value={filters.risk_level || undefined} onChange={(value) => setFilters((old) => ({ ...old, risk_level: value || '' }))} options={['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))} />
          <Input placeholder="发起人 ID" value={filters.requester_id} onChange={(event) => setFilters((old) => ({ ...old, requester_id: event.target.value }))} style={{ width: 220 }} />
          <Button onClick={() => void refresh()}>应用筛选</Button>
        </Space>
        <div style={{ marginBottom: 16 }}>
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <Text strong>待领取申请（{pendingApprovals.length}）</Text>
            {pendingApprovals.length > 5 && <Button type="link" size="small" onClick={() => setShowAllPending((value) => !value)}>{showAllPending ? '收起记录' : '展开全部'}</Button>}
          </Space>
          <List loading={refreshing} locale={{ emptyText: <Empty description="当前没有待领取申请" /> }} dataSource={visiblePendingApprovals} renderItem={(item) => renderApprovalItem(item, true)} />
        </div>
        <div>
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <Text strong>我的审批记录（{myApprovals.length}）</Text>
            {myApprovals.length > 5 && <Button type="link" size="small" onClick={() => setShowAllMine((value) => !value)}>{showAllMine ? '收起记录' : '展开全部'}</Button>}
          </Space>
          <List loading={refreshing} locale={{ emptyText: <Empty description="你还没有领取过审批申请" /> }} dataSource={visibleMyApprovals} renderItem={(item) => renderApprovalItem(item)} />
        </div>
      </Card>
      <Modal
        open={Boolean(selected)}
        title="审批材料"
        width={980}
        style={{ top: 32 }}
        footer={null}
        destroyOnClose
        onCancel={() => { if (!actingId) setSelected(null) }}
      >
      {selected && <>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}><Button onClick={() => void loadTrace(selected)}>查看任务链审计</Button></div>
        <Descriptions bordered size="small" column={2}>
          <Descriptions.Item label="业务动作">{toolText[detail?.tool_name || ''] || detail?.tool_name}</Descriptions.Item><Descriptions.Item label="策略">{detail?.policy_id}</Descriptions.Item>
          <Descriptions.Item label="发起人">{selected.requester_name || selected.requester_id || '系统'}</Descriptions.Item><Descriptions.Item label="风险">{detail?.risk_level} / {detail?.risk_score}</Descriptions.Item>
          <Descriptions.Item label="业务上下文" span={2}>{String(detail?.safe_params?.business_task || detail?.safe_params?.knowledge_base_name || '未填写业务任务')}</Descriptions.Item>
          <Descriptions.Item label="受控预览" span={2}>{String(detail?.safe_params?.summary_preview || detail?.safe_params?.preview_text || detail?.safe_params?.file_name || '未提供可预览内容')}</Descriptions.Item>
          <Descriptions.Item label="影响范围" span={2}>{String(detail?.safe_params?.impact_scope || detail?.safe_params?.delivery_target || detail?.safe_params?.knowledge_base_name || '仅影响项目本地受控环境')}</Descriptions.Item>
          <Descriptions.Item label="风险证据" span={2}>{detail?.evidence?.join('；') || '无额外证据'}</Descriptions.Item>
          <Descriptions.Item label="参数摘要" span={2}>{summarizeParams(detail?.safe_params)}</Descriptions.Item>
        </Descriptions>
        <Space direction="vertical" style={{ width: '100%', marginTop: 16 }}>
          <Input.TextArea value={comment} onChange={(event) => setComment(event.target.value)} rows={3} maxLength={500} placeholder="填写审批意见或关闭原因（将写入审计链）" />
          {selected.status === 'claimed' && <Alert type="info" message={selected.claimant_name ? `该请求已由 ${selected.claimant_name} 领取。仅领取人可批准或拒绝。` : '已领取，等待领取人处理。'} />}
          {selected.status === 'claimed' && isClaimedByCurrentUser && <Space><Button type="primary" icon={<CheckOutlined />} loading={actingId === selected.id} onClick={() => void decide(true)}>批准并执行一次</Button><Button danger icon={<CloseOutlined />} loading={actingId === selected.id} onClick={() => void decide(false)}>拒绝</Button></Space>}
          {isAdmin && (selected.status === 'pending' || selected.status === 'claimed') && <Button danger loading={actingId === selected.id} onClick={() => void close()}>管理员关闭请求</Button>}
        </Space>
      </>}
      </Modal>
      {trace && <div ref={traceRef}><Card title="任务链审计时间线" extra={<Tag color={trace.integrity.valid ? 'green' : 'red'}>{trace.integrity.valid ? '哈希链校验通过' : '哈希链校验失败'}</Tag>}>
        <Timeline items={trace.events.map((event) => ({ children: <Space direction="vertical" size={1}><Text strong>{eventText[event.event_type] || event.event_type}</Text><Text type="secondary">{formatTime(event.created_at)}</Text><Text>{String(event.payload?.comment || event.payload?.result_summary || event.payload?.decision || '')}</Text><Text code>事件哈希：{event.event_hash.slice(0, 16)}...</Text></Space> }))} />
        <Paragraph type="secondary">此任务链包含 {trace.integrity.event_count} 个安全事件。完整哈希用于事后完整性核验，页面优先展示人可读的业务过程。</Paragraph>
      </Card></div>}
    </Space>
  </div>
}
