import { Alert, Button, Card, Checkbox, Input, Space, Tag, Typography, message } from 'antd'
import { SendOutlined } from '@ant-design/icons'
import { useCallback, useEffect, useState } from 'react'
import * as api from '@/api'
import type { ApprovalRequest } from '@/api/security'

const { Text } = Typography

const statusText: Record<string, string> = {
  pending: '等待数据安全专员审批',
  approved: '已批准，正在执行本地模拟递送',
  executed: '已完成本地报告导出与模拟递送',
  rejected: '已拒绝，未生成或递送报告',
  withdrawn: '已撤回，未生成或递送报告',
  failed: '执行失败，未完成递送',
}

export default function ReportDelivery({ sessionId }: { sessionId?: string }) {
  const [title, setTitle] = useState('投标情报分析报告')
  const [content, setContent] = useState('请填写需要导出的报告摘要。审批前不会生成文件，也不会向任何真实外部服务发送内容。')
  const [containsInternalMaterial, setContainsInternalMaterial] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [requests, setRequests] = useState<ApprovalRequest[]>([])

  const refresh = useCallback(async () => {
    try {
      const response = await api.security.getMyApprovals()
      const latest = response.data
        .filter((item) => item.invocation?.tool_name === 'report_export_delivery' && (!sessionId || item.invocation?.trace_id === sessionId))
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
        .slice(0, 1)
      setRequests(latest)
    } catch {
      // 聊天页不因辅助状态查询失败而阻断正常对话。
    }
  }, [sessionId])

  useEffect(() => { void refresh() }, [refresh])

  useEffect(() => {
    const active = requests.some((item) => ['pending', 'claimed', 'approved'].includes(item.status) || ['pending', 'approved'].includes(item.invocation?.status || ''))
    if (!active) return
    const timer = setInterval(() => { void refresh() }, 2000)
    return () => clearInterval(timer)
  }, [requests, refresh])

  const submit = async () => {
    if (!sessionId) {
      message.warning('请先创建或进入一个会话，再发起报告递送申请。')
      return
    }
    if (!content.trim()) {
      message.warning('请填写报告摘要。')
      return
    }
    const existing = requests[0]
    if (existing && !['rejected', 'withdrawn', 'failed'].includes(existing.status) && !['failed'].includes(existing.invocation?.status || '')) {
      message.info('当前会话已有一条报告申请，请等待其完成后再发起新的申请。')
      return
    }
    setSubmitting(true)
    try {
      const response = await api.security.invokeTool({
        tool_name: 'report_export_delivery',
        trace_id: sessionId,
        agent_name: 'tender_intelligence_agent',
        source_type: 'business_report',
        risk_labels: containsInternalMaterial ? ['内部资料', '需要人工复核'] : [],
        params: {
          report_title: title,
          report_content: content,
          summary_preview: content.replace(/\s+/g, ' ').trim().slice(0, 300),
          business_task: '投标情报分析与报告导出',
          delivery_target: 'local_mock_receiver',
        },
      })
      if (response.data.invocation.decision === 'approval_required') {
        message.info('报告已进入审批队列。审批前不会生成文件，也不会发生任何外部发送。')
      } else {
        message.error('报告递送请求被安全策略阻断。')
      }
      await refresh()
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '提交报告递送申请失败')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card size="small" title="报告导出与受控递送" className="report-delivery-card">
      <Space direction="vertical" size={10} style={{ width: '100%' }}>
        <Alert type="info" showIcon message="审批前仅保存申请；批准后只在本机安全目录生成报告和模拟接收回执，不会真实外发。" />
        <Input value={title} maxLength={120} onChange={(event) => setTitle(event.target.value)} placeholder="报告标题" />
        <Input.TextArea value={content} rows={3} maxLength={4000} onChange={(event) => setContent(event.target.value)} placeholder="填写投标分析摘要" />
        <Checkbox checked={containsInternalMaterial} onChange={(event) => setContainsInternalMaterial(event.target.checked)}>
          本报告引用了已审批入库的内部资料
        </Checkbox>
        <Button type="primary" icon={<SendOutlined />} onClick={submit} loading={submitting} disabled={!!requests[0] && !['rejected', 'withdrawn', 'failed'].includes(requests[0].status)}>申请导出并递送到本地模拟接收端</Button>
        {requests.map((item) => (
          <div className="report-delivery-card__status" key={item.id}>
            <Tag color={item.status === 'executed' ? 'green' : item.status === 'pending' ? 'orange' : 'default'}>{item.status}</Tag>
            <Text>{statusText[item.invocation?.status || item.status] || '状态已更新'}</Text>
            {item.invocation?.result_summary && <Text type="secondary">：{item.invocation.result_summary}</Text>}
          </div>
        ))}
      </Space>
    </Card>
  )
}
