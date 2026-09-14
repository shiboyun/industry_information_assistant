import { useEffect, useRef, useState } from 'react'
import { Button, Card, Col, DatePicker, Descriptions, Empty, Form, Input, List, Modal, Popconfirm, Row, Select, Space, Steps, Tag, Typography, message } from 'antd'
import { DeleteOutlined, FileSearchOutlined, PlusOutlined, SaveOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import * as api from '@/api'
import type { EvidenceOption, EvidenceType, TenderAnalysisTask } from '@/api/tender-analysis'

const { Text, Paragraph } = Typography
const sourceMeta: Record<EvidenceType, { name: string; color: string }> = {
  knowledge_document: { name: '已审批内部资料', color: 'blue' },
  bidding: { name: '本地招投标记录', color: 'gold' },
  news: { name: '本地行业资讯', color: 'green' },
}

export default function TenderAnalysisPage() {
  const [tasks, setTasks] = useState<TenderAnalysisTask[]>([])
  const [selected, setSelected] = useState<TenderAnalysisTask | null>(null)
  const [options, setOptions] = useState<{ documents: EvidenceOption[]; bidding: EvidenceOption[]; news: EvidenceOption[] }>({ documents: [], bidding: [], news: [] })
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const submitLockRef = useRef(false)
  const [form] = Form.useForm()
  const [draft, setDraft] = useState('')
  const [verification, setVerification] = useState('')

  const refresh = async () => {
    setLoading(true)
    try {
      const [taskResult, optionResult] = await Promise.all([api.tenderAnalysis.getTenderTasks(), api.tenderAnalysis.getAvailableEvidence()])
      setTasks(taskResult)
      setOptions(optionResult)
      if (selected) {
        const result = await api.tenderAnalysis.getTenderTask(selected.id)
        setSelected(result); setDraft(result.conclusion_draft); setVerification(result.verification_items)
      }
    } catch (error: any) { message.error(error?.response?.data?.detail || '无法读取投标分析任务') }
    finally { setLoading(false) }
  }

  useEffect(() => { void refresh() }, [])

  const openTask = async (task: TenderAnalysisTask) => {
    try {
      const result = await api.tenderAnalysis.getTenderTask(task.id)
      setSelected(result); setDraft(result.conclusion_draft); setVerification(result.verification_items)
    } catch (error: any) { message.error(error?.response?.data?.detail || error?.message || '无法读取任务详情') }
  }

  const submitCreate = async (values: any) => {
    if (submitLockRef.current) return
    submitLockRef.current = true
    setSaving(true)
    try {
      const evidence = [
        ...(values.documents || []).map((source_id: string) => ({ source_type: 'knowledge_document' as const, source_id })),
        ...(values.bidding || []).map((source_id: string) => ({ source_type: 'bidding' as const, source_id })),
        ...(values.news || []).map((source_id: string) => ({ source_type: 'news' as const, source_id })),
      ]
      const result = await api.tenderAnalysis.createTenderTask({
        project_name: values.project_name, analysis_goal: values.analysis_goal,
        deadline: values.deadline?.toISOString(), public_scope: values.public_scope, evidence,
      })
      setCreateOpen(false); form.resetFields(); message.success('投标分析任务已创建，已记录所选依据')
      setTasks((old) => [result, ...old.filter((item) => item.id !== result.id)])
      try {
        const detail = await api.tenderAnalysis.getTenderTask(result.id)
        setSelected(detail)
        setDraft(detail.conclusion_draft || '')
        setVerification(detail.verification_items || '')
      } catch (detailError: any) {
        message.warning(detailError?.response?.data?.detail || detailError?.message || '任务已创建，但详情暂时无法打开')
      }
    } catch (error: any) { message.error(error?.response?.data?.detail || error?.message || '创建任务失败') }
    finally { setSaving(false); submitLockRef.current = false }
  }

  const saveDraft = async () => {
    if (!selected) return
    setSaving(true)
    try {
      const result = await api.tenderAnalysis.updateTenderDraft(selected.id, { conclusion_draft: draft, verification_items: verification })
      setSelected({ ...selected, ...result }); message.success('结论草稿已保存')
      setTasks((old) => old.map((item) => item.id === result.id ? { ...item, ...result } : item))
    } catch { message.error('保存草稿失败') }
    finally { setSaving(false) }
  }

  const removeTask = async (task: TenderAnalysisTask) => {
    try {
      await api.tenderAnalysis.deleteTenderTask(task.id)
      setTasks((old) => old.filter((item) => item.id !== task.id))
      message.success('任务已删除')
    } catch (error: any) { message.error(error?.response?.data?.detail || '删除任务失败') }
  }

  if (selected) return <div style={{ padding: 24, maxWidth: 1280, margin: '0 auto' }}>
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div><Button type="link" onClick={() => setSelected(null)}>返回任务列表</Button><h2 style={{ margin: '6px 0' }}>{selected.project_name}</h2><Text type="secondary">任务追踪号：{selected.trace_id}</Text></div>
        <Tag color={selected.status === 'draft_ready' ? 'green' : 'blue'}>{selected.status === 'draft_ready' ? '结论草稿已保存' : '证据已就绪'}</Tag>
      </div>
      <Card><Descriptions column={2} size="small"><Descriptions.Item label="分析目标" span={2}>{selected.analysis_goal}</Descriptions.Item><Descriptions.Item label="截止日期">{selected.deadline ? dayjs(selected.deadline).format('YYYY-MM-DD') : '未设置'}</Descriptions.Item><Descriptions.Item label="公开资料范围">{selected.public_scope || '使用任务中已选择的本地公开记录'}</Descriptions.Item></Descriptions></Card>
      <Card title="分析步骤"><Steps current={2} items={[{ title: '内部资料检索', description: '仅引用已审批、已完成入库的文档' }, { title: '公开情报引用', description: '仅使用本地已有资讯与招投标记录' }, { title: '结论草稿', description: '可编辑，尚未形成正式报告' }]} /></Card>
      <Card title="本次分析依据"><List dataSource={selected.evidence || []} locale={{ emptyText: '尚未选择依据' }} renderItem={(item) => <List.Item><List.Item.Meta title={<Space><Tag color={sourceMeta[item.source_type].color}>{sourceMeta[item.source_type].name}</Tag><Text strong>{item.title}</Text></Space>} description={<><Paragraph ellipsis={{ rows: 2 }} style={{ marginBottom: 4 }}>{item.summary || '该记录没有可显示摘要。'}</Paragraph><Text type="secondary">{String(item.metadata.security_boundary || '本地记录')}</Text></>} /></List.Item>} /></Card>
      <Card title="分析结论草稿" extra={<Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={() => void saveDraft()}>保存草稿</Button>}>
        <Text type="secondary">此处仅保存任务草稿，不会导出或发送报告。</Text>
        <Input.TextArea value={draft} onChange={(event) => setDraft(event.target.value)} rows={7} maxLength={8000} placeholder="结合已选依据，填写交付要求、机会判断与风险提示。" style={{ marginTop: 12 }} />
        <Text strong style={{ display: 'block', marginTop: 16 }}>待核实事项</Text>
        <Input.TextArea value={verification} onChange={(event) => setVerification(event.target.value)} rows={4} maxLength={4000} placeholder="例如：确认招标公告的最新版本、核对项目预算与交付周期。" style={{ marginTop: 8 }} />
      </Card>
    </Space>
  </div>

  return <div style={{ padding: 24, maxWidth: 1280, margin: '0 auto' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}><div><h2 style={{ marginBottom: 4 }}>投标分析任务</h2><Text type="secondary">把已审批内部资料和本地公开情报组织为一次可追踪的投标分析。</Text></div><Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建任务</Button></div>
    <List
      loading={loading}
      grid={{ gutter: 16, column: 2 }}
      dataSource={tasks}
      locale={{ emptyText: <Empty description="还没有投标分析任务" /> }}
      renderItem={(task) => <List.Item>
        <Card
          title={task.project_name}
          extra={<Tag color={task.status === 'draft_ready' ? 'green' : 'blue'}>{task.status === 'draft_ready' ? '草稿已保存' : '证据已就绪'}</Tag>}
          actions={[
            <Button key="view" type="link" icon={<FileSearchOutlined />} onClick={() => void openTask(task)}>查看详情</Button>,
            <Popconfirm key="delete" title="删除这个投标任务？" description="任务草稿和证据快照会一并删除，此操作不可撤销。" okText="删除" cancelText="取消" okButtonProps={{ danger: true }} onConfirm={() => void removeTask(task)}>
              <Button danger type="link" icon={<DeleteOutlined />}>删除</Button>
            </Popconfirm>,
          ]}
        >
          <Paragraph ellipsis={{ rows: 2 }}>{task.analysis_goal}</Paragraph>
          <Text type="secondary">截止日期：{task.deadline ? dayjs(task.deadline).format('YYYY-MM-DD') : '未设置'}</Text>
        </Card>
      </List.Item>}
    />
    <Modal title="创建投标分析任务" open={createOpen} width={760} onCancel={() => setCreateOpen(false)} onOk={() => form.submit()} confirmLoading={saving} okText="创建并记录依据">
      <Form form={form} layout="vertical" onValuesChange={() => { (document.activeElement as HTMLElement | null)?.blur() }} onFinish={(values) => void submitCreate(values)}>
        <Row gutter={16}><Col span={16}><Form.Item name="project_name" label="项目名称" rules={[{ required: true, message: '请填写项目名称' }]}><Input placeholder="例如：雄安数字城市运维服务投标分析" /></Form.Item></Col><Col span={8}><Form.Item name="deadline" label="截止日期"><DatePicker style={{ width: '100%' }} /></Form.Item></Col></Row>
        <Form.Item name="analysis_goal" label="分析目标" rules={[{ required: true, message: '请说明要解决的问题' }]}><Input.TextArea rows={3} placeholder="例如：识别交付要求、竞争关注点和待核实风险。" /></Form.Item>
        <Form.Item name="public_scope" label="公开资料范围"><Input placeholder="例如：本地已采集的雄安新区数字城市政策与招投标公告" /></Form.Item>
        <Form.Item name="documents" label="已审批内部资料"><Select mode="multiple" allowClear placeholder="只显示本人已完成入库的正式文档" options={options.documents.map((item) => ({ value: item.id, label: item.title }))} /></Form.Item>
        <Form.Item name="bidding" label="本地招投标记录"><Select mode="multiple" allowClear placeholder="选择已存在的本地记录，不会触发采集" options={options.bidding.map((item) => ({ value: item.id, label: item.title }))} /></Form.Item>
        <Form.Item name="news" label="本地行业资讯"><Select mode="multiple" allowClear placeholder="选择已存在的本地记录，不会联网搜索" options={options.news.map((item) => ({ value: item.id, label: item.title }))} /></Form.Item>
      </Form>
    </Modal>
  </div>
}
