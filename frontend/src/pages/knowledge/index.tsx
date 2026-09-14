import { useEffect, useState, useRef } from 'react'
import {
  Card,
  Button,
  List,
  Modal,
  Form,
  Input,
  Upload,
  message,
  Popconfirm,
  Tag,
  Empty,
  Spin,
  Progress,
  Typography,
} from 'antd'
import {
  PlusOutlined,
  DeleteOutlined,
  EditOutlined,
  UploadOutlined,
  FileOutlined,
  FolderOutlined,
  ArrowLeftOutlined,
  ReloadOutlined,
  EyeOutlined,
} from '@ant-design/icons'
import { useSnapshot } from 'valtio'
import { knowledgeState, knowledgeActions, KnowledgeBase, KBDocument } from '@/store/knowledge'
import { getQuarantinedUploads, withdrawQuarantinedUpload, type QuarantinedUpload } from '@/api/knowledge'
import { authState } from '@/store/auth'
import { useNavigate } from 'react-router-dom'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'
import UploadModal, { UploadResult } from '@/components/upload-modal'
import ChunksDrawer from '@/components/chunks-drawer'
import styles from './index.module.scss'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const { Text, Paragraph } = Typography

const STATUS_MAP: Record<string, { color: string; text: string }> = {
  pending: { color: 'default', text: '等待解析' },
  processing: { color: 'processing', text: '处理中' },
  completed: { color: 'success', text: '已完成' },
  failed: { color: 'error', text: '处理失败' },
}

const QUARANTINE_STATUS_MAP: Record<QuarantinedUpload['status'], { color: string; text: string }> = {
  pending: { color: 'warning', text: '隔离待审批' },
  claimed: { color: 'processing', text: '安全专员审核中' },
  approved: { color: 'processing', text: '已批准，处理中' },
  rejected: { color: 'error', text: '已拒绝' },
  withdrawn: { color: 'default', text: '已撤回' },
  closed: { color: 'default', text: '已关闭' },
}

export default function KnowledgePage() {
  const navigate = useNavigate()
  const { knowledgeBases, currentKnowledgeBase, loading, uploading } = useSnapshot(knowledgeState)
  const { isLoggedIn } = useSnapshot(authState)
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingKb, setEditingKb] = useState<KnowledgeBase | null>(null)
  const [form] = Form.useForm()
  const [editForm] = Form.useForm()
  const pollingRef = useRef<NodeJS.Timeout | null>(null)

  // 上传模态框状态
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [uploadingFile, setUploadingFile] = useState('')
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null)

  // 切片查看抽屉状态
  const [chunksDrawerOpen, setChunksDrawerOpen] = useState(false)
  const [selectedDoc, setSelectedDoc] = useState<{ id: string; filename: string } | null>(null)
  const [quarantinedUploads, setQuarantinedUploads] = useState<QuarantinedUpload[]>([])

  const refreshQuarantine = async (kbId: string) => {
    try {
      const result = await getQuarantinedUploads(kbId)
      setQuarantinedUploads(result.data)
    } catch {
      setQuarantinedUploads([])
    }
  }

  useEffect(() => {
    if (isLoggedIn) {
      knowledgeActions.fetchKnowledgeBases()
    }
    return () => {
      knowledgeActions.clearCurrentKnowledgeBase()
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
      }
    }
  }, [isLoggedIn])

  // Polling for document status updates
  useEffect(() => {
    if (currentKnowledgeBase) {
      const hasProcessing = currentKnowledgeBase.documents.some(
        (doc) => doc.status === 'pending' || doc.status === 'processing'
      )
      const hasOpenApproval = quarantinedUploads.some(
        (upload) => upload.status === 'pending' || upload.status === 'claimed'
      )
      if (hasProcessing || hasOpenApproval) {
        pollingRef.current = setInterval(() => {
          knowledgeActions.refreshDocuments(currentKnowledgeBase.id)
          void refreshQuarantine(currentKnowledgeBase.id)
        }, 3000)
      }
    }
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [currentKnowledgeBase?.id, currentKnowledgeBase?.documents, quarantinedUploads])

  if (!isLoggedIn) {
    return (
      <div className={styles['knowledge-page']}>
        <div className={styles['empty-state']}>
          <Empty description="请先登录" />
          <Button type="primary" onClick={() => navigate('/login')}>
            去登录
          </Button>
        </div>
      </div>
    )
  }

  const handleCreateKb = async (values: { name: string; description?: string }) => {
    try {
      await knowledgeActions.createKnowledgeBase(values.name, values.description)
      message.success('知识库创建成功')
      setCreateModalOpen(false)
      form.resetFields()
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '创建失败')
    }
  }

  const handleEditKb = async (values: { name: string; description?: string }) => {
    if (!editingKb) return
    try {
      await knowledgeActions.updateKnowledgeBase(editingKb.id, values.name, values.description)
      message.success('知识库更新成功')
      setEditModalOpen(false)
      setEditingKb(null)
      editForm.resetFields()
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '更新失败')
    }
  }

  const handleDeleteKb = async (kbId: string) => {
    try {
      await knowledgeActions.deleteKnowledgeBase(kbId)
      message.success('知识库删除成功')
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '删除失败')
    }
  }

  const handleKbClick = (kb: KnowledgeBase) => {
    knowledgeActions.fetchKnowledgeBase(kb.id)
    refreshQuarantine(kb.id)
  }

  const handleBackToList = () => {
    knowledgeActions.clearCurrentKnowledgeBase()
  }

  const handleUpload = async (file: File) => {
    if (!currentKnowledgeBase) return false

    // 打开上传模态框
    setUploadModalOpen(true)
    setUploadingFile(file.name)
    setUploadResult(null)

    try {
      const result = await knowledgeActions.uploadDocument(currentKnowledgeBase.id, file)
      await refreshQuarantine(currentKnowledgeBase.id)
      setUploadResult({
        success: true,
        message: '上传成功',
        filename: file.name,
        docId: result?.id,
      })
    } catch (error: any) {
      setUploadResult({
        success: false,
        message: '上传失败',
        filename: file.name,
        error: error?.response?.data?.detail || error?.message || '网络请求失败',
      })
    }
    return false
  }

  // 关闭上传模态框
  const handleCloseUploadModal = () => {
    if (!uploading) {
      setUploadModalOpen(false)
      setUploadResult(null)
      setUploadingFile('')
    }
  }

  // 查看切片
  const handleViewChunks = (doc: KBDocument) => {
    if (doc.status !== 'completed') {
      message.warning('文档尚未处理完成')
      return
    }
    setSelectedDoc({ id: doc.id, filename: doc.filename })
    setChunksDrawerOpen(true)
  }

  // 关闭切片抽屉
  const handleCloseChunksDrawer = () => {
    setChunksDrawerOpen(false)
    setSelectedDoc(null)
  }

  const handleDeleteDocument = async (docId: string) => {
    if (!currentKnowledgeBase) return
    try {
      await knowledgeActions.deleteDocument(currentKnowledgeBase.id, docId)
      message.success('文档删除成功')
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '删除失败')
    }
  }

  const handleWithdrawUpload = async (uploadId: string) => {
    if (!currentKnowledgeBase) return
    try {
      await withdrawQuarantinedUpload(currentKnowledgeBase.id, uploadId)
      await refreshQuarantine(currentKnowledgeBase.id)
      message.success('已撤回隔离申请，可修改文件后重新上传')
    } catch (error: any) {
      message.error(error?.response?.data?.detail || '撤回失败')
    }
  }

  const openEditModal = (kb: KnowledgeBase, e: React.MouseEvent) => {
    e.stopPropagation()
    setEditingKb(kb)
    editForm.setFieldsValue({
      name: kb.name,
      description: kb.description,
    })
    setEditModalOpen(true)
  }

  const renderKbList = () => (
    <div className={styles['kb-list']}>
      <div className={styles['header']}>
        <h2>我的知识库</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
          创建知识库
        </Button>
      </div>

      <Spin spinning={loading}>
        {knowledgeBases.length === 0 ? (
          <div className={styles['empty-state']}>
            <Empty description="暂无知识库" />
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
              创建第一个知识库
            </Button>
          </div>
        ) : (
          <div className={styles['card-grid']}>
            {(knowledgeBases as KnowledgeBase[]).map((kb) => (
              <Card
                key={kb.id}
                className={styles['kb-card']}
                hoverable
                onClick={() => handleKbClick(kb)}
              >
                <div className={styles['card-icon']}>
                  <FolderOutlined />
                </div>
                <div className={styles['card-content']}>
                  <Text strong ellipsis={{ tooltip: kb.name }} className={styles['card-title']}>
                    {kb.name}
                  </Text>
                  <Paragraph
                    type="secondary"
                    ellipsis={{ rows: 2 }}
                    className={styles['card-desc']}
                  >
                    {kb.description || '暂无描述'}
                  </Paragraph>
                  <div className={styles['card-meta']}>
                    <span>{kb.document_count} 个文档</span>
                    <span>{dayjs(kb.updated_at).fromNow()}</span>
                  </div>
                </div>
                <div className={styles['card-actions']}>
                  <Button
                    type="text"
                    size="small"
                    icon={<EditOutlined />}
                    onClick={(e) => openEditModal(kb, e)}
                  />
                  <Popconfirm
                    title="确定删除此知识库？"
                    description="删除后将无法恢复"
                    onConfirm={(e) => {
                      e?.stopPropagation()
                      handleDeleteKb(kb.id)
                    }}
                    onCancel={(e) => e?.stopPropagation()}
                  >
                    <Button
                      type="text"
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </Popconfirm>
                </div>
              </Card>
            ))}
          </div>
        )}
      </Spin>
    </div>
  )

  const renderKbDetail = () => {
    if (!currentKnowledgeBase) return null
    // 已批准资料已由下方正式文档列表展示；这里仅保留仍可等待或处理的隔离申请。
    const activeQuarantinedUploads = quarantinedUploads.filter(
      (upload) => upload.status === 'pending' || upload.status === 'claimed'
    )

    return (
      <div className={styles['kb-detail']}>
        <div className={styles['header']}>
          <div className={styles['header-left']}>
            <Button type="text" icon={<ArrowLeftOutlined />} onClick={handleBackToList}>
              返回
            </Button>
            <h2>{currentKnowledgeBase.name}</h2>
            <Text type="secondary">({currentKnowledgeBase.document_count} 个文档)</Text>
          </div>
          <div className={styles['header-right']}>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                knowledgeActions.refreshDocuments(currentKnowledgeBase.id)
                void refreshQuarantine(currentKnowledgeBase.id)
              }}
            >
              刷新
            </Button>
            <Upload
              beforeUpload={handleUpload}
              showUploadList={false}
              accept=".pdf,.doc,.docx,.txt,.md,.html,.xlsx,.xls,.pptx,.ppt,.jpg,.jpeg,.png,.gif,.webp,.bmp,.py,.js,.ts,.json,.yaml,.yml,.xml,.csv"
            >
              <Button type="primary" icon={<UploadOutlined />} loading={uploading}>
                上传文档
              </Button>
            </Upload>
          </div>
        </div>

        {currentKnowledgeBase.description && (
          <Paragraph type="secondary" className={styles['description']}>
            {currentKnowledgeBase.description}
          </Paragraph>
        )}

        {activeQuarantinedUploads.length > 0 && (
          <Card size="small" title="资料入库审批队列" style={{ marginBottom: 16 }}>
            <List
              size="small"
              dataSource={activeQuarantinedUploads}
              renderItem={(upload) => (
                <List.Item
                  actions={upload.status === 'pending' ? [
                    <Popconfirm key="withdraw" title="撤回后该文件不会进入知识库" onConfirm={() => handleWithdrawUpload(upload.id)}>
                      <Button type="link" size="small">撤回并修改</Button>
                    </Popconfirm>,
                  ] : []}
                >
                  <List.Item.Meta
                    title={<><Text>{upload.filename}</Text> <Tag color={QUARANTINE_STATUS_MAP[upload.status].color}>{QUARANTINE_STATUS_MAP[upload.status].text}</Tag></>}
                    description={`文件先在隔离区保存；${dayjs(upload.created_at).format('YYYY-MM-DD HH:mm')}`}
                  />
                </List.Item>
              )}
            />
          </Card>
        )}

        <Spin spinning={loading}>
          {currentKnowledgeBase.documents.length === 0 ? (
            <div className={styles['empty-state']}>
              <Empty description="暂无文档" />
              <Upload
                beforeUpload={handleUpload}
                showUploadList={false}
                accept=".pdf,.doc,.docx,.txt,.md,.html,.xlsx,.xls,.pptx,.ppt,.jpg,.jpeg,.png,.gif,.webp,.bmp,.py,.js,.ts,.json,.yaml,.yml,.xml,.csv"
              >
                <Button type="primary" icon={<UploadOutlined />}>
                  上传第一个文档
                </Button>
              </Upload>
            </div>
          ) : (
            <List
              className={styles['doc-list']}
              dataSource={currentKnowledgeBase.documents as KBDocument[]}
              renderItem={(doc) => (
                <List.Item
                  className={styles['doc-item']}
                  actions={[
                    <Button
                      key="view"
                      type="text"
                      size="small"
                      icon={<EyeOutlined />}
                      onClick={() => handleViewChunks(doc)}
                      disabled={doc.status !== 'completed'}
                      title="查看切片"
                    />,
                    <Popconfirm
                      key="delete"
                      title="确定删除此文档？"
                      onConfirm={() => handleDeleteDocument(doc.id)}
                    >
                      <Button type="text" danger size="small" icon={<DeleteOutlined />} />
                    </Popconfirm>,
                  ]}
                >
                  <List.Item.Meta
                    avatar={<FileOutlined style={{ fontSize: 24, color: '#1890ff' }} />}
                    title={
                      <div className={styles['doc-title']}>
                        <Text ellipsis={{ tooltip: doc.filename }}>{doc.filename}</Text>
                        <Tag color={STATUS_MAP[doc.status]?.color}>
                          {STATUS_MAP[doc.status]?.text}
                        </Tag>
                      </div>
                    }
                    description={
                      <div className={styles['doc-meta']}>
                        <span>
                          {doc.file_type?.toUpperCase()} · {formatFileSize(doc.file_size)}
                        </span>
                        {doc.status === 'completed' && (
                          <span
                            className={styles['chunk-link']}
                            onClick={() => handleViewChunks(doc)}
                          >
                            {doc.chunk_count} 个切片
                          </span>
                        )}
                        {doc.status === 'processing' && (
                          <Progress percent={30} size="small" style={{ width: 100 }} />
                        )}
                        {doc.status === 'failed' && doc.error_message && (
                          <Text type="danger" style={{ fontSize: 12 }}>
                            {doc.error_message}
                          </Text>
                        )}
                        <span>{dayjs(doc.created_at).fromNow()}</span>
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          )}
        </Spin>
      </div>
    )
  }

  return (
    <div className={styles['knowledge-page']}>
      {currentKnowledgeBase ? renderKbDetail() : renderKbList()}

      <Modal
        title="创建知识库"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false)
          form.resetFields()
        }}
        footer={null}
      >
        <Form form={form} layout="vertical" onFinish={handleCreateKb} autoComplete="off">
          <Form.Item
            name="name"
            label="知识库名称"
            rules={[{ required: true, message: '请输入知识库名称' }]}
          >
            <Input placeholder="请输入知识库名称" maxLength={255} autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea placeholder="请输入知识库描述（可选）" rows={3} autoComplete="off" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Button onClick={() => setCreateModalOpen(false)} style={{ marginRight: 8 }}>
              取消
            </Button>
            <Button type="primary" htmlType="submit">
              创建
            </Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="编辑知识库"
        open={editModalOpen}
        onCancel={() => {
          setEditModalOpen(false)
          setEditingKb(null)
          editForm.resetFields()
        }}
        footer={null}
      >
        <Form form={editForm} layout="vertical" onFinish={handleEditKb} autoComplete="off">
          <Form.Item
            name="name"
            label="知识库名称"
            rules={[{ required: true, message: '请输入知识库名称' }]}
          >
            <Input placeholder="请输入知识库名称" maxLength={255} autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea placeholder="请输入知识库描述（可选）" rows={3} autoComplete="off" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Button
              onClick={() => {
                setEditModalOpen(false)
                setEditingKb(null)
                editForm.resetFields()
              }}
              style={{ marginRight: 8 }}
            >
              取消
            </Button>
            <Button type="primary" htmlType="submit">
              保存
            </Button>
          </Form.Item>
        </Form>
      </Modal>

      {/* 上传进度模态框 */}
      <UploadModal
        open={uploadModalOpen}
        uploading={uploading}
        result={uploadResult}
        filename={uploadingFile}
        onClose={handleCloseUploadModal}
      />

      {/* 切片查看抽屉 */}
      <ChunksDrawer
        open={chunksDrawerOpen}
        kbId={currentKnowledgeBase?.id || ''}
        docId={selectedDoc?.id || ''}
        filename={selectedDoc?.filename || ''}
        onClose={handleCloseChunksDrawer}
      />
    </div>
  )
}

function formatFileSize(bytes?: number): string {
  if (!bytes) return '未知'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
