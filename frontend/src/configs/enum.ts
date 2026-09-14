export enum ChatRole {
  User = 'user',
  Assistant = 'assistant',
}

export enum ChatType {
  Normal = 'normal',
  Deepsearch = 'deepsearch',
  // 工具调用问答：模型按需调用知识库/联网/Text2SQL 等工具后再回答。
  // 与 Normal 的区别是链路不同（工具调用会经过工具安全网关与审批），
  // 与 Deepsearch 的区别是不做子问题规划与研究报告生成。
  ToolQA = 'toolqa',
}
