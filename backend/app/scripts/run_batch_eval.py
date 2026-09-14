# scripts/run_batch_eval.py
import json
import asyncio
import aiohttp
import re
from pathlib import Path
from typing import Dict, Any, List
import argparse

# 路径设置（使用绝对路径）
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent  # backend/
DATA_DIR = PROJECT_ROOT / "app" / "data"

DATASET_PATH = DATA_DIR / "rageval_eval_dataset.json"  # 改为新数据集
TEMP_PATH = DATA_DIR / "eval_dataset_full.json"

# API 地址
CHAT_API_URL = "http://localhost:8000/chat/completion"
SESSION_API_URL = "http://localhost:8000/chat/session"
EVAL_API_URL = "http://localhost:8000/evaluate/batch"


async def get_rag_answer(session: aiohttp.ClientSession, question: str) -> Dict[str, Any]:
    """
    调用 RAG 系统获取答案和上下文（支持 SSE 流式响应）
    """
    # 1. 创建会话
    async with session.post(SESSION_API_URL) as resp:
        if resp.status != 200:
            raise Exception(f"Create session failed: {resp.status}")
        session_data = await resp.json()
        session_id = session_data.get("session_id")
        if not session_id:
            raise Exception("No session_id returned")

    # 2. 提问（流式接口）
    payload = {"session_id": session_id, "question": question}
    async with session.post(CHAT_API_URL, json=payload) as resp:
        if resp.status != 200:
            raise Exception(f"Chat API returned {resp.status}")

        full_answer = ""
        contexts = []
        collected_chunks = []

        async for line in resp.content:
            line = line.decode('utf-8').strip()
            if not line:
                continue
            if line.startswith('data: '):
                data_str = line[6:]
                if data_str == '[DONE]':
                    break
                try:
                    data = json.loads(data_str)
                    if data.get('role') == 'assistant' and 'content' in data:
                        content = data['content']
                        if content:
                            collected_chunks.append(content)
                    if 'documents' in data:
                        docs = data['documents']
                        for doc in docs:
                            if 'content' in doc and doc['content']:
                                contexts.append(doc['content'])
                except json.JSONDecodeError:
                    continue

        full_answer = ''.join(collected_chunks)
        full_answer = re.sub(r'##\d+\$\$', '', full_answer)

        if not full_answer:
            print(f"Warning: No answer received for question: {question[:30]}...")

        return {"answer": full_answer, "contexts": contexts}


async def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="运行 RAG 批量评估")
    parser.add_argument(
        "--dataset",
        type=str,
        default="rageval_eval_dataset.json",
        help="数据集文件名（位于 backend/data/ 下）"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="eval_dataset_full.json",
        help="输出文件名"
    )
    args = parser.parse_args()

    # 设置数据集路径
    dataset_path = DATA_DIR / args.dataset
    temp_path = DATA_DIR / args.output

    # 确保 data 目录存在
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 检查数据集是否存在
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}")
        print(f"可用数据集: {[f.name for f in DATA_DIR.glob('*.json')]}")
        return

    # 1. 读取数据集
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"📋 共加载 {len(dataset)} 条评估样本")

    # 统计各行业分布
    industry_counts = {}
    for item in dataset:
        industry = item.get("industry", "未知")
        industry_counts[industry] = industry_counts.get(industry, 0) + 1
    print(f"📊 行业分布: {json.dumps(industry_counts, ensure_ascii=False)}")

    # 2. 逐个运行 RAG 获取答案
    full_dataset = []
    async with aiohttp.ClientSession() as session:
        for idx, item in enumerate(dataset):
            print(f"Processing [{idx + 1}/{len(dataset)}]: {item.get('question', '')[:50]}...")
            try:
                rag_result = await get_rag_answer(session, item["question"])
            except Exception as e:
                print(f"Error processing question: {e}")
                rag_result = {"answer": "", "contexts": []}

            # 如果 contexts 为空，使用 contexts（如果有）
            if not rag_result.get("contexts") and item.get("contexts"):
                rag_result["contexts"] = item["contexts"]

            full_item = {
                "id": item.get("id", f"q_{idx + 1:03d}"),
                "question": item["question"],
                "answer": rag_result.get("answer", ""),
                "contexts": rag_result.get("contexts", item.get("contexts", [])),
                "ground_truth": item.get("ground_truth", item.get("answer", "")),
                "keypoints": item.get("keypoints", []),  # 🔥 传递 keypoints
                "industry": item.get("industry", "未知"),
                "question_type": item.get("question_type", "Unknown")
            }
            full_dataset.append(full_item)

            # 打印部分答案以供验证
            if full_item["contexts"]:
                print(f"  Contexts count: {len(full_item['contexts'])}")
            answer_preview = full_item["answer"][:100] + "..." if len(full_item["answer"]) > 100 else full_item[
                "answer"]
            print(f"  Answer preview: {answer_preview}")

    # 3. 将完整数据集写入临时文件
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(full_dataset, f, ensure_ascii=False, indent=2)
    print(f"Full dataset saved to {temp_path}")

    # 4. 调用评估接口
    async with aiohttp.ClientSession() as session:
        eval_url = f"{EVAL_API_URL}?file_path={temp_path}"
        async with session.post(eval_url) as resp:
            if resp.status != 200:
                text = await resp.text()
                print(f"Evaluation API error: {resp.status}\n{text}")
                return
            result = await resp.json()
            print("\n" + "=" * 60)
            print("📊 评估结果")
            print("=" * 60)
            print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())