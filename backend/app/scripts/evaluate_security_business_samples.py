"""输出投标情报安全闭环的本地业务样例评测指标。"""
import json
import sys
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parents[2] / "test"
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

from security_business_samples import evaluate_samples


if __name__ == "__main__":
    print(json.dumps(evaluate_samples(), ensure_ascii=False, indent=2))
