"""命令行供应链扫描：扫描插件/Skill/脚本目录并输出报告。

用法：
    cd backend
    PYTHONPATH=app python app/scripts/scan_plugin.py <目录或文件> [--json]

退出码：0 = 全部通过；1 = 存在评分 >= 80 的组件（可用于 CI 门禁）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from security_tools.supply_chain import scan_component

SCANNABLE_SUFFIXES = {".py"}


def collect_targets(target: Path):
    if target.is_file():
        return [target]
    return sorted(
        path for path in target.rglob("*")
        if path.is_file() and path.suffix in SCANNABLE_SUFFIXES
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="插件/Skill/脚本 供应链静态扫描")
    parser.add_argument("target", help="要扫描的文件或目录")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args()

    root = Path(args.target)
    if not root.exists():
        print(f"路径不存在：{root}", file=sys.stderr)
        return 2

    reports = [
        scan_component(path.read_text(encoding="utf-8", errors="replace"), name=str(path))
        for path in collect_targets(root)
    ]

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
    else:
        print(f"共扫描 {len(reports)} 个组件\n")
        for report in reports:
            # 使用纯 ASCII 标记：部分控制台是 GBK 编码，输出 emoji 会抛 UnicodeEncodeError
            flag = "[BLOCK]" if report.risk_score >= 80 else ("[WARN]" if report.risk_score >= 40 else "[OK]")
            print(f"{flag} {report.name}")
            print(f"   评分={report.risk_score} 等级={report.risk_level} "
                  f"评级={report.rating} 状态={report.status}")
            for finding in report.findings:
                print(f"   - [{finding.rule_id}] {finding.category} "
                      f"({finding.severity}/{finding.side}) 行{finding.lineno}: {finding.evidence[:90]}")
            print()

    worst = max((r.risk_score for r in reports), default=0)
    return 1 if worst >= 80 else 0


if __name__ == "__main__":
    sys.exit(main())
