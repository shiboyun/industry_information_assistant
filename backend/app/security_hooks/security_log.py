"""结构化安全日志（方向四：审计与安全日志）。

形态选择：**JSON Lines 追加写文件**。理由：
- 它是"安全日志"的标准形态，可直接被 SIEM / ELK / Filebeat 采集；
- 不依赖数据库会话——聊天与工具调用链路拿不到 db 会话（`db=None`），
  此前这些链路的审计只落在内存里，**重启即丢**；
- 与哈希链审计互补：哈希链解决"防篡改与完整性验证"，本模块解决"可采集、可检索、可导出"。

写入时机：由 hook 层的**唯一汇聚点**触发（`pipeline._record_hook_event`
与 `pipeline._append_taint_event`），因此七个业务入口一经接入即全覆盖，
无需在各处重复埋点。

失败处理：写日志失败**绝不阻断业务**，与既有审计失败的处理保持一致。
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_PATH = _PROJECT_ROOT / "logs" / "security_events.jsonl"

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_TAIL_BUFFER = 2000

# 每条日志都必须具备的字段，便于下游稳定解析
REQUIRED_FIELDS = ("ts", "event_type", "trace_id", "stage", "decision", "risk_level", "labels")


class SecurityLog:
    """追加式 JSON Lines 安全日志（带大小上限与内存环形缓冲）。"""

    def __init__(
        self,
        path: Optional[Path] = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        enabled: bool = True,
    ):
        self.path = Path(path) if path else DEFAULT_LOG_PATH
        self.max_bytes = max(1024, int(max_bytes))
        self.enabled = enabled
        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=_TAIL_BUFFER)
        self._lock = threading.Lock()

    # ---- 写 ----

    def write(self, event_type: str, payload: Dict[str, Any], trace_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        record: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            # trace 归属依次回退：显式参数 → 载荷顶层 → 载荷 metadata
            "trace_id": trace_id or payload.get("trace_id") or metadata.get("trace_id") or "",
        }
        for key, value in payload.items():
            record.setdefault(key, value)
        record["pid"] = os.getpid()

        with self._lock:
            self._buffer.append(record)
            self._append_to_file(record)
        return record

    def _append_to_file(self, record: Dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception:
            # 磁盘满/权限不足等不应影响业务；错误可见即可
            logger.exception("安全日志写入失败：path=%s", self.path)

    def _rotate_if_needed(self) -> None:
        try:
            if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
                return
            rotated = self.path.with_suffix(self.path.suffix + ".1")
            if rotated.exists():
                rotated.unlink()
            self.path.rename(rotated)
        except Exception:
            logger.exception("安全日志轮转失败：path=%s", self.path)

    # ---- 读 ----

    def tail(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._buffer)
        return items[-max(0, int(limit)):]

    def query(self, trace_id: str, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            items = [item for item in self._buffer if item.get("trace_id") == trace_id]
        return items[-max(0, int(limit)):]

    def reset(self) -> None:
        """清空缓冲并截断文件——仅供测试使用。"""
        with self._lock:
            self._buffer.clear()
            try:
                if self.path.exists():
                    self.path.write_text("", encoding="utf-8")
            except Exception:
                logger.exception("安全日志重置失败：path=%s", self.path)


_security_log = SecurityLog()


def get_security_log() -> SecurityLog:
    return _security_log
