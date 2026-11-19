import time

from config import ScanConfig
from mcp.types import CallToolResult

from .errors import require


class Budget:
    def __init__(self, config: ScanConfig, started: float | None = None):
        self.config = config
        self.started = started if started is not None else time.monotonic()
        self.calls = 0
        self.reply_bytes = 0
        self.memory_bytes = 0
        self.memory_calls = 0
        self.max_read_size = 0

    def remaining(self) -> float:
        left = self.config.total_seconds - (time.monotonic() - self.started)
        require(left > 0, "time_budget_exhausted")
        return min(self.config.rpc_seconds, left)

    def reserve_rpc(self) -> None:
        self.remaining()
        require(self.calls < self.config.rpc_limit, "rpc_budget_exhausted")
        self.calls += 1

    def accept_reply(self, reply: CallToolResult) -> None:
        size = len(reply.model_dump_json().encode("utf-8"))
        require(size <= self.config.max_reply_bytes, "reply_budget_exhausted")
        require(self.reply_bytes + size <= self.config.max_total_reply_bytes,
                "total_reply_budget_exhausted")
        self.reply_bytes += size

    def reserve_memory(self, size: int) -> None:
        require(1 <= size <= self.config.max_read_bytes, "read_size_boundary")
        require(self.memory_bytes + size <= self.config.max_memory_bytes,
                "memory_byte_budget_exhausted")
        self.memory_bytes += size
        self.memory_calls += 1
        self.max_read_size = max(self.max_read_size, size)

    def summary(self) -> dict:
        return {
            "rpc_limit": self.config.rpc_limit,
            "attempted_rpc": self.calls,
            "reply_bytes": self.reply_bytes,
            "total_reply_byte_limit": self.config.max_total_reply_bytes,
            "memory_calls": self.memory_calls,
            "memory_bytes_read": self.memory_bytes,
            "memory_byte_limit": self.config.max_memory_bytes,
            "max_read_size": self.max_read_size,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
        }
