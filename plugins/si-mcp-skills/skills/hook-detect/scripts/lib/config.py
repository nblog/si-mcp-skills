from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanConfig(BaseModel):
    """Strict limits for an authorized read-only scan."""

    model_config = ConfigDict(strict=True, extra="forbid")

    page_size: Literal[4096] = Field(
        default=4096,
        description="Initial mapped PE header read size; not the OS page size or transport limit.",
    )
    patch_block_size: Literal[512] = Field(
        default=512,
        description="Only contiguous patches strictly smaller than this size enter Capstone classification.",
    )
    max_read_bytes: Literal[65535] = Field(
        default=65535,
        description="Hard maximum size for one process-memory read; caller options cannot raise it.",
    )
    rpc_limit: int = Field(
        default=8192,
        ge=32,
        le=16384,
        description="Maximum attempted MCP calls, including handshake, listings, reads, and identity rechecks.",
    )
    total_seconds: float = Field(
        default=300,
        ge=30,
        le=600,
        description="Wall-clock budget for one scan pipeline before cancellation.",
    )
    rpc_seconds: float = Field(
        default=10,
        ge=1,
        le=30,
        description="Timeout for one MCP request, also bounded by the remaining wall-clock budget.",
    )
    max_reply_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=128 * 1024,
        description="Maximum serialized SDK model size accepted for one MCP reply.",
    )
    max_total_reply_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1024 * 1024,
        description="Cumulative serialized SDK model size accepted across all MCP replies.",
    )
    max_memory_bytes: Literal[64 * 1024 * 1024, 0] = Field(
        default=64 * 1024 * 1024,
        description="Maximum process-memory bytes this process may read; zero disables memory reads.",
    )
    max_modules: int = Field(
        default=512,
        ge=1,
        le=1024,
        description="Maximum module rows accepted from the target process enumeration.",
    )
    max_table_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=4096,
        description="Maximum bytes accepted for one PE directory or table region read.",
    )
    max_export_entries: int = Field(
        default=65535,
        ge=1,
        description="Maximum export function or name entries accepted before the table is rejected as malformed.",
    )
    max_string_bytes: int = Field(
        default=512,
        ge=16,
        description="Maximum bytes used to read one NUL-terminated export or forwarder string.",
    )
    max_snapshot_age_seconds: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Maximum allowed age of a provider snapshot; up to five seconds of future skew is accepted.",
    )


class TransportConfig(ScanConfig):
    """Transport verification has no process-memory allowance."""

    rpc_limit: int = Field(
        default=8,
        ge=8,
        le=16,
        description="Lower MCP call budget used by self metadata transport verification.",
    )
    total_seconds: float = Field(
        default=30,
        ge=30,
        le=60,
        description="Lower wall-clock budget used by self metadata transport verification.",
    )
    max_total_reply_bytes: int = Field(
        default=3 * 1024 * 1024,
        ge=1024 * 1024,
        description="Lower cumulative reply budget used by self metadata transport verification.",
    )
    max_memory_bytes: Literal[0] = Field(
        default=0,
        description="Transport verification may never request process-memory reads.",
    )
