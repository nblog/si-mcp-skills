from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ModuleRecord:
    name: str
    path: str
    kind: str
    base: int
    size: int
    load_time: str | None

    @property
    def file_name(self) -> str:
        return Path(self.path).name

    @property
    def identity(self) -> tuple:
        return (self.base, self.size, Path(self.path).resolve().as_posix().casefold(),
                self.kind, self.load_time)


@dataclass(frozen=True)
class MemoryRegion:
    start: int
    end: int
    executable: bool


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    sequence: int
    name: str
    start_time: str
