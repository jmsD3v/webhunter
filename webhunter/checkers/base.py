from __future__ import annotations

import time
from abc import ABC, abstractmethod

from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability


class BaseChecker(ABC):
    name: str
    category: VulnCategory
    description: str

    async def execute(self, target: TargetURL, result: ScanResult) -> float:
        start = time.perf_counter()
        try:
            await self.run(target, result)
        except Exception as exc:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Checker error: {self.name}",
                    description=f"{type(exc).__name__}: {exc}",
                    severity=Severity.INFO,
                    evidence=str(exc),
                    remediation="Internal checker error — review checker implementation.",
                )
            )
        return time.perf_counter() - start

    @abstractmethod
    async def run(self, target: TargetURL, result: ScanResult) -> None: ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
