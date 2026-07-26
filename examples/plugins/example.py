"""A deliberately passive example Sentinel plugin."""

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule


class ScopeNoteModule(ScanModule):
    name = "scope_note"

    async def run(self, context: ScanContext) -> ModuleResult:
        return ModuleResult(module=self.name, data={"scoped_host": context.target.host})


def register() -> ScanModule:
    return ScopeNoteModule()

