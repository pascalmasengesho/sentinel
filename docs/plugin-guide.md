# Plugin guide

Plugins are trusted local Python code. Sentinel does not sandbox them; do not load plugins you have not reviewed.

Give a plugin a `register()` function that returns one `ScanModule` or a list of modules. Place it in a directory and pass `--plugins-dir`.

```python
from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule


class ExampleModule(ScanModule):
    name = "example"

    async def run(self, context: ScanContext) -> ModuleResult:
        return ModuleResult(module=self.name, data={"target": context.target.host})


def register() -> ScanModule:
    return ExampleModule()
```

Plugins must preserve Sentinel's safe operating model: use the scoped `context.http` client for HTTP, return structured output, honor the config limits, and never add intrusive, destructive, or authentication-bypass behavior.

