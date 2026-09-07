"""Test doubles dùng chung cho các test pipeline (FakeRunner/FakeConn/FakePool)
— mô phỏng ToolRunner và asyncpg pool mà không cần DB thật."""

from app.tools import ToolResult


class FakeRunner:
    """Tool runner giả: map tool → stdout, ghi lại mọi lần gọi để test âm tính
    kiểm tra request không lọt ra ngoài."""

    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs  # tool → stdout
        self.calls: list[tuple[str, list[str], str | None]] = []
        self.docker_calls: list[list[str] | None] = []

    async def __call__(
        self, tool: str, args: list[str], stdin: str | None = None,
        docker_args: list[str] | None = None,
    ):
        self.calls.append((tool, args, stdin))
        self.docker_calls.append(docker_args)
        return ToolResult(0, self.outputs.get(tool, ""), "")


class FakeConn:
    def __init__(self, parent):
        self.parent = parent

    async def execute(self, sql, *params):
        self.parent.executes.append((sql.strip().split()[0].lower(), sql, params))

    async def executemany(self, sql, rows):
        self.parent.executes.append(("executemany", sql, rows))

    async def fetchval(self, sql, *params):
        self.parent.executes.append(("fetchval", sql, params))
        return next(self.parent.ids)  # id tool_executions tăng dần

    async def fetchrow(self, sql, *params):
        self.parent.executes.append(("fetchrow", sql, params))
        return {"count": 0}

    async def fetch(self, sql, *params):
        return []


class FakePool:
    def __init__(self):
        self.executes = []
        self.ids = iter(range(1, 10_000))

    def acquire(self):
        return self

    async def __aenter__(self):
        return FakeConn(self)

    async def __aexit__(self, *exc):
        return False
