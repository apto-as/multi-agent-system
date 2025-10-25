#!/usr/bin/env python3
"""
GenAI Toolbox Integration Bridge
統合アーキテクチャ: TMWSとGenAI Toolbox間のMCP通信ブリッジ
"""

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from src.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class GenAIToolInfo:
    """GenAI Toolboxツール情報"""

    name: str
    binary_path: str
    config: dict[str, Any]
    process_id: str | None = None
    status: str = "inactive"


class GenAIToolboxBridge:
    """
    GenAI Toolbox統合ブリッジ

    統合パターン:
    1. サイドカーパターン - GenAI ToolboxをGoプロセスとして並列実行
    2. プロキシパターン - TMWSを通じてツールを公開
    3. 共有リソース - SQLite/Redisで状態管理
    """

    def __init__(self, mcp_server: FastMCP):
        self.mcp = mcp_server
        self.genai_tools: dict[str, GenAIToolInfo] = {}
        self.go_processes: dict[str, subprocess.Popen] = {}
        self.message_handlers = {}

        # GenAI Toolbox検出
        self.genai_toolbox_path = self._detect_genai_toolbox()

        # 利用可能ツールの登録
        self._register_genai_tools()

    def _detect_genai_toolbox(self) -> Path | None:
        """GenAI Toolboxバイナリの自動検出"""
        possible_paths = [
            Path.home() / ".local/bin/genai-toolbox",
            Path("/usr/local/bin/genai-toolbox"),
            Path("./genai-toolbox"),
            Path(os.getenv("GENAI_TOOLBOX_PATH", "")),
        ]

        for path in possible_paths:
            if path.exists() and path.is_file():
                logger.info(f"GenAI Toolbox detected: {path}")
                return path

        logger.warning("GenAI Toolbox not found in standard locations")
        return None

    def _register_genai_tools(self):
        """利用可能なGenAIツールの登録"""
        if not self.genai_toolbox_path:
            return

        # 標準的なGenAI Toolboxツール
        standard_tools = {
            "genai-chat": {
                "description": "AI chat interface with multiple providers",
                "binary": "genai-chat",
                "config": {"provider": "openai", "model": "gpt-4"},
            },
            "genai-image": {
                "description": "AI image generation and manipulation",
                "binary": "genai-image",
                "config": {"provider": "dall-e", "size": "1024x1024"},
            },
            "genai-code": {
                "description": "AI code generation and analysis",
                "binary": "genai-code",
                "config": {"language": "auto", "style": "production"},
            },
            "genai-document": {
                "description": "AI document processing and generation",
                "binary": "genai-document",
                "config": {"format": "markdown", "style": "technical"},
            },
        }

        for tool_name, config in standard_tools.items():
            tool_info = GenAIToolInfo(
                name=tool_name,
                binary_path=str(self.genai_toolbox_path.parent / config["binary"]),
                config=config["config"],
            )
            self.genai_tools[tool_name] = tool_info

            # MCPツールとして登録
            self._register_mcp_tool(tool_name, config["description"])

    def _register_mcp_tool(self, tool_name: str, description: str):
        """個別ツールをMCPツールとして登録"""

        @self.mcp.tool(
            name=f"genai_{tool_name.replace('-', '_')}", description=f"GenAI Toolbox: {description}"
        )
        async def genai_tool_wrapper(
            prompt: str, config_override: dict[str, Any] | None = None, **kwargs
        ) -> dict[str, Any]:
            """GenAI Toolbox ツールラッパー"""
            return await self.execute_genai_tool(tool_name, prompt, config_override, **kwargs)

    async def execute_genai_tool(
        self, tool_name: str, prompt: str, config_override: dict[str, Any] | None = None, **kwargs
    ) -> dict[str, Any]:
        """GenAI Toolboxツールの実行"""
        if tool_name not in self.genai_tools:
            return {"error": f"Tool {tool_name} not available"}

        tool_info = self.genai_tools[tool_name]

        try:
            # 設定のマージ
            config = {**tool_info.config}
            if config_override:
                config.update(config_override)

            # Goプロセスとして実行
            result = await self._execute_go_process(tool_info.binary_path, prompt, config, **kwargs)

            # 結果をTMWSメモリに保存
            await self._store_execution_result(tool_name, prompt, result)

            return result

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"GenAI tool execution error: {e}",
                exc_info=True,
                extra={"tool_name": tool_name, "prompt_length": len(prompt)}
            )
            return {"error": str(e)}

    async def _execute_go_process(
        self, binary_path: str, prompt: str, config: dict[str, Any], **kwargs
    ) -> dict[str, Any]:
        """Goプロセスとしてツールを実行"""

        # MCP JSON-RPCメッセージ構築
        mcp_request = {
            "jsonrpc": "2.0",
            "id": f"genai_{asyncio.current_task().get_name()}",
            "method": "execute",
            "params": {"prompt": prompt, "config": config, **kwargs},
        }

        # Goプロセス起動
        process = await asyncio.create_subprocess_exec(
            binary_path,
            "--mcp-mode",  # MCPモードでの実行
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # JSON-RPC通信
        input_data = json.dumps(mcp_request).encode()
        stdout, stderr = await process.communicate(input_data)

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"GenAI tool failed: {error_msg}")

        # レスポンス解析
        try:
            response = json.loads(stdout.decode())
            if "error" in response:
                return {"error": response["error"]}
            return response.get("result", {})

        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON response: {e}"}

    async def _store_execution_result(self, tool_name: str, prompt: str, result: dict[str, Any]):
        """実行結果をTMWSメモリシステムに保存"""
        from src.services.memory_service import MemoryService

        memory_service = MemoryService()

        content = f"GenAI Tool {tool_name}: {prompt[:100]}..."

        await memory_service.create_memory(
            content=content,
            memory_type="genai_execution",
            importance=0.7,
            tags=[f"genai_{tool_name}", "ai_generation", "external_tool"],
            metadata={
                "tool_name": tool_name,
                "prompt": prompt,
                "result_preview": str(result)[:500],
                "execution_time": result.get("execution_time"),
                "token_usage": result.get("token_usage"),
            },
        )

    async def start_sidecar_services(self):
        """サイドカーサービスの起動"""
        for tool_name, tool_info in self.genai_tools.items():
            if Path(tool_info.binary_path).exists():
                try:
                    # サイドカープロセス起動
                    process = await asyncio.create_subprocess_exec(
                        tool_info.binary_path,
                        "--daemon-mode",  # デーモンモードで起動
                        "--mcp-port",
                        str(8000 + len(self.go_processes) + 1),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    self.go_processes[tool_name] = process
                    tool_info.status = "active"
                    tool_info.process_id = str(process.pid)

                    logger.info(f"Started GenAI sidecar: {tool_name} (PID: {process.pid})")

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    logger.error(
                        f"Failed to start {tool_name}: {e}",
                        exc_info=True,
                        extra={"tool_name": tool_name, "binary_path": tool_info.binary_path}
                    )
                    tool_info.status = "failed"

    async def health_check_genai_tools(self) -> dict[str, Any]:
        """GenAI Toolboxツールのヘルスチェック"""
        status = {}

        for tool_name, _tool_info in self.genai_tools.items():
            if tool_name in self.go_processes:
                process = self.go_processes[tool_name]
                if process.returncode is None:
                    status[tool_name] = "running"
                else:
                    status[tool_name] = "stopped"
            else:
                status[tool_name] = "not_started"

        return {
            "genai_toolbox_detected": self.genai_toolbox_path is not None,
            "available_tools": list(self.genai_tools.keys()),
            "tool_status": status,
            "total_tools": len(self.genai_tools),
        }

    async def shutdown(self):
        """すべてのGenAIプロセスのシャットダウン"""
        for tool_name, process in self.go_processes.items():
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5.0)
                logger.info(f"Gracefully stopped {tool_name}")
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"Force killed {tool_name}")
            except (KeyboardInterrupt, SystemExit):
                # Best-effort shutdown - don't propagate interrupts during cleanup
                process.kill()
                logger.warning(f"Force killed {tool_name} during shutdown interrupt")
            except Exception as e:
                # Best-effort shutdown - log warning but continue
                logger.warning(
                    f"Error stopping {tool_name}: {e}",
                    exc_info=False,
                    extra={"tool_name": tool_name}
                )


# MCPサーバーに統合
def register_genai_integration(mcp_server: FastMCP) -> GenAIToolboxBridge:
    """GenAI Toolbox統合をMCPサーバーに登録"""

    bridge = GenAIToolboxBridge(mcp_server)

    @mcp_server.tool(
        name="genai_health_check", description="Check status of GenAI Toolbox integration"
    )
    async def genai_health_check() -> dict[str, Any]:
        """GenAI Toolbox統合のヘルスチェック"""
        return await bridge.health_check_genai_tools()

    @mcp_server.tool(name="list_genai_tools", description="List available GenAI Toolbox tools")
    async def list_genai_tools() -> dict[str, Any]:
        """利用可能なGenAIツールの一覧"""
        return {
            "tools": [
                {
                    "name": tool_info.name,
                    "status": tool_info.status,
                    "config": tool_info.config,
                    "process_id": tool_info.process_id,
                }
                for tool_info in bridge.genai_tools.values()
            ]
        }

    return bridge
