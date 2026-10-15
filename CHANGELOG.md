# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Changed

- **Pin `mcp` to `mcp>=1,<2`.**
  - `requirements.txt` now installs `mcp>=1,<2` (previously just `mcp`) with an
    explanatory comment.
  - This server targets the **v1** MCP SDK, which exposes `FastMCP`
    (`mcp.server.fastmcp.FastMCP`). In `mcp` 2.x that class was renamed to
    `MCPServer` (`mcp.server.mcpserver.MCPServer`), so a plain
    `pip install mcp` today (2.x) fails with
    `No module named 'mcp.server.fastmcp'`. Pinning `mcp>=1,<2` keeps the v1 API.
    To use mcp 2.x instead, migrate to `MCPServer` and drop the pin.
  - `README.md` updated accordingly: the requirements list now notes the pin, the
    install command points at `pip install -r requirements.txt`, and a callout box
    explains why `mcp<2` is pinned.
