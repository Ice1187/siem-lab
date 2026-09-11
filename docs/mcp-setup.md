# Letting an AI investigate the lab (MCP)

This wires an AI client to the lab's Elasticsearch so it can run its own queries
instead of you pasting results into a chat window.

We use Elastic's official MCP server image, unmodified:
`docker.elastic.co/mcp/elasticsearch` (v0.4.6). It exposes five **read-only**
tools: `search`, `esql`, `list_indices`, `get_mappings`, `get_shards`.

## Why this server and not the community one

`cr7258/elasticsearch-mcp-server` has 20 tools and works fine here, but it
includes `delete_index`, `delete_by_query`, and `index_document`. Our
`docker-compose.yml` sets `action.destructive_requires_name=false`, so one
confused agent calling `delete_index` on `winlogbeat-*` wipes the dataset with
no auth and no confirmation. The official server cannot write.

The official server is marked deprecated in favour of Elastic Agent Builder,
which needs **Elastic 9.2+**. This lab is on 8.19, so Agent Builder is not an
option and the deprecated server is the right call. Deprecated here means
security-only updates, not broken.

Elastic's own built-in AI Assistant is *not* usable: it requires an Enterprise
licence and the lab runs on basic.

## Setup

Security is disabled on the lab cluster, so **no credentials are needed** — omit
`ES_API_KEY` entirely. Every README implies auth is mandatory; it isn't.

### Claude Code
Already wired via `.mcp.json` in the repo root. Restart Claude Code in this
directory and approve the server when prompted.

### Claude Desktop
Settings > Developer > Edit Config, then merge:

```json
{
  "mcpServers": {
    "elasticsearch": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-e", "ES_URL=http://host.docker.internal:9200",
               "docker.elastic.co/mcp/elasticsearch", "stdio"]
    }
  }
}
```

Restart Claude Desktop. Works on the **free plan** — local MCP servers are
available to all Claude Desktop users. Note that claude.ai in a browser cannot
do this at any price: a cloud-hosted connector cannot reach your localhost.

### Gemini CLI
Best option for students with no subscription: 1000 requests/day on a personal
Google account. Same block as above goes in `~/.gemini/settings.json`.

**ChatGPT free cannot do this at all** — custom MCP servers require Developer
Mode (Plus/Pro/Business and up).

## Three gotchas that will cost you an hour

1. **The `stdio` argument is required.** Without it the container prints a usage
   error and exits.
2. **Use `host.docker.internal`, not `localhost`.** The server runs inside
   Docker; with `localhost` it logs
   `Container mode: could not find a replacement for 'localhost'` and cannot
   reach the cluster.
3. **`get_mappings` is broken against this data** — see below.

## Known bug: get_mappings

`get_mappings` returns `error decoding response body` (JSON-RPC -32603) on any
index whose mapping contains a nested object field. Elasticsearch returns a
valid 200; the failure is in the server's own response deserialisation.

Verified by bisecting the real mapping down to a minimal reproducer:

```json
{"mappings": {"properties": {"agent": {"properties": {"type": {"type": "keyword"}}}}}}
```

Flat mappings (`{"host": {"type": "keyword"}}`) decode fine. Since all ECS data
is dotted objects, `get_mappings` is effectively unusable for this lab.

**Workaround — tell the agent to discover fields with ES|QL instead:**

```
FROM winlogbeat-apt29-host-day1 | KEEP process.* | LIMIT 1
```

This lists every `process.*` column. A `search` with `size: 1` also works, but
returns the huge raw `Message` blob.

Related rough edge: on a bad query the server reports only
`HTTP status client error (400 Bad Request)` and discards Elasticsearch's actual
parser error, so an agent cannot self-correct. Watch for agents looping on a
malformed query. (Careful with ES|QL reserved words — `STATS first = MIN(...)`
is a syntax error; rename the alias.)

## Verified investigation

Run end-to-end against `winlogbeat-apt29-host-day1` (196,081 docs, 4 hosts)
using only `search` and `esql`. The full APT29 Day 1 chain comes out:

**Initial access — T1036.002 Right-to-Left Override.** Parent `explorer.exe`
(user double-click) at 02:00:31:

```
FROM winlogbeat-apt29-host-day1
| WHERE process.command_line LIKE "*3aka3*"
| KEEP @timestamp, host.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
```

The filename renders as `‮cod.3aka3.scr` — a U+202E override making the real
`rcs.3aka3.scr` display as a `.doc`.

**Execution.** `‮cod.3aka3.scr` spawns `cmd.exe` (02:00:39) then
`powershell.exe` (02:00:49) with a gzipped base64 payload
(`-nop -w hidden -c &([scriptblock]::create(...GzipStream...FromBase64String(...`).

**C2.** `python.exe` → `192.168.0.4:8443`, 348 connections:

```
FROM winlogbeat-apt29-host-day1 | WHERE event.code == "3"
| STATS c = COUNT(*) BY process.name, destination.ip, destination.port
| SORT c DESC
```

**Lateral movement.** `PsExec64.exe` spawned by `powershell.exe` on SCRANTON,
with `PSEXESVC.exe` under `services.exe` on NASHUA.

**Defense evasion — T1070.004.** `sdelete64.exe /accepteula
C:\programdata\victim\...cod.3aka3.scr` at 02:06:39, the payload wiping itself.

### Starter prompts

- "Using the elasticsearch tools, list indices and work out what data is in them."
- "Find the earliest suspicious process creation on SCRANTON and reconstruct the process tree."
- "Which process makes the most outbound connections, and to where? Is it C2?"
- "Find evidence of lateral movement between hosts."

Timestamps are shifted by `ANCHOR_DATE` in `lab.conf`; `@timestamp_original`
keeps the real 2020 time. Tell the agent this, or it will get confused about the
date.
