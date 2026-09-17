#!/usr/bin/env python3
#
# Copyright (C) 2026 Ellis Huang
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See the LICENSE file for the full text.
#
"""Reverse proxy that makes get_mappings work with the Elastic MCP server.

The MCP server (docker.elastic.co/mcp/elasticsearch) cannot deserialise a
mapping that contains object fields without an explicit "type" -- see
https://github.com/elastic/mcp-server-elasticsearch/issues/173. Every ECS
mapping hits this, because dotted field names like agent.type become nested
objects, and Elasticsearch normalises an explicit "type": "object" away again.
So it cannot be fixed in the index template.

This proxy sits between the MCP server and Elasticsearch and flattens
_mapping responses to dotted leaf fields, which the server parses happily:

    {"agent": {"properties": {"type": {"type": "keyword"}}}}
 -> {"agent.type": {"type": "keyword"}}

Everything else is passed through untouched.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("ES_UPSTREAM", "http://localhost:9200").rstrip("/")
PORT = int(os.environ.get("PROXY_PORT", "9280"))
HOP_BY_HOP = {"transfer-encoding", "connection", "keep-alive", "content-length",
              "content-encoding"}


def flatten(node, prefix=""):
    """Collapse a mapping properties tree into dotted leaf fields."""
    out = {}
    for name, spec in (node or {}).items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}{name}"
        if "properties" in spec:
            out.update(flatten(spec["properties"], f"{path}."))
        elif "type" in spec:
            # Keep only the type: extra attributes are what trip the decoder.
            out[path] = {"type": spec["type"]}
            # Multi-fields (foo.keyword) are addressable, so surface them too.
            for sub, subspec in (spec.get("fields") or {}).items():
                if isinstance(subspec, dict) and "type" in subspec:
                    out[f"{path}.{sub}"] = {"type": subspec["type"]}
    return out


def rewrite_mapping(payload):
    """Rewrite a _mapping response in place, per index."""
    for index, body in payload.items():
        if not isinstance(body, dict) or "mappings" not in body:
            continue
        mappings = body["mappings"] or {}
        body["mappings"] = {"properties": flatten(mappings.get("properties"))}
    return payload


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "es-mapping-proxy"

    def proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        req = urllib.request.Request(UPSTREAM + self.path, data=body,
                                     method=self.command)
        for header in ("Content-Type", "Accept"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])

        try:
            with urllib.request.urlopen(req) as resp:
                status, raw = resp.status, resp.read()
                ctype = resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as err:
            status, raw = err.code, err.read()
            ctype = err.headers.get("Content-Type", "application/json")
        except urllib.error.URLError as err:
            self.send_error(502, f"upstream unreachable: {err.reason}")
            return

        # Only touch successful mapping reads.
        if status == 200 and self.path.rstrip("/").endswith("_mapping"):
            try:
                raw = json.dumps(rewrite_mapping(json.loads(raw))).encode()
                self.log("flattened mapping for %s" % self.path)
            except (ValueError, AttributeError) as err:
                self.log("could not flatten %s: %s" % (self.path, err))

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = proxy

    def log(self, msg):
        sys.stderr.write(f"[proxy] {msg}\n")
        sys.stderr.flush()

    def log_message(self, *args):
        pass  # too chatty: one line per Elasticsearch call


if __name__ == "__main__":
    print(f"[proxy] :{PORT} -> {UPSTREAM} (flattening _mapping)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
