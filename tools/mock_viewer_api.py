#!/usr/bin/env python3
"""Tiny mock API for local webhookviewer debugging."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "dev" / "mock_api_data.json"
ALLOWED_SORT_COLS = {
    "started_at",
    "trace_name",
    "request_model",
    "response_model",
    "duration_ms",
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "total_cost_usd",
    "finish_reason",
    "received_at",
}
NUMERIC_SORT_COLS = {
    "duration_ms",
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "total_cost_usd",
}
SEARCH_FIELDS = [
    "trace_name",
    "request_model",
    "response_model",
    "finish_reason",
    "operation_name",
    "trace_id",
    "span_id",
    "prompt_preview",
    "response_preview",
    "cron_name",
]
PER_PAGE = 50


def load_data(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _match_search(span: dict[str, Any], term: str) -> bool:
    term = term.lower()
    for field in SEARCH_FIELDS:
        value = span.get(field)
        if value is not None and term in str(value).lower():
            return True
    return False


def _apply_filters(spans: list[dict[str, Any]], params: dict[str, str]) -> list[dict[str, Any]]:
    search = params.get("search", "").strip()
    hidden = {item for item in params.get("hide", "").split(",") if item}
    filtered = spans

    if search:
        filtered = [span for span in filtered if _match_search(span, search)]

    if "cron" in hidden:
        filtered = [span for span in filtered if not span.get("cron_name")]

    if "heartbeat" in hidden:
        filtered = [span for span in filtered if not span.get("heartbeat")]

    if "other" in hidden:
        filtered = [span for span in filtered if span.get("cron_name") or span.get("heartbeat")]

    return filtered


def _sort_key(span: dict[str, Any], col: str) -> Any:
    value = span.get(col)
    if value is None:
        return float("-inf") if col in NUMERIC_SORT_COLS else ""
    if col in NUMERIC_SORT_COLS:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float("-inf")
    return str(value)


def spans_response(data: dict[str, Any], params: dict[str, str]) -> dict[str, Any]:
    col = params.get("sort", "started_at")
    if col not in ALLOWED_SORT_COLS:
        col = "started_at"

    direction = "ASC" if params.get("dir") == "ASC" else "DESC"
    page = max(1, int(params.get("page", "1") or "1"))
    filtered = _apply_filters(list(data["spans"]), params)
    filtered.sort(key=lambda span: _sort_key(span, col), reverse=(direction == "DESC"))

    total = len(filtered)
    offset = (page - 1) * PER_PAGE
    page_items = filtered[offset:offset + PER_PAGE]
    return {"spans": page_items, "total": total, "page": page}


class MockHandler(BaseHTTPRequestHandler):
    data: dict[str, Any] = {}

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers("application/json; charset=utf-8")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        action = params.get("_action")

        if action == "stats":
            self._json(self.data["stats"])
            return

        if action == "spans":
            self._json(spans_response(self.data, params))
            return

        if action == "detail":
            detail_id = params.get("id", "")
            detail = self.data["details"].get(str(detail_id))
            if detail is None:
                self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
                return
            self._json(detail)
            return

        self._json(
            {
                "status": "ok",
                "message": "Mock viewer API is running.",
                "usage": "?_action=stats | ?_action=spans | ?_action=detail&id=101",
            }
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[mock-api] {self.address_string()} - {fmt % args}")

    def _json(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_common_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local mock API for webhookviewer.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", default=8765, type=int, help="Port to bind to")
    parser.add_argument("--data", default=str(DEFAULT_DATA), help="Path to mock JSON data file")
    args = parser.parse_args()

    data_path = Path(args.data).expanduser().resolve()
    MockHandler.data = load_data(data_path)

    server = ThreadingHTTPServer((args.host, args.port), MockHandler)
    print(f"Mock viewer API listening on http://{args.host}:{args.port}")
    print(f"Using data file: {data_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping mock viewer API.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
