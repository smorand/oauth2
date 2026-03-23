"""OpenTelemetry tracing configuration."""

from __future__ import annotations

import json
import logging
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import Span, StatusCode

logger = logging.getLogger(__name__)


class JSONLFileExporter(SpanExporter):
    """Export spans to a JSONL file."""

    __slots__ = ("_path",)

    def __init__(self, file_path: Path) -> None:
        self._path = file_path

    def export(self, spans: Any) -> SpanExportResult:
        """Write spans to JSONL file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as f:
            for span in spans:
                record = {
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "trace_id": format(span.context.trace_id, "032x"),
                    "span_id": format(span.context.span_id, "016x"),
                    "name": span.name,
                    "status": span.status.status_code.name,
                    "attributes": dict(span.attributes) if span.attributes else {},
                    "duration_ms": (span.end_time - span.start_time) / 1_000_000 if span.end_time and span.start_time else 0,
                }
                f.write(json.dumps(record) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        """Shutdown exporter."""

    def force_flush(self, timeout_millis: int = 0) -> bool:
        """Force flush."""
        return True


def configure_tracing(service_name: str = "oauth2", trace_file: Path | None = None) -> None:
    """Configure OpenTelemetry tracing with JSONL file exporter."""
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if trace_file:
        exporter = JSONLFileExporter(trace_file)
        provider.add_span_processor(SimpleSpanProcessor(exporter))

    trace.set_tracer_provider(provider)


@contextmanager
def trace_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Span, None, None]:
    """Create a traced span with optional attributes."""
    tracer = trace.get_tracer("oauth2")
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, str(value))
        try:
            yield span
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            raise
