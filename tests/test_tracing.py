"""Tests for OpenTelemetry tracing configuration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracing import JSONLFileExporter, configure_tracing, trace_span


class TestJSONLFileExporter:
    def test_export_writes_spans(self, tmp_path: Path) -> None:
        out = tmp_path / "traces" / "test.jsonl"
        exporter = JSONLFileExporter(out)

        # Create a minimal mock span
        class MockContext:
            trace_id = 0x1234567890ABCDEF
            span_id = 0xABCDEF

        class MockStatus:
            class status_code:
                name = "OK"

        class MockSpan:
            context = MockContext()
            status = MockStatus()
            name = "test-span"
            attributes = {"key": "value"}
            start_time = 1000000000
            end_time = 2000000000

        from opentelemetry.sdk.trace.export import SpanExportResult

        result = exporter.export([MockSpan()])
        assert result == SpanExportResult.SUCCESS
        assert out.exists()

        lines = out.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["name"] == "test-span"
        assert record["status"] == "OK"
        assert record["attributes"] == {"key": "value"}
        assert "trace_id" in record
        assert "span_id" in record
        assert "duration_ms" in record

    def test_export_no_attributes(self, tmp_path: Path) -> None:
        out = tmp_path / "traces.jsonl"
        exporter = JSONLFileExporter(out)

        class MockContext:
            trace_id = 0x1
            span_id = 0x2

        class MockStatus:
            class status_code:
                name = "UNSET"

        class MockSpan:
            context = MockContext()
            status = MockStatus()
            name = "no-attrs"
            attributes = None
            start_time = None
            end_time = None

        exporter.export([MockSpan()])
        record = json.loads(out.read_text().strip())
        assert record["attributes"] == {}
        assert record["duration_ms"] == 0

    def test_shutdown(self, tmp_path: Path) -> None:
        exporter = JSONLFileExporter(tmp_path / "t.jsonl")
        exporter.shutdown()  # Should not raise

    def test_force_flush(self, tmp_path: Path) -> None:
        exporter = JSONLFileExporter(tmp_path / "t.jsonl")
        assert exporter.force_flush() is True


class TestConfigureTracing:
    def test_configure_without_file(self) -> None:
        configure_tracing(service_name="test-svc")
        # Should not raise

    def test_configure_with_file(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "traces" / "app.jsonl"
        configure_tracing(service_name="test-svc", trace_file=trace_file)
        # Should not raise


class TestTraceSpan:
    def test_trace_span_basic(self) -> None:
        configure_tracing(service_name="test")
        with trace_span("test-op") as span:
            span.set_attribute("test", "true")
        # Should complete without error

    def test_trace_span_with_attributes(self) -> None:
        configure_tracing(service_name="test")
        with trace_span("test-op", attributes={"key": "val"}):
            pass
        # Should complete without error

    def test_trace_span_with_exception(self) -> None:
        configure_tracing(service_name="test")
        with pytest.raises(ValueError, match="boom"), trace_span("failing-op"):
            raise ValueError("boom")
