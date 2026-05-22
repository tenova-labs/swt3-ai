"""SWT3 AI Witness SDK -- OpenTelemetry Exporter.

Exports SWT3 witness anchors as OpenTelemetry spans, allowing them to
flow into existing observability pipelines (Datadog, Grafana, Jaeger,
Honeycomb, etc.).

Usage:
    from swt3_ai import Witness
    from swt3_ai.exporters.otel import OTelExporter

    exporter = OTelExporter(tracer_name="swt3-witness")
    witness = Witness(..., on_flush=exporter.export)

    # Anchors now appear as OTel spans alongside your existing traces.

Requires: pip install opentelemetry-api
    Or: pip install swt3-ai[otel]
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..types import WitnessPayload, WitnessReceipt

logger = logging.getLogger("swt3_ai.exporters.otel")


class OTelExporter:
    """Export SWT3 witness data as OpenTelemetry spans.

    Each flushed anchor becomes a span with swt3.* attributes. Pass
    ``exporter.export`` as the ``on_flush`` callback when creating
    a Witness instance.
    """

    def __init__(
        self,
        tracer_name: str = "swt3-ai",
        service_name: str = "swt3-witness",
    ) -> None:
        try:
            from opentelemetry import trace
            self._trace = trace
            self._tracer = trace.get_tracer(tracer_name)
        except ImportError:
            raise ImportError(
                "opentelemetry-api is required for OTel export. "
                "Install with: pip install opentelemetry-api  "
                "Or: pip install swt3-ai[otel]"
            )
        self._service_name = service_name

    def export(
        self,
        payloads: List[Any],
        receipts: List[Any],
    ) -> None:
        """Callback for Witness on_flush. Creates one span per anchor.

        This method is safe to pass directly as the on_flush callback:
            witness = Witness(..., on_flush=exporter.export)
        """
        for i, payload in enumerate(payloads):
            receipt = receipts[i] if i < len(receipts) else None
            attrs = self._span_attributes(payload, receipt)
            span_name = f"swt3.witness.{getattr(payload, 'procedure_id', 'unknown')}"

            with self._tracer.start_as_current_span(span_name, attributes=attrs) as span:
                if receipt and not getattr(receipt, "ok", True):
                    span.set_status(
                        self._trace.StatusCode.ERROR,
                        getattr(receipt, "error", "") or "",
                    )

    def _span_attributes(
        self,
        payload: Any,
        receipt: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Build OTel span attributes from a witness payload and receipt."""
        attrs: Dict[str, Any] = {}

        # Core anchor fields
        _set(attrs, "swt3.procedure_id", getattr(payload, "procedure_id", None))
        _set(attrs, "swt3.clearing_level", getattr(payload, "clearing_level", None))
        _set(attrs, "swt3.fingerprint", getattr(payload, "anchor_fingerprint", None))
        _set(attrs, "swt3.epoch", getattr(payload, "anchor_epoch", None))

        # Factors
        _set(attrs, "swt3.factor_a", getattr(payload, "factor_a", None))
        _set(attrs, "swt3.factor_b", getattr(payload, "factor_b", None))
        _set(attrs, "swt3.factor_c", getattr(payload, "factor_c", None))

        # AI metadata (may be cleared depending on level)
        _set(attrs, "swt3.model_id", getattr(payload, "ai_model_id", None))
        _set(attrs, "swt3.latency_ms", getattr(payload, "ai_latency_ms", None))

        # Identity (survives all clearing levels)
        _set(attrs, "swt3.agent_id", getattr(payload, "agent_id", None))
        _set(attrs, "swt3.cycle_id", getattr(payload, "cycle_id", None))

        # Receipt fields (from server response)
        if receipt:
            _set(attrs, "swt3.verdict", getattr(receipt, "verdict", None))
            _set(attrs, "swt3.anchor", getattr(receipt, "swt3_anchor", None))

        return attrs


def _set(attrs: Dict[str, Any], key: str, value: Any) -> None:
    """Set an attribute only if the value is not None."""
    if value is not None:
        attrs[key] = value
