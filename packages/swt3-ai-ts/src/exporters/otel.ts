/**
 * SWT3 AI Witness SDK -- OpenTelemetry Exporter.
 *
 * Exports SWT3 witness anchors as OpenTelemetry spans, allowing them to
 * flow into existing observability pipelines (Datadog, Grafana, Jaeger,
 * Honeycomb, etc.).
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import { OTelExporter } from "@tenova/swt3-ai/exporters/otel";
 *
 *   const exporter = new OTelExporter({ tracerName: "swt3-witness" });
 *   const witness = new Witness({ ..., onFlush: exporter.export.bind(exporter) });
 *
 * Requires: npm install @opentelemetry/api
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { WitnessPayload, WitnessReceipt } from "../types.js";

export interface OTelExporterOptions {
  tracerName?: string;
  serviceName?: string;
}

export class OTelExporter {
  private tracer: any;
  private traceModule: any;

  constructor(options?: OTelExporterOptions) {
    const tracerName = options?.tracerName ?? "swt3-ai";
    try {
      // Dynamic require to avoid hard dependency
      const trace = require("@opentelemetry/api").trace;
      this.traceModule = require("@opentelemetry/api");
      this.tracer = trace.getTracer(tracerName);
    } catch {
      throw new Error(
        "@opentelemetry/api is required for OTel export. " +
        "Install with: npm install @opentelemetry/api"
      );
    }
  }

  /**
   * Callback for Witness onFlush. Creates one span per anchor.
   *
   * Pass as: onFlush: exporter.export.bind(exporter)
   */
  export(payloads: WitnessPayload[], receipts: WitnessReceipt[]): void {
    for (let i = 0; i < payloads.length; i++) {
      const payload = payloads[i];
      const receipt = receipts[i] ?? null;
      const spanName = `swt3.witness.${payload.procedure_id ?? "unknown"}`;
      const attrs = this.spanAttributes(payload, receipt);

      const span = this.tracer.startSpan(spanName, { attributes: attrs });

      if (receipt && !(receipt as any).ok) {
        span.setStatus({
          code: this.traceModule.SpanStatusCode.ERROR,
          message: (receipt as any).error ?? "",
        });
      }

      span.end();
    }
  }

  private spanAttributes(
    payload: WitnessPayload,
    receipt: WitnessReceipt | null,
  ): Record<string, string | number | boolean> {
    const attrs: Record<string, string | number | boolean> = {};

    // Core anchor fields
    if (payload.procedure_id) attrs["swt3.procedure_id"] = payload.procedure_id;
    if (payload.clearing_level != null) attrs["swt3.clearing_level"] = payload.clearing_level;
    if (payload.anchor_fingerprint) attrs["swt3.fingerprint"] = payload.anchor_fingerprint;
    if (payload.anchor_epoch) attrs["swt3.epoch"] = payload.anchor_epoch;

    // Factors
    if (payload.factor_a != null) attrs["swt3.factor_a"] = payload.factor_a;
    if (payload.factor_b != null) attrs["swt3.factor_b"] = payload.factor_b;
    if (payload.factor_c != null) attrs["swt3.factor_c"] = payload.factor_c;

    // AI metadata (may be cleared depending on level)
    if (payload.ai_model_id) attrs["swt3.model_id"] = payload.ai_model_id;
    if (payload.ai_latency_ms != null) attrs["swt3.latency_ms"] = payload.ai_latency_ms;

    // Identity (survives all clearing levels)
    if (payload.agent_id) attrs["swt3.agent_id"] = payload.agent_id;
    if (payload.cycle_id) attrs["swt3.cycle_id"] = payload.cycle_id;

    // Receipt fields
    if (receipt) {
      if (receipt.verdict) attrs["swt3.verdict"] = receipt.verdict;
      if (receipt.swt3_anchor) attrs["swt3.anchor"] = receipt.swt3_anchor;
    }

    return attrs;
  }
}
