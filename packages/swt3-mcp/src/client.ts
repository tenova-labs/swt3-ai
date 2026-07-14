/**
 * SWT3 MCP Server — HTTP client for Axiom APIs.
 *
 * Uses native fetch (Node 18+). Zero dependencies.
 */

import type { McpConfig } from "./config.js";

export interface WitnessPayload {
  procedure_id: string;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  clearing_level: number;
  anchor_fingerprint: string;
  anchor_epoch: number;
  fingerprint_timestamp_ms: number;
  ai_model_id?: string;
  ai_prompt_hash?: string;
  ai_response_hash?: string;
  ai_system_prompt_hash?: string;
  ai_latency_ms?: number;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  ai_context?: Record<string, unknown>;
  agent_id?: string;
  cycle_id?: string;
  payload_signature?: string;
  policy_version_hash?: string;
  jurisdiction?: string;
  legal_basis?: string;
  purpose_class?: string;
  witness_source?: string;
  lifecycle_chain_id?: string;
  lifecycle_parent?: string;
  lifecycle_stage?: string;
  escalation_chain_id?: string;
}

export interface WitnessReceipt {
  ok: boolean;
  tenant_id: string;
  procedure_id: string;
  verdict: string;
  swt3_anchor: string;
  clearing_level: number;
  witnessed_at: string;
  verification_url: string;
  error?: string;
}

export interface VerifyResponse {
  verified: boolean;
  status: string;
  claimed_fingerprint?: string;
  recomputed_fingerprint?: string;
  inputs?: Record<string, unknown>;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime: number;
  checks: Record<string, string>;
}

export class AxiomClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;
  private resolvedTenantId: string | null = null;

  constructor(config: McpConfig, timeout: number = 10000) {
    this.baseUrl = config.endpoint;
    this.apiKey = config.apiKey;
    this.timeout = timeout;
  }

  /**
   * Returns the tenant ID resolved from a prior API call, if available.
   */
  getResolvedTenantId(): string | null {
    return this.resolvedTenantId;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
          ...options.headers,
        },
      });

      const body = await response.json() as T & { error?: string; tenant_id?: string };

      if (!response.ok) {
        const msg = body?.error || response.statusText;
        throw new Error(`${response.status}: ${msg}`);
      }

      // Auto-resolve tenant ID from any response that includes it
      if (body?.tenant_id && typeof body.tenant_id === "string") {
        this.resolvedTenantId = body.tenant_id;
      }

      return body;
    } finally {
      clearTimeout(timer);
    }
  }

  async postWitness(payload: WitnessPayload): Promise<WitnessReceipt> {
    return this.request<WitnessReceipt>("/api/v1/witness", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async verifyAnchor(token: string): Promise<VerifyResponse> {
    const encoded = encodeURIComponent(token);
    return this.request<VerifyResponse>(
      `/api/v1/attest/verify?token=${encoded}`,
    );
  }

  async getHealth(): Promise<HealthResponse> {
    const url = `${this.baseUrl}/api/v1/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, { signal: controller.signal });
      return (await response.json()) as HealthResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  async getPosture(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("/api/v1/ai-witness");
  }

  async fetchRegistry(): Promise<Record<string, unknown>> {
    const url = `${this.baseUrl}/registry/uct-registry.json`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, { signal: controller.signal });
      return (await response.json()) as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }
  }

}
