import { describe, it, expect, vi } from "vitest";
import { handleWitnessTrajectory } from "../src/tools/trajectory.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

const demoConfig: McpConfig = { ...mockConfig, demo: true };

function mockClient(receipt: Record<string, unknown>): AxiomClient {
  return {
    postWitness: vi.fn().mockResolvedValue(receipt),
  } as unknown as AxiomClient;
}

const baseReceipt = {
  ok: true,
  procedure_id: "AI-MOB.6",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIMOB6-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-08-06T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_trajectory tool", () => {
  it("witnesses validated trajectory with correct factors", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessTrajectory(
      { safety_validated: true, waypoint_count: 47, action_class: "navigate" },
      mockConfig,
      client,
    );

    expect(result).toContain("Trajectory Witnessed (AI-MOB.6)");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Safety Validated: YES");
    expect(result).toContain("Waypoints: 47");
    expect(result).toContain("Action: navigate");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-MOB.6");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(1); // validated
    expect(call.factor_c).toBe(1); // nominal (default)
  });

  it("witnesses failed trajectory", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessTrajectory(
      { safety_validated: false, safety_classification: "emergency" },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0); // failed
    expect(call.factor_c).toBe(4); // emergency
  });

  it("strips context at clearing level 3", async () => {
    const cl3Config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleWitnessTrajectory(
      { safety_validated: true, model_id: "secret-vla" },
      cl3Config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context).toBeUndefined();
    expect(call.ai_model_id).not.toBe("secret-vla"); // hashed
  });

  it("works in demo mode", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessTrajectory(
      { safety_validated: true },
      demoConfig,
      client,
    );

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("Trajectory Witnessed (AI-MOB.6)");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("includes sensor sources at CL1", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessTrajectory(
      {
        safety_validated: true,
        sensor_sources: ["camera_front", "lidar_top"],
        coc_trace_hash: "abc123",
      },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context.sensor_count).toBe(2);
    expect(call.ai_context.sensor_sources).toEqual(["camera_front", "lidar_top"]);
    expect(call.ai_context.coc_trace_hash).toBe("abc123");
  });
});
