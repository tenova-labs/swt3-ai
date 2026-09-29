/**
 * OpenShell OCSF event consumer adapter tests.
 *
 * Verifies OCSF-to-SWT3 procedure mapping, factor extraction,
 * graceful skip of unknown events, and stream processing.
 */

import { describe, it, expect, vi } from "vitest";
import { OpenShellWitness } from "../src/adapters/openshell.js";
import type { OcsfEvent } from "../src/adapters/openshell.js";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockWitness() {
  return {
    record: vi.fn(),
    strict: false,
    gateCheck: vi.fn(),
    _strict: false,
  } as any;
}

// ---------------------------------------------------------------------------
// OCSF event fixtures
// ---------------------------------------------------------------------------

const networkAllow: OcsfEvent = {
  class_name: "network_activity",
  disposition: "allow",
  activity_name: "http_request",
  time: 1700000000000,
  duration: 42,
  request_uid: "req-001",
  response_uid: "res-001",
  dst_endpoint: { hostname: "api.openai.com", url: "https://api.openai.com/v1/chat" },
};

const networkDeny: OcsfEvent = {
  class_name: "network_activity",
  disposition: "deny",
  activity_name: "blocked_egress",
  time: 1700000001000,
  dst_endpoint: { hostname: "evil.com" },
};

const networkDenyInt: OcsfEvent = {
  class_name: "network_activity",
  disposition: 2, // integer disposition ID
  activity_name: "blocked_egress",
};

const networkRoute: OcsfEvent = {
  class_name: "network_activity",
  disposition: "route",
  activity_name: "credential_inject",
  dst_endpoint: { hostname: "vault.internal" },
};

const processLaunch: OcsfEvent = {
  class_name: "process_activity",
  disposition: "launch",
  activity_name: "agent_start",
};

const processTerminate: OcsfEvent = {
  class_name: "process_activity",
  disposition: "terminate",
  activity_name: "agent_stop",
};

const toolCall: OcsfEvent = {
  class_name: "process_activity",
  disposition: "tool_call",
  activity_name: "web_search",
  process: { name: "brave_search" },
};

const fileAllow: OcsfEvent = {
  class_name: "file_activity",
  disposition: "allow",
  activity_name: "read",
  file: { path: "/data/model.bin" },
};

const fileDeny: OcsfEvent = {
  class_name: "file_activity",
  disposition: "deny",
  activity_name: "write",
  file: { path: "/etc/passwd" },
};

const configChange: OcsfEvent = {
  class_name: "configuration_change",
  disposition: "update",
  activity_name: "policy_update",
};

const guardrailAllow: OcsfEvent = {
  class_name: "security_finding",
  disposition: "guardrail_allow",
  activity_name: "content_filter",
};

const guardrailDeny: OcsfEvent = {
  class_name: "security_finding",
  disposition: "guardrail_deny",
  activity_name: "content_filter",
};

const unknownEvent: OcsfEvent = {
  class_name: "dns_activity",
  disposition: "allow",
  activity_name: "dns_query",
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OpenShellWitness", () => {
  describe("procedure mapping", () => {
    it("maps network_activity/allow to AI-INF.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      const result = osw.processEvent(networkAllow);
      expect(result).toBe("AI-INF.1");
      expect(w.record).toHaveBeenCalledTimes(1);
    });

    it("maps network_activity/deny to AI-SEC.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(networkDeny)).toBe("AI-SEC.1");
    });

    it("maps network_activity/route to AI-ACC.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(networkRoute)).toBe("AI-ACC.1");
    });

    it("maps process_activity/launch to AI-ID.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(processLaunch)).toBe("AI-ID.1");
    });

    it("maps process_activity/terminate to AI-ID.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(processTerminate)).toBe("AI-ID.1");
    });

    it("maps process_activity/tool_call to AI-TOOL.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(toolCall)).toBe("AI-TOOL.1");
    });

    it("maps file_activity/allow to AI-DATA.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(fileAllow)).toBe("AI-DATA.1");
    });

    it("maps file_activity/deny to AI-SEC.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(fileDeny)).toBe("AI-SEC.1");
    });

    it("maps configuration_change/update to AI-MDL.2", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(configChange)).toBe("AI-MDL.2");
    });

    it("maps security_finding/guardrail_allow to AI-GRD.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(guardrailAllow)).toBe("AI-GRD.1");
    });

    it("maps security_finding/guardrail_deny to AI-GRD.1", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(guardrailDeny)).toBe("AI-GRD.1");
    });
  });

  describe("integer disposition", () => {
    it("handles OCSF integer disposition 2 (deny)", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(networkDenyInt)).toBe("AI-SEC.1");
    });
  });

  describe("unknown events", () => {
    it("returns null for unmapped event classes", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent(unknownEvent)).toBeNull();
      expect(w.record).not.toHaveBeenCalled();
    });

    it("returns null for empty events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      expect(osw.processEvent({})).toBeNull();
    });
  });

  describe("record fields", () => {
    it("sets provider to nvidia-openshell", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkAllow);
      const record = w.record.mock.calls[0][0];
      expect(record.provider).toBe("nvidia-openshell");
    });

    it("sets modelId from dst_endpoint hostname", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkAllow);
      const record = w.record.mock.calls[0][0];
      expect(record.modelId).toBe("api.openai.com");
    });

    it("sets hasRefusal=true for denied events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkDeny);
      const record = w.record.mock.calls[0][0];
      expect(record.hasRefusal).toBe(true);
    });

    it("sets guardrailPassed=false for denied events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkDeny);
      const record = w.record.mock.calls[0][0];
      expect(record.guardrailPassed).toBe(false);
    });

    it("sets guardrailsActive=1 for security procedures", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkDeny); // AI-SEC.1
      const record = w.record.mock.calls[0][0];
      expect(record.guardrailsActive).toBe(1);
      expect(record.guardrailsRequired).toBe(1);
    });

    it("sets guardrailsActive=0 for non-security procedures", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkAllow); // AI-INF.1
      const record = w.record.mock.calls[0][0];
      expect(record.guardrailsActive).toBe(0);
    });

    it("sets toolName for tool_call events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(toolCall);
      const record = w.record.mock.calls[0][0];
      expect(record.toolName).toBe("brave_search");
    });

    it("sets accessTarget from file path for file events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(fileDeny);
      const record = w.record.mock.calls[0][0];
      expect(record.accessTarget).toBe("/etc/passwd");
    });

    it("sets accessTarget from dst_endpoint for network security events", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkDeny);
      const record = w.record.mock.calls[0][0];
      expect(record.accessTarget).toBe("evil.com");
    });

    it("sets latencyMs from OCSF duration", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkAllow);
      const record = w.record.mock.calls[0][0];
      expect(record.latencyMs).toBe(42);
    });
  });

  describe("stats", () => {
    it("tracks processed and skipped counts", () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);
      osw.processEvent(networkAllow);
      osw.processEvent(networkDeny);
      osw.processEvent(unknownEvent);
      osw.processEvent({});
      expect(osw.stats).toEqual({ processed: 2, skipped: 2 });
    });
  });

  describe("watchStream", () => {
    it("processes all events from async iterator", async () => {
      const w = mockWitness();
      const osw = new OpenShellWitness(w);

      async function* events(): AsyncGenerator<OcsfEvent> {
        yield networkAllow;
        yield toolCall;
        yield unknownEvent;
        yield guardrailDeny;
      }

      await osw.watchStream(events());
      expect(osw.stats).toEqual({ processed: 3, skipped: 1 });
      expect(w.record).toHaveBeenCalledTimes(3);
    });
  });
});
