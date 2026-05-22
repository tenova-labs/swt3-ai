/**
 * SWT3 AI Witness SDK -- vLLM Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="vllm". vLLM uses an OpenAI-compatible API at
 * http://localhost:8000/v1.
 *
 * NOT auto-detected by witness.wrap() (port 8000 too generic).
 * Use wrap_vllm() or vllmClient() explicitly.
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

export function wrapVllm(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "vllm");
}
