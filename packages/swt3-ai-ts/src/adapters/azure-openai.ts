/**
 * SWT3 AI Witness SDK -- Azure OpenAI Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="azure-openai". Azure OpenAI uses the openai TypeScript
 * SDK with the AzureOpenAI class:
 *
 *   import { AzureOpenAI } from "openai";
 *
 *   const client = new AzureOpenAI({
 *     endpoint: "https://your-resource.openai.azure.com",
 *     apiKey: "...",
 *     apiVersion: "2024-02-01",
 *   });
 *
 * Auto-detected by witness.wrap() when constructor name is "AzureOpenAI"
 * or baseURL contains ".openai.azure.com".
 *
 * The model parameter in Azure OpenAI is the deployment name, not the
 * model family. The adapter records the deployment name as modelId,
 * which is correct -- the deployment name is the operationally significant
 * identifier.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an Azure OpenAI client with transparent witnessing.
 *
 * Identical to the OpenAI adapter but tags all InferenceRecords with
 * provider="azure-openai" for accurate lineage tracking.
 */
export function wrapAzureOpenAI(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "azure-openai");
}

export function isAzureOpenAIClient(client: unknown): boolean {
  if (client === null || client === undefined) return false;
  const proto = Object.getPrototypeOf(client);
  const name = proto?.constructor?.name ?? "";
  if (name === "AzureOpenAI" || name === "AsyncAzureOpenAI") return true;
  return getBaseURL(client).includes(".openai.azure.com");
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
