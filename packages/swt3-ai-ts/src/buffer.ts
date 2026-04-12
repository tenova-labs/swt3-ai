/**
 * SWT3 AI Witness SDK — Flush Buffer.
 *
 * Non-blocking buffer that collects witness payloads and flushes them
 * to the /api/v1/witness/batch endpoint. Uses setTimeout for periodic
 * flushing and a dead-letter array for resilience.
 *
 * Flight Recorder: When the endpoint is unreachable, payloads move to
 * a dead-letter array and retry on the next cycle. Configurable cap
 * prevents unbounded memory growth.
 */

import type { WitnessConfig, WitnessPayload, WitnessReceipt, BatchResponse } from "./types.js";

const DEFAULT_MAX_RETRY_BUFFER = 5000;

export class WitnessBuffer {
  private config: WitnessConfig;
  private queue: WitnessPayload[] = [];
  private deadLetter: WitnessPayload[] = [];
  private maxRetryBuffer: number;
  private allReceipts: WitnessReceipt[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private consecutiveFailures = 0;
  private ctaShown = false;

  constructor(config: WitnessConfig, maxRetryBuffer = DEFAULT_MAX_RETRY_BUFFER) {
    this.config = config;
    this.maxRetryBuffer = maxRetryBuffer;
    this.startTimer();
  }

  /** Add a single payload to the buffer. */
  enqueue(payload: WitnessPayload): void {
    if (this.stopped) return;
    this.queue.push(payload);
    if (this.queue.length >= this.config.bufferSize) {
      this.flushInternal();
    }
  }

  /** Add multiple payloads. */
  enqueueMany(payloads: WitnessPayload[]): void {
    for (const p of payloads) this.enqueue(p);
  }

  /** Force-flush all buffered payloads. */
  async flush(): Promise<WitnessReceipt[]> {
    return this.flushInternal();
  }

  /** Stop the buffer and flush remaining payloads. */
  async stop(): Promise<WitnessReceipt[]> {
    if (this.stopped) return [];
    this.stopped = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const receipts = await this.flushInternal();
    if (this.deadLetter.length > 0) {
      console.warn(
        `[swt3-ai] Buffer stopped with ${this.deadLetter.length} payloads in dead-letter queue`,
      );
    }
    return receipts;
  }

  /** Number of payloads waiting (includes dead-letter). */
  get pending(): number {
    return this.queue.length + this.deadLetter.length;
  }

  /** Payloads in dead-letter queue awaiting retry. */
  get deadLetterCount(): number {
    return this.deadLetter.length;
  }

  /** All receipts from completed flushes. */
  get receipts(): WitnessReceipt[] {
    return [...this.allReceipts];
  }

  private startTimer(): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.flushInternal().catch(() => {});
      this.startTimer();
    }, this.config.flushInterval * 1000);
    // Unref so the timer doesn't keep the process alive
    if (typeof this.timer === "object" && "unref" in this.timer) {
      (this.timer as NodeJS.Timeout).unref();
    }
  }

  private async flushInternal(): Promise<WitnessReceipt[]> {
    // Drain queue
    const payloads = [...this.deadLetter, ...this.queue];
    this.deadLetter = [];
    this.queue = [];

    if (payloads.length === 0) return [];

    return this.sendBatch(payloads);
  }

  private async sendBatch(payloads: WitnessPayload[]): Promise<WitnessReceipt[]> {
    if (payloads.length === 0) return [];

    const url = `${this.config.endpoint}/api/v1/witness/batch`;
    const body = JSON.stringify({ witnesses: payloads });
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.config.apiKey}`,
    };

    let lastError: string | null = null;

    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

        const resp = await fetch(url, {
          method: "POST",
          headers,
          body,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (resp.status >= 400 && resp.status < 500) {
          // Client error — don't retry, don't dead-letter
          const text = await resp.text();
          console.error(`[swt3-ai] Batch flush failed (${resp.status}): ${text.slice(0, 200)}`);
          return [];
        }

        const result = (await resp.json()) as BatchResponse;

        const receipts: WitnessReceipt[] = result.receipts ?? [];
        this.allReceipts.push(...receipts);
        this.consecutiveFailures = 0;

        if (result.rejected > 0) {
          console.warn(
            `[swt3-ai] Batch flush: ${result.accepted} accepted, ${result.rejected} rejected`,
          );
        }

        if (!this.ctaShown && (result.accepted ?? 0) > 0) {
          this.ctaShown = true;
          console.info(
            `\n  [SWT3] ${result.accepted} anchors delivered to ${this.config.endpoint}` +
            `\n  [SWT3] Dashboard & audit reports \u2192 https://sovereign.tenova.io/signup?ref=sdk` +
            `\n  [SWT3] EU AI Act deadline: Aug 2, 2026. Is your AI ready?\n`
          );
        }

        return receipts;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        console.warn(
          `[swt3-ai] Batch flush attempt ${attempt + 1} failed: ${lastError}`,
        );

        // Exponential backoff: 1s, 2s, 4s
        if (attempt < this.config.maxRetries - 1) {
          await new Promise((r) => setTimeout(r, 2 ** attempt * 1000));
        }
      }
    }

    // All retries exhausted — move to dead-letter queue
    this.consecutiveFailures++;
    const before = this.deadLetter.length;
    this.deadLetter.push(...payloads);

    // Cap the dead-letter queue
    if (this.deadLetter.length > this.maxRetryBuffer) {
      const dropped = this.deadLetter.length - this.maxRetryBuffer;
      this.deadLetter = this.deadLetter.slice(dropped);
      console.error(
        `[swt3-ai] Dead-letter queue full: ${dropped} oldest payloads dropped (cap: ${this.maxRetryBuffer})`,
      );
    } else {
      console.warn(
        `[swt3-ai] Endpoint unreachable — ${payloads.length} payloads moved to dead-letter (total: ${this.deadLetter.length}). Error: ${lastError}`,
      );
    }

    return [];
  }
}
