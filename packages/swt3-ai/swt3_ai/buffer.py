"""SWT3 AI Witness SDK — Threaded Flush Buffer.

Non-blocking background buffer that collects witness payloads and flushes
them to the /api/v1/witness/batch endpoint. The developer's inference call
returns immediately — witnessing happens in the background.

Architecture:
    - Daemon thread + queue.Queue (no asyncio dependency)
    - Flush triggers: count threshold OR time interval (whichever first)
    - Dead-letter queue: failed payloads survive network outages
    - atexit handler for graceful final flush
    - Exponential backoff retry on transient failures

Resilience (Flight Recorder mode):
    When the witness endpoint is unreachable, payloads move to a dead-letter
    deque instead of being dropped. On the next successful flush cycle, the
    backlog drains automatically. A configurable cap (max_retry_buffer)
    prevents OOM during extended outages.
"""

from __future__ import annotations

import atexit
import collections
import json
import logging
import os
import queue
import re
import threading
import time
from typing import Any, Deque, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .types import WitnessConfig, WitnessPayload, WitnessReceipt
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .wal import WriteAheadLog

logger = logging.getLogger("swt3_ai")

# Maximum payloads held in the dead-letter queue before oldest are dropped
DEFAULT_MAX_RETRY_BUFFER = 5000


class WitnessBuffer:
    """Threaded buffer that batches and flushes witness payloads.

    The buffer operates as a "Flight Recorder" — if the witness endpoint
    is down, payloads accumulate in memory and drain when connectivity
    is restored. This ensures zero anchor loss during transient outages.
    """

    def __init__(
        self,
        config: WitnessConfig,
        max_retry_buffer: int = DEFAULT_MAX_RETRY_BUFFER,
        on_flush: Optional[Any] = None,
        wal: Optional["WriteAheadLog"] = None,
    ) -> None:
        self._config = config
        self._on_flush = on_flush
        self._wal = wal
        self._wal_seq_map: Dict[int, int] = {}  # id(payload) -> WAL seq
        self._queue: queue.Queue[WitnessPayload] = queue.Queue()
        self._dead_letter: Deque[WitnessPayload] = collections.deque(
            maxlen=max_retry_buffer,
        )
        self._lock = threading.Lock()
        self._stopped = False
        self._receipts: List[WitnessReceipt] = []
        self._consecutive_failures = 0
        self._cta_shown = False
        self._token_accumulator: int = 0  # cumulative tokens since last flush

        # Start daemon flush thread
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

        # Register graceful shutdown
        atexit.register(self.stop)

    def enqueue(self, payload: WitnessPayload) -> None:
        """Add a payload to the buffer. Non-blocking."""
        if self._stopped:
            logger.warning("Buffer is stopped — payload dropped for %s", payload.procedure_id)
            return

        # WAL: replay protection + persist to disk
        if self._wal is not None:
            seq = self._wal.append(payload)
            if seq == -1:
                # Duplicate fingerprint -- silently skip
                return
            self._wal_seq_map[id(payload)] = seq

        # Track token accumulation for token_budget flush trigger
        tokens = (payload.ai_input_tokens or 0) + (payload.ai_output_tokens or 0)
        if tokens > 0:
            self._token_accumulator += tokens
        self._queue.put(payload)

    def enqueue_many(self, payloads: List[WitnessPayload]) -> None:
        """Add multiple payloads to the buffer."""
        for p in payloads:
            self.enqueue(p)

    def flush(self) -> List[WitnessReceipt]:
        """Force-flush all buffered payloads. Called by atexit or manually."""
        payloads = self._drain()
        # Prepend dead-letter items so they flush first
        if self._dead_letter:
            with self._lock:
                dl_items = list(self._dead_letter)
                self._dead_letter.clear()
            payloads = dl_items + payloads
        if not payloads:
            return []
        return self._send_batch(payloads)

    def stop(self) -> List[WitnessReceipt]:
        """Stop the buffer and flush remaining payloads.

        After stop(), no more payloads are accepted. Any items remaining
        in the dead-letter queue after the final flush are logged and lost.
        """
        if self._stopped:
            return []
        self._stopped = True
        receipts = self.flush()
        # Log any remaining dead-letter items (can't retry after stop)
        remaining = len(self._dead_letter)
        if remaining > 0:
            logger.warning(
                "Buffer stopped with %d payloads still in dead-letter queue "
                "(endpoint unreachable — anchors lost)",
                remaining,
            )
        return receipts

    async def flush_async(self) -> List[WitnessReceipt]:
        """Async force-flush. Runs the sync flush in a thread pool executor."""
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.flush)

    async def stop_async(self) -> List[WitnessReceipt]:
        """Async stop. Runs the sync stop in a thread pool executor."""
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.stop)

    @property
    def pending(self) -> int:
        """Number of payloads waiting in the buffer (includes dead-letter)."""
        return self._queue.qsize() + len(self._dead_letter)

    @property
    def dead_letter_count(self) -> int:
        """Number of payloads in the dead-letter queue awaiting retry."""
        return len(self._dead_letter)

    @property
    def tokens_since_flush(self) -> int:
        """Cumulative tokens accumulated since last flush (for token_budget monitoring)."""
        return self._token_accumulator

    @property
    def receipts(self) -> List[WitnessReceipt]:
        """All receipts from completed flushes."""
        with self._lock:
            return list(self._receipts)

    def _drain(self) -> List[WitnessPayload]:
        """Drain all payloads from the queue."""
        payloads: List[WitnessPayload] = []
        while True:
            try:
                payloads.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return payloads

    def _flush_loop(self) -> None:
        """Background loop — flush on count threshold or time interval."""
        buffer: List[WitnessPayload] = []
        last_flush = time.monotonic()

        while not self._stopped:
            # Drain ALL available items from the queue (collects full inference batches)
            try:
                payload = self._queue.get(timeout=0.5)
                buffer.append(payload)
                # Drain any additional items that arrived during the wait
                while True:
                    try:
                        buffer.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                pass

            elapsed = time.monotonic() - last_flush
            token_budget_hit = (
                self._config.token_budget is not None
                and self._token_accumulator >= self._config.token_budget
            )
            should_flush = (
                len(buffer) >= self._config.buffer_size
                or (len(buffer) > 0 and elapsed >= self._config.flush_interval)
                or (len(buffer) > 0 and token_budget_hit)
            )

            # Also flush dead-letter backlog if we have new items to send
            # (piggyback retry on regular flush cycles)
            if should_flush:
                # Prepend dead-letter items
                if self._dead_letter:
                    with self._lock:
                        dl_items = list(self._dead_letter)
                        self._dead_letter.clear()
                    buffer = dl_items + buffer
                    logger.info(
                        "Draining %d dead-letter payloads with %d new",
                        len(dl_items), len(buffer) - len(dl_items),
                    )

                self._send_batch(buffer)
                buffer = []
                last_flush = time.monotonic()
                self._token_accumulator = 0

            # If we have dead-letter items but no new items, retry periodically
            # Use exponential backoff: 10s, 20s, 40s, 80s, max 300s
            elif self._dead_letter and not buffer:
                backoff = min(10 * (2 ** self._consecutive_failures), 300)
                if elapsed >= backoff:
                    with self._lock:
                        dl_items = list(self._dead_letter)
                        self._dead_letter.clear()
                    logger.info(
                        "Retrying %d dead-letter payloads (attempt after %.0fs backoff)",
                        len(dl_items), backoff,
                    )
                    self._send_batch(dl_items)
                    last_flush = time.monotonic()

    def _send_batch(self, payloads: List[WitnessPayload]) -> List[WitnessReceipt]:
        """Send a batch of payloads to the configured flush target.

        Routes to Redis Streams when flush_target="redis", otherwise
        uses the standard HTTP batch endpoint. On final failure, payloads
        go to the dead-letter queue.
        """
        if not payloads:
            return []

        # Route to Redis if configured
        if self._config.flush_target == "redis":
            return self._send_redis(payloads)

        url = f"{self._config.endpoint}/api/v1/witness/batch"
        body = json.dumps({
            "witnesses": [p.to_dict() for p in payloads],
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._config.api_key}",
        }

        receipts: List[WitnessReceipt] = []
        last_error: Optional[str] = None

        for attempt in range(self._config.max_retries):
            try:
                req = Request(url, data=body, headers=headers, method="POST")
                with urlopen(req, timeout=self._config.timeout) as resp:
                    result: Dict[str, Any] = json.loads(resp.read().decode("utf-8"))

                # Parse receipts
                for r in result.get("receipts", []):
                    receipts.append(WitnessReceipt(
                        procedure_id=r.get("procedure_id", ""),
                        verdict=r.get("verdict", "UNKNOWN"),
                        swt3_anchor=r.get("swt3_anchor", ""),
                        clearing_level=r.get("clearing_level", 0),
                        witnessed_at=r.get("witnessed_at", ""),
                        verification_url=r.get("verification_url", ""),
                        ok=r.get("ok", False),
                        error=r.get("error"),
                    ))

                with self._lock:
                    self._receipts.extend(receipts)
                    self._consecutive_failures = 0  # Reset on success

                # WAL: mark flushed entries
                if self._wal is not None:
                    max_seq = 0
                    for p in payloads:
                        s = self._wal_seq_map.pop(id(p), 0)
                        if s > max_seq:
                            max_seq = s
                    if max_seq > 0:
                        self._wal.mark_flushed(max_seq)

                accepted = result.get("accepted", 0)
                rejected = result.get("rejected", 0)
                if rejected > 0:
                    logger.warning(
                        "Batch flush: %d accepted, %d rejected", accepted, rejected
                    )
                else:
                    logger.debug("Batch flush: %d anchors accepted", accepted)

                if not self._cta_shown and accepted > 0:
                    self._cta_shown = True
                    print(
                        f"\n  [SWT3] {accepted} anchors delivered to {self._config.endpoint}"
                        f"\n  [SWT3] Dashboard & audit reports \u2192 https://sovereign.tenova.io/signup?ref=sdk"
                        f"\n  [SWT3] EU AI Act high-risk deadline: Dec 2, 2027. GPAI obligations enforceable now.\n"
                    )

                # Invoke on_flush callback (never let callback errors break the pipeline)
                if self._on_flush and receipts:
                    try:
                        self._on_flush(payloads, receipts)
                    except Exception as cb_err:
                        logger.warning("on_flush callback error (non-fatal): %s", cb_err)

                return receipts

            except HTTPError as e:
                raw_err = e.read().decode("utf-8", errors="replace")[:200]
                # Scrub any key material from error response body
                last_error = f"HTTP {e.code}: {re.sub(r'(?i)(?:Bearer|Authorization|api[_-]?key|signing[_-]?key)\\s*[^\\s,;\"]{4,}', '[REDACTED]', raw_err)}"
                if e.code < 500:
                    # Client error (4xx) — don't retry, don't dead-letter
                    # These are validation errors, not transient failures
                    logger.error("Batch flush failed (client error, no retry): %s", last_error)
                    return receipts
                logger.warning("Batch flush attempt %d failed: %s", attempt + 1, last_error)

            except (URLError, OSError, TimeoutError) as e:
                last_error = str(e)
                logger.warning("Batch flush attempt %d failed: %s", attempt + 1, last_error)

            # Exponential backoff: 1s, 2s, 4s
            if attempt < self._config.max_retries - 1:
                time.sleep(2 ** attempt)

        # ── All retries exhausted — move to dead-letter queue ──
        with self._lock:
            self._consecutive_failures += 1
            before = len(self._dead_letter)
            for p in payloads:
                self._dead_letter.append(p)
            after = len(self._dead_letter)
            dropped = len(payloads) - (after - before)

        if dropped > 0:
            logger.error(
                "Dead-letter queue full: %d payloads added, %d oldest dropped "
                "(cap: %d). Last error: %s",
                len(payloads), dropped, self._dead_letter.maxlen, last_error,
            )
        else:
            logger.warning(
                "Endpoint unreachable — %d payloads moved to dead-letter queue "
                "(total: %d, will retry). Last error: %s",
                len(payloads), after, last_error,
            )

        return receipts

    def _send_redis(self, payloads: List[WitnessPayload]) -> List[WitnessReceipt]:
        """Push payloads to a Redis Stream for high-throughput decoupled intake.

        The Axiom Engine (or a separate processor) consumes from this stream
        and writes to the ledger. This decouples intake speed from storage
        speed -- the "Shock Absorber" pattern for token factory workloads.

        Requires: redis package (pip install redis)
        """
        try:
            import redis as redis_lib
        except ImportError:
            logger.error(
                "Redis flush target requires the 'redis' package. "
                "Install with: pip install redis"
            )
            with self._lock:
                for p in payloads:
                    self._dead_letter.append(p)
            return []

        redis_url = self._config.redis_url or os.environ.get("SWT3_REDIS_URL", "redis://localhost:6379")
        stream_name = self._config.redis_stream or os.environ.get("SWT3_REDIS_STREAM", "swt3:anchors")

        try:
            r = redis_lib.from_url(redis_url, decode_responses=True)

            # XADD each payload to the stream. Redis Streams guarantee
            # ordering and persistence -- "Sequential Truth" for audits.
            receipts: List[WitnessReceipt] = []
            for p in payloads:
                r.xadd(stream_name, {
                    "payload": json.dumps(p.to_dict()),
                    "api_key": self._config.api_key,
                    "clearing_level": str(p.clearing_level),
                    "procedure_id": p.procedure_id,
                })
                receipts.append(WitnessReceipt(
                    procedure_id=p.procedure_id,
                    verdict="QUEUED",
                    swt3_anchor="",
                    clearing_level=p.clearing_level,
                    witnessed_at="",
                    verification_url="",
                    ok=True,
                    error=None,
                ))

            with self._lock:
                self._receipts.extend(receipts)
                self._consecutive_failures = 0

            # WAL: mark flushed entries
            if self._wal is not None:
                max_seq = 0
                for p in payloads:
                    s = self._wal_seq_map.pop(id(p), 0)
                    if s > max_seq:
                        max_seq = s
                if max_seq > 0:
                    self._wal.mark_flushed(max_seq)

            logger.debug(
                "Redis flush: %d payloads pushed to stream '%s'",
                len(payloads), stream_name,
            )

            if self._on_flush and receipts:
                try:
                    self._on_flush(payloads, receipts)
                except Exception as cb_err:
                    logger.warning("on_flush callback error (non-fatal): %s", cb_err)

            return receipts

        except Exception as e:
            logger.warning("Redis flush failed: %s — moving to dead-letter", e)
            with self._lock:
                self._consecutive_failures += 1
                for p in payloads:
                    self._dead_letter.append(p)
            return []
