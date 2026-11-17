# SWT3 Witness Sidecar Injection

Inject a passive SWT3 witness sidecar into existing Kubernetes Deployments.
The sidecar watches a shared volume for AI telemetry and witnesses it through
the SWT3 protocol. No traffic interception, no iptables, no proxy.

## How It Works

1. Your app writes AI call telemetry as JSONL to a shared `emptyDir` volume
2. The sidecar reads new lines, extracts model/tokens/latency/status
3. The sidecar witnesses events through the SWT3 API
4. Raw prompts and completions are never captured (clearing levels apply)

## Telemetry JSON Schema

Your app writes one JSON object per line to any `.jsonl` file in `/shared/swt3/`:

```json
{"model":"gpt-4","tokens_in":500,"tokens_out":200,"latency_ms":1200,"status":"ok","timestamp":"2026-11-14T12:00:00Z"}
```

**Fields:**
- `model` (required): Model identifier (e.g., `gpt-4`, `claude-sonnet-4-20250514`)
- `tokens_in`: Input/prompt token count
- `tokens_out`: Output/completion token count
- `latency_ms`: Request latency in milliseconds
- `status`: `ok`, `error`, or provider error code
- `timestamp`: ISO 8601 timestamp
- `agent_id`: Optional service identifier (overrides pod-level agent ID)
- `request_id`: Optional request ID for deduplication

OTel span JSON with `gen_ai.*` semantic convention attributes is also supported.

## Quick Start

### 1. Create the API key secret

```bash
kubectl create secret generic swt3-api-key \
  --from-literal=api-key=axm_live_YOUR_KEY \
  -n your-namespace
```

### 2. Apply the sidecar overlay

**Option A: Kustomize (all Deployments in a directory)**

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yaml  # your existing Deployment

patches:
  - path: sidecar-overlay/sidecar-patch.yaml
    target:
      kind: Deployment
  - path: sidecar-overlay/app-volume-patch.yaml
    target:
      kind: Deployment
      name: my-ai-service  # target specific Deployment
```

Then edit `app-volume-patch.yaml` to replace `YOUR_APP_CONTAINER` with your
container name.

```bash
kustomize build . | kubectl apply -f -
```

**Option B: Kustomize (label selector)**

Target only Deployments with a specific label:

```yaml
patches:
  - path: sidecar-overlay/sidecar-patch.yaml
    target:
      kind: Deployment
      labelSelector: "swt3.io/witness=enabled"
```

Then label your Deployments:

```bash
kubectl label deployment my-ai-service swt3.io/witness=enabled
```

**Option C: Helm extraContainers**

If your Helm chart supports `extraContainers` and `extraVolumes`:

```bash
helm upgrade my-release my-chart \
  -f swt3-witness/helm/swt3-witness/examples/sidecar-values.yaml
```

### 3. Add the volume mount to your app

Your app container needs to mount the shared volume and write telemetry to it.
The simplest approach is appending to a JSONL file after each AI call:

**Python:**
```python
import json, time

def log_ai_call(model, tokens_in, tokens_out, latency_ms, status="ok"):
    with open("/shared/swt3/telemetry.jsonl", "a") as f:
        f.write(json.dumps({
            "model": model,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "latency_ms": latency_ms,
            "status": status,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }) + "\n")
```

**Node.js:**
```javascript
const fs = require('fs');

function logAICall(model, tokensIn, tokensOut, latencyMs, status = 'ok') {
  fs.appendFileSync('/shared/swt3/telemetry.jsonl',
    JSON.stringify({
      model, tokens_in: tokensIn, tokens_out: tokensOut,
      latency_ms: latencyMs, status,
      timestamp: new Date().toISOString(),
    }) + '\n'
  );
}
```

### 4. Verify

```bash
# Check the sidecar is running
kubectl get pods -l app=my-ai-service -o jsonpath='{.items[0].status.containerStatuses[*].name}'

# Check sidecar health
kubectl exec deploy/my-ai-service -c swt3-witness-sidecar -- wget -qO- http://localhost:9091/healthz

# Check metrics
kubectl exec deploy/my-ai-service -c swt3-witness-sidecar -- wget -qO- http://localhost:9091/metrics
```

## File Rotation

The sidecar tracks byte offsets per file. Apps can:

- **Append forever**: The sidecar reads only new lines. File size is bounded by the
  emptyDir `sizeLimit` (default 100Mi).
- **Rotate files**: Write to `telemetry-{date}.jsonl`. The sidecar discovers new files
  automatically. Old files can be deleted by the app.
- **Truncate and rewrite**: The sidecar detects truncation and re-reads from byte 0.

## Mutating Webhook (Phase 2)

A mutating admission webhook that auto-injects the sidecar into any pod with
`swt3.io/inject: "true"` is planned for Phase 2. The Kustomize approach above
avoids the complexity of webhook certificate management and webhook failure
domains. If your organization needs automatic injection at scale, contact
engineering@tenovaai.com.

## Security

- **Non-root**: The sidecar runs as a non-root user
- **Read-only filesystem**: No writes to the container filesystem
- **Read-only volume**: The sidecar mounts the shared volume as read-only
- **Capabilities dropped**: All Linux capabilities are dropped
- **No network privileges**: The sidecar only makes outbound HTTPS to the SWT3 endpoint
- **No raw data**: Prompts and completions are never captured or transmitted
