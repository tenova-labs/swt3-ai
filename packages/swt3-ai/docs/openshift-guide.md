# SWT3 AI Witness SDK on OpenShift

Deployment patterns for running SWT3-witnessed AI workloads on Red Hat OpenShift and OpenShift AI.

## Architecture

SWT3 runs as a library inside your inference container. No sidecar, no operator, no CRDs. Your application imports the SDK, wraps the AI client, and anchors are sent to the Axiom Engine over HTTPS.

```
+-----------------------+         +-------------------+
| OpenShift Pod         |         | Axiom Engine      |
|                       |  HTTPS  |                   |
|  [Your App]           | ------> | /api/v1/witness   |
|    + swt3-ai SDK      |         |                   |
|    + Ollama / vLLM    |         +-------------------+
+-----------------------+
```

## Quick Start

### 1. Add SDK to your container image

Python:
```dockerfile
RUN pip install swt3-ai
```

TypeScript:
```dockerfile
RUN npm install @tenova/swt3-ai
```

### 2. Configure via environment

Create a Secret with your SWT3 credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: swt3-credentials
  namespace: ai-workloads
type: Opaque
stringData:
  SWT3_ENDPOINT: "https://sovereign.tenova.io"
  SWT3_API_KEY: "axm_live_your_key_here"
  SWT3_TENANT_ID: "YOUR_TENANT_ID"
  SWT3_CLEARING_LEVEL: "1"
```

### 3. Reference in your Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-inference
  namespace: ai-workloads
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ai-inference
  template:
    metadata:
      labels:
        app: ai-inference
    spec:
      containers:
        - name: inference
          image: your-registry/ai-app:latest
          envFrom:
            - secretRef:
                name: swt3-credentials
          ports:
            - containerPort: 8080
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "2"
```

## Ollama Sidecar Pattern

Run Ollama as a sidecar container in the same pod. The SDK auto-detects Ollama when the OpenAI client points to port 11434.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama-witnessed
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ollama-witnessed
  template:
    metadata:
      labels:
        app: ollama-witnessed
    spec:
      containers:
        # Your application
        - name: app
          image: your-registry/ai-app:latest
          envFrom:
            - secretRef:
                name: swt3-credentials
          env:
            - name: OLLAMA_HOST
              value: "http://localhost:11434"

        # Ollama sidecar
        - name: ollama
          image: ollama/ollama:latest
          ports:
            - containerPort: 11434
          resources:
            requests:
              memory: "4Gi"
              cpu: "2"
            limits:
              nvidia.com/gpu: "1"  # if GPU available
          volumeMounts:
            - name: models
              mountPath: /root/.ollama

      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: ollama-models
```

Application code (Python):
```python
from openai import OpenAI
from swt3_ai import Witness

witness = Witness.from_env()  # reads SWT3_* env vars
client = witness.wrap(OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama",
))

# Auto-detected as Ollama, provider="ollama" in anchors
response = client.chat.completions.create(
    model="llama3.2",
    messages=[{"role": "user", "content": "Summarize this contract."}],
)
```

## vLLM Serving Pattern

vLLM runs as a separate Deployment with a Service. Use `wrap_vllm()` for accurate provider lineage.

```yaml
# vLLM serving deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-server
  template:
    metadata:
      labels:
        app: vllm-server
    spec:
      containers:
        - name: vllm
          image: vllm/vllm-openai:latest
          args:
            - "--model"
            - "mistralai/Mistral-7B-Instruct-v0.3"
            - "--port"
            - "8000"
          ports:
            - containerPort: 8000
          resources:
            limits:
              nvidia.com/gpu: "1"
---
apiVersion: v1
kind: Service
metadata:
  name: vllm-service
spec:
  selector:
    app: vllm-server
  ports:
    - port: 8000
      targetPort: 8000
```

Application code:
```python
from openai import OpenAI
from swt3_ai import Witness
from swt3_ai.adapters.vllm import wrap_vllm

witness = Witness.from_env()
client = OpenAI(
    base_url="http://vllm-service:8000/v1",
    api_key="token",
)
witnessed = wrap_vllm(client, witness)

response = witnessed.chat.completions.create(
    model="mistralai/Mistral-7B-Instruct-v0.3",
    messages=[{"role": "user", "content": "Analyze risk factors."}],
)
```

## LangChain on OpenShift

For LangChain pipelines, use the callback handler. No proxy wrapping needed.

```python
from langchain_openai import ChatOpenAI
from swt3_ai import Witness
from swt3_ai.adapters.langchain import SWT3CallbackHandler

witness = Witness.from_env()
handler = SWT3CallbackHandler(witness)

llm = ChatOpenAI(
    model="llama3.2",
    base_url="http://localhost:11434/v1",
    api_key="ollama",
    callbacks=[handler],
)

response = llm.invoke("What are the compliance requirements?")
```

## Network Policy

Restrict egress to only your Axiom Engine endpoint:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: swt3-egress
  namespace: ai-workloads
spec:
  podSelector:
    matchLabels:
      app: ai-inference
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to: []
      ports:
        - port: 53
          protocol: UDP
    # Allow HTTPS to Axiom Engine
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
          protocol: TCP
```

For air-gapped environments, use the SWT3 offline pulse bundle instead of live egress. See the air-gap documentation.

## ConfigMap for Policy-as-Code

Store SWT3 configuration in a ConfigMap for version-controlled policy binding:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: swt3-config
data:
  .swt3.yaml: |
    endpoint: https://sovereign.tenova.io
    tenant_id: YOUR_TENANT_ID
    clearing_level: 1
    procedures:
      - AI-INF.1
      - AI-DRIFT.1
      - AI-GRD.1
    jurisdiction: US
    purpose_class: contract_analysis
```

Mount it and point the SDK:

```yaml
env:
  - name: SWT3_CONFIG_PATH
    value: /etc/swt3/.swt3.yaml
volumeMounts:
  - name: swt3-config
    mountPath: /etc/swt3
volumes:
  - name: swt3-config
    configMap:
      name: swt3-config
```

## Health Checks

The SDK does not expose its own health endpoint. Health checks should target your application. The SDK operates in fire-and-forget mode with automatic retries -- if the Axiom Engine is unreachable, anchors are buffered and retried without blocking inference.

## OpenShift AI (RHOAI) Integration

If using Red Hat OpenShift AI (formerly RHODS):

1. Add `swt3-ai` to your notebook image or runtime image
2. Configure credentials via OpenShift Secrets
3. The SDK works with any ServingRuntime (KServe, ModelMesh, or custom)
4. For KServe InferenceService, wrap the client in your pre/post-processing container

The SDK has zero external dependencies beyond the Python or Node.js standard library. It does not require cluster-level permissions, operators, or CRDs.

## Security Considerations

- API keys belong in Secrets, never ConfigMaps
- Use RBAC to restrict Secret access to the inference namespace
- The SDK communicates over TLS 1.2+ only
- Signing keys (HMAC-SHA256) should be stored in a separate Secret with tighter access
- For classified workloads (clearing_level=3), ensure the egress path meets your enclave requirements
