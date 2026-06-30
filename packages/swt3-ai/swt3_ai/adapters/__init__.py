"""SWT3 AI Witness SDK -- Provider Adapters.

Adapters:
    openai      - OpenAI / AsyncOpenAI (ChainProxy)
    anthropic   - Anthropic / AsyncAnthropic (ChainProxy)
    bedrock     - AWS Bedrock Runtime (ChainProxy)
    litellm     - LiteLLM module (namespace wrap)
    ollama      - Ollama via OpenAI-compatible API (auto-detected)
    vllm        - vLLM via OpenAI-compatible API (explicit wrap)
    vllm_native - vLLM AsyncLLMEngine direct hook (Token Factory Observer)
    langchain   - LangChain callback handler (any LLM)
    dynamo      - NVIDIA Dynamo async generator decorator (Layer 1, zero deps)
    triton      - NVIDIA Triton Inference Server plugin (Python backend, BSD)
    cerebras    - Cerebras WSE-3 SdkRuntime host-side witness (wafer-scale)
    google_adk  - Google ADK Agent.run() witness (duck-typed)
    crewai      - CrewAI Crew.kickoff() witness (duck-typed)
    a2a         - A2A Agent.send() witness (duck-typed, Google Agent-to-Agent)
    foundry     - Microsoft Foundry Agent.execute() witness (duck-typed)
    agt         - Microsoft AGT policy engine evaluate() witness (duck-typed)
    qdrant      - Qdrant vector DB search() witness (RAG pipeline, AI-RAG.1)
    cohere      - Cohere chat() and chat_stream() witness (V2 API)
    langgraph   - LangGraph CompiledGraph invoke/stream witness (duck-typed)
    skillspector - NVIDIA SkillSpector scan result witness (static analysis, AI-SEC.1)
"""
