# Contributing to SWT3

Thank you for your interest in the SWT3 AI Witness Protocol.

## Reporting Issues

Use [GitHub Issues](https://github.com/tenova-labs/swt3-ai/issues) for bugs and feature requests. Please include:

- SDK language (Python or TypeScript)
- SDK version (`swt3-ai` or `@tenova/swt3-ai`)
- AI provider (OpenAI, Anthropic, Vercel AI SDK, etc.)
- Steps to reproduce

## Development Setup

### Python SDK

```bash
cd packages/swt3-ai
pip install -e ".[all]"
python -m swt3_ai.demo
pytest
```

### TypeScript SDK

```bash
cd packages/swt3-ai-ts
npm install
npm run build
npx swt3-demo
npm test
```

## Pull Requests

1. Fork the repository and create a feature branch
2. Ensure cross-language fingerprint parity (see `test-vectors.json`)
3. Add tests for new functionality
4. Follow existing code style
5. Open a PR with a clear description of the change

## Protocol Lock

The SWT3 fingerprint formula and clearing level semantics (0-3) are locked. Changes to the core protocol require an RFC discussion in GitHub Issues before any implementation.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

## Questions?

- [SDK Documentation](https://sovereign.tenova.io/docs/)
- [engineering@tenovaai.com](mailto:engineering@tenovaai.com)
