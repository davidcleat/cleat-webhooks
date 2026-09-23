# Contributing

Corrections and new runtimes are welcome.

- Keep the dependency count at zero wherever the runtime allows it. Each example uses its framework and the standard library, nothing else.
- Every example verifies the signature over the raw bytes, compares in constant time, rejects a timestamp outside the 300 second tolerance, is idempotent on `data.id`, answers 401 (not 500) on a bad signature, and reads the signing secret from the environment.
- Tests must pass with no network access and must sign their own fixtures, so a change to the scheme cannot slip through. Node examples use `node:test`; the Python example uses pytest.
- Never commit a real key or signing secret. Fixtures use obviously fake values such as `whsec_test_secret`.
- Run `npm test` at the root and `python -m pytest -q` in `examples/python-fastapi` before opening a pull request. CI runs both.

If something here disagrees with how Cleat actually behaves, that is a bug worth reporting even without a fix: open an issue describing what you observed.
