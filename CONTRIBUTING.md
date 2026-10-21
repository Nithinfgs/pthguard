# Contributing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check . && ruff format --check . && mypy
```

- Every rule needs a test in `tests/test_analyzer.py` (positive **and** a near-miss that must stay quiet).
- Test fixtures must be inert: strings and unexecuted functions only. Never commit working malware.
- New IOCs go in `src/pthguard/iocs.json` with a public source URL in `_source`.
- Keep runtime dependencies at zero.
