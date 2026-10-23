import os

# Keep the test suite deterministic and offline, even if the developer's shell
# has production-like settings exported.
os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("LEXICON_ENABLED", "true")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "1000")
