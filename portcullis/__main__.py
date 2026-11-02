"""Entry point so the gate runs as python -m portcullis."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
