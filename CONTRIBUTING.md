# Contributing

1. `uv sync` and `(cd console && npm ci)`.
2. Keep changes inside the layer rules (`uv run lint-imports`): core ← security ← modules ← services.
3. Before opening a PR, run:
   ```bash
   uv run ruff check neurawall tests && uv run ruff format --check neurawall tests
   uv run mypy neurawall && uv run lint-imports && uv run pytest
   (cd console && npm run build)
   ```
4. Schema changes need an Alembic migration. A test fails if models and migrations drift:
   ```bash
   uv run python -c "from sqlalchemy import create_engine; from alembic import command; \
   from neurawall.services.control_plane.db import alembic_config; e=create_engine('sqlite://'); \
   c=e.connect(); command.upgrade(alembic_config(c),'head'); \
   command.revision(alembic_config(c), message='describe change', autogenerate=True)"
   ```
5. Changes to tier authority, bundle format or the security model need an ADR in `docs/adr/`.
6. Configuration changes: document the field with a `#:` comment and regenerate
   `docs/configuration.md` with `uv run python scripts/gen_config_docs.py`.
