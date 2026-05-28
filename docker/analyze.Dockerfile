FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

USER nobody

ENV VANGUARDX_ANTHROPIC_API_KEY=""
ENV VANGUARDX_DATABASE_URL="sqlite+aiosqlite:///./data/vanguard.db"

ENTRYPOINT ["vanguard-x", "analyze"]
