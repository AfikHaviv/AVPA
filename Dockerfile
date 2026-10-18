FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

COPY src ./src
COPY docs ./docs

ENV FLASK_APP=cve_pipeline.app
ENV PYTHONPATH=/app/src

EXPOSE 5000

# .env.enc is mounted (not baked into the image) and decrypted at runtime
# using the MASTER_KEY secret, e.g.:
#   docker run -e MASTER_KEY=... -v %cd%/.env.enc:/app/.env.enc -p 5000:5000 cve-exploit-llm-pipeline
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
