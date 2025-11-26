# Use a small Python base
FROM python:3.11-slim

# best practice: set working dir
WORKDIR /app

# install system deps (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# copy files
COPY requirements.txt .

# install python deps
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# run uvicorn
ENV PORT 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
