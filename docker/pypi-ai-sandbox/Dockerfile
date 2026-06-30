FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip

WORKDIR /sandbox
COPY entrypoint.py /sandbox/entrypoint.py

ENTRYPOINT ["python", "/sandbox/entrypoint.py"]
