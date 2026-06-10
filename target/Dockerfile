FROM python:3.11-slim

WORKDIR /app

COPY target/app.py /app/app.py

RUN pip install --no-cache-dir flask

EXPOSE 5000

CMD ["python", "app.py"]
