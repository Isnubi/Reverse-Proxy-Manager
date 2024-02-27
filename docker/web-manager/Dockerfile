FROM python:3
LABEL maintainer="Isnubi"

WORKDIR /app

COPY ./ /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "app.py"]