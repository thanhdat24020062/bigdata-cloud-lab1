FROM python:3.11-slim
RUN pip install --no-cache-dir boto3==1.28.0
COPY s3lab.py /opt/s3lab.py
WORKDIR /opt
CMD ["sleep", "infinity"]
