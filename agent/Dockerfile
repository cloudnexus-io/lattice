# Requires BCC installed in the base image. BCC is complex to install in slim images.
# In a real scenario, use a base image like 'quay.io/iovisor/bcc:latest' or similar.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-generic
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages
COPY . .
CMD ["python3", "agent.py"]
