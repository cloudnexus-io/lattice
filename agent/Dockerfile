# Lattice Security Agent Dockerfile
# Requires BCC installed in the base image for real eBPF support
FROM ubuntu:24.04

# Install BCC and dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-bpfcc \
    bpfcc-tools \
    libbpfcc-dev \
    procps \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/* || true

# Try to install kernel headers if available, otherwise skip
RUN apt-get update && apt-get install -y linux-headers-amd64 || true

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages || true

# Copy agent code and eBPF programs
COPY agent.py .
COPY security_hooks.bpf.c .

# Run with entrypoint that tries eBPF first, falls back to proc-based monitoring
CMD ["python3", "-u", "agent.py"]
