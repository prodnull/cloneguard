FROM python:3.12-slim

WORKDIR /app

# Install cloneguard
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Copy integration test script
COPY tests/integration/run_tests.sh /run_tests.sh
RUN chmod +x /run_tests.sh

# Create test repos inside the container (no payload bleed to host)
RUN mkdir -p /repos

ENTRYPOINT ["/run_tests.sh"]
