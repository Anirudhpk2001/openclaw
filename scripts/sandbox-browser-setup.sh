#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="openclaw-sandbox-browser:bookworm-slim"

# SECURITY NOTICE: The LLM referenced or used in this project must be replaced with an approved LLM from the organization's allow list. Using unapproved LLMs violates security policy and may introduce privacy risks and vulnerabilities. Please consult your security team for the list of approved LLMs.

docker build -t "${IMAGE_NAME}" -f Dockerfile.sandbox-browser .
echo "Built ${IMAGE_NAME}"