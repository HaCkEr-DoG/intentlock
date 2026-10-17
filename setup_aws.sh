#!/usr/bin/env bash
# setup_aws.sh — one-time AWS configuration for IntentLock
# Run this once to set up credentials and enable the Bedrock model.
#
# Usage:  bash setup_aws.sh

set -e

echo "=== IntentLock AWS Setup ==="
echo ""
echo "You need an AWS account with Bedrock access. If you don't have one:"
echo "  https://aws.amazon.com/free"
echo ""
echo "Step 1: Install the AWS CLI if not already installed"
if ! command -v aws &>/dev/null; then
  echo "  AWS CLI not found. Installing via Homebrew..."
  brew install awscli
else
  echo "  AWS CLI already installed: $(aws --version)"
fi

echo ""
echo "Step 2: Configure credentials"
echo "  Run: aws configure"
echo "  You'll need:"
echo "    AWS Access Key ID      (from IAM → Users → your user → Security credentials)"
echo "    AWS Secret Access Key"
echo "    Default region:        us-east-1"
echo "    Output format:         json"
echo ""
echo "  Press ENTER when ready to run 'aws configure', or Ctrl+C to skip."
read -r
aws configure

echo ""
echo "Step 3: Verify identity"
aws sts get-caller-identity

echo ""
echo "Step 4: Enable Bedrock model access"
echo "  1. Open: https://console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess"
echo "  2. Click 'Manage model access'"
echo "  3. Find 'Claude Haiku 4.5' under Anthropic"
echo "  4. Check the box and click 'Save changes'"
echo "  5. Wait ~1 minute for access to activate"
echo ""
echo "Step 5: Test Bedrock access"
echo "  Press ENTER when model access is enabled..."
read -r
aws bedrock list-foundation-models --region us-east-1 --query "modelSummaries[?contains(modelId,'haiku')].{id:modelId,name:modelName}" --output table 2>&1 | head -20

echo ""
echo "=== AWS setup complete ==="
echo "Now start the Decider server and run the demo:"
echo ""
echo "  Terminal 1:"
echo "    source .venv/bin/activate"
echo "    strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 \\"
echo "      --device mlx --port 8099"
echo ""
echo "  Terminal 2:"
echo "    source .venv/bin/activate"
echo "    python agent_demo.py"
