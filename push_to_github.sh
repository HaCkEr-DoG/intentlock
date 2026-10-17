#!/usr/bin/env bash
# push_to_github.sh — create GitHub repo and push IntentLock
# Prerequisites: gh CLI installed and authenticated (gh auth login)
# Usage: bash push_to_github.sh

set -e

REPO_NAME="intentlock"
DESCRIPTION="Provenance-aware temporal policy engine for agentic InfraOps using Strands Decider 2B"

echo "=== Creating GitHub repo: $REPO_NAME ==="
gh repo create "$REPO_NAME" \
  --public \
  --description "$DESCRIPTION" \
  --source . \
  --push

echo ""
echo "=== Done! ==="
REMOTE_URL=$(git remote get-url origin)
echo "Repo: $REMOTE_URL"
echo ""
echo "Add this URL to ARTICLE_DRAFT.md before submitting:"
echo "  sed -i '' 's|\[YOUR GITHUB LINK HERE\]|$REMOTE_URL|' ARTICLE_DRAFT.md"
