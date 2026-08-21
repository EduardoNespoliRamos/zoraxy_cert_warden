#!/usr/bin/env bash
set -euo pipefail

REPO="EduardoNespoliRamos/zoraxy_cert_warden"
BRANCH="main"

echo "Configuring branch protection rules for ${REPO}#${BRANCH}..."

# Check whether the repository belongs to an organization. User-owned
# repositories do not support user/team push restrictions through the API.
OWNER_TYPE=$(gh api "repos/${REPO}" --jq '.owner.type')

if [[ "$OWNER_TYPE" == "Organization" ]]; then
  RESTRICTIONS_JSON='"restrictions": {"users": ["EduardoNespoliRamos"], "teams": []},'
else
  echo "Note: repository is owned by a user ($OWNER_TYPE). Push restrictions are implicit."
  RESTRICTIONS_JSON='"restrictions": null,'
fi

gh api "repos/${REPO}/branches/${BRANCH}/protection" \
  --method PUT \
  --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Validate source branch",
      "unit-tests",
      "e2e",
      "build",
      "integration-matrix"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  ${RESTRICTIONS_JSON}
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
EOF

echo "Branch protection rules applied to ${REPO}#${BRANCH}"
