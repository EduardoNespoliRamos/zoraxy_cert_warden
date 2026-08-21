#!/usr/bin/env bash
set -euo pipefail

REPO="EduardoNespoliRamos/zoraxy_cert_warden"

if [[ $# -eq 0 ]]; then
  BRANCHES=(main develop)
else
  BRANCHES=("$@")
fi

# Matrix jobs feed stable aggregate contexts so branch protection does not
# depend on version-specific check names.

# Check whether the repository belongs to an organization. User-owned
# repositories do not support user/team push restrictions through the API.
OWNER_TYPE=$(gh api "repos/${REPO}" --jq '.owner.type')

if [[ "$OWNER_TYPE" == "Organization" ]]; then
  RESTRICTIONS_JSON='"restrictions": {"users": ["EduardoNespoliRamos"], "teams": []},'
else
  echo "Note: repository is owned by a user ($OWNER_TYPE). Push restrictions are implicit."
  RESTRICTIONS_JSON='"restrictions": null,'
fi

for BRANCH in "${BRANCHES[@]}"; do
  if [[ "$BRANCH" != "main" && "$BRANCH" != "develop" ]]; then
    echo "ERROR: Supported branches are main and develop. Received: $BRANCH" >&2
    exit 1
  fi

  echo "Configuring branch protection rules for ${REPO}#${BRANCH}..."

  gh api "repos/${REPO}/branches/${BRANCH}/protection" \
    --method PUT \
    --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Validate source branch",
      "quality / Quality gates",
      "e2e / E2E stable"
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
done
