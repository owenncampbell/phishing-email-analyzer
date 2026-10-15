#!/usr/bin/env bash
# Download real phishing samples from the phishing_pot project for testing.
#   ./get_samples.sh          -> samples 1-5
#   ./get_samples.sh 12 40    -> samples 12 and 40
# These are LIVE phishing emails: view them only as text, never in a mail client.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p samples
if [ $# -eq 0 ]; then set -- 1 2 3 4 5; fi
for i in "$@"; do
  curl -sSfo "samples/sample-$i.eml" \
    "https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/sample-$i.eml"
  echo "downloaded samples/sample-$i.eml"
done
