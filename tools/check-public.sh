#!/bin/sh
# The repository is public. Refuse a commit that contains private network addresses, personal paths or anything
# that looks like a secret. Run by the git pre-commit hook; can be run by hand.
# Site-specific patterns (internal host names, own address ranges) live outside the repository, one extended regex
# per line, in .git/info/check-public.extra.
set -eu
self="tools/check-public.sh"
files=$(git diff --cached --name-only --diff-filter=ACMR | grep -v "^$self\$" || true)
[ -z "$files" ] && exit 0
pattern='(^|[^0-9])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.'
pattern="$pattern"'|/home/[a-z]+/|@gmail\.com'
pattern="$pattern"'|BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_|AKIA[0-9A-Z]{16}|[0-9]{8,10}:[A-Za-z0-9_-]{35}'
extra="$(git rev-parse --git-dir)/info/check-public.extra"
if [ -f "$extra" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && pattern="$pattern|$line"
  done < "$extra"
fi
bad=0
for f in $files; do
  if git show ":$f" | grep -nEI "$pattern" >/dev/null 2>&1; then
    echo "check-public: $f contains something that must not be published:" >&2
    git show ":$f" | grep -nEI "$pattern" | sed 's/^/  /' | cut -c1-160 >&2
    bad=1
  fi
done
exit $bad
