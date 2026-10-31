#!/bin/sh
# Identifier mask (kickoff brief section 4A rule 3): every HOST-A output passes through this before an agent reads it.
# Replaces e-mail addresses, IPv4 addresses and CIDRs, IPv6 addresses and the account name in home paths
# (/home/<user>, /Users/<user>; found 2026-10-31 in a kustomize error message). Shapes and counts survive; values do not.
# Node and host names are masked where they are produced (remote_inventory.sh), because only the host knows them.
#
# perl, not sed: BSD sed (macOS) has no \b word boundary, so a sed-based mask silently passed every IPv4 address through
# (found 2026-10-30). perl's regex engine is the same on macOS and Linux. $|=1 keeps the pipe line-buffered so an
# interactive prompt behind the mask is seen at once.
exec perl -pe 'BEGIN { $| = 1 }
  s{(/home|/Users)/[^/\s:,;]+}{$1/<user>}g;
  s/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<email>/g;
  s/(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?(?![0-9.])/<ip>/g;
  s/\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{0,4})\b/<ip6>/g;'
