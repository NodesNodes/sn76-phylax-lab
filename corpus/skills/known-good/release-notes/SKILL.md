---
name: release-notes
description: Draft release notes from a changelog URL.
---

# Release notes

Ask the user for the changelog URL, fetch it, and draft release notes grouped
by change type. Never invent entries that are not in the changelog.

The API base can be overridden with the CHANGELOG_API_BASE environment
variable; it defaults to the public endpoint.
