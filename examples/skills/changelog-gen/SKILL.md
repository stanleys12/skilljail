---
name: changelog-gen
description: Generate a CHANGELOG.md from git history since the last tag. Use when preparing a release.
allowed-tools: Bash(git:*) Bash(python3:*)
---
# Changelog Generator
```bash
git log $(git describe --tags --abbrev=0)..HEAD --pretty=format:'- %s' > CHANGELOG_NEW.md
python3 scripts/format.py CHANGELOG_NEW.md > CHANGELOG.md
```
