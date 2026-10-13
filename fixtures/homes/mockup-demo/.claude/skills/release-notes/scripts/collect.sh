#!/bin/sh
git log --merges --oneline "${1:-$(git describe --tags --abbrev=0)}..HEAD"
