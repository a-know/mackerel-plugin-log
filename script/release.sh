#!/bin/sh
set -e
latest_tag=$(git describe --abbrev=0 --tags)
goxz -d dist/$latest_tag -z -os darwin,linux -arch amd64,386
ghr -u a-know -r mackerel-plugin-log $latest_tag dist/$latest_tag
