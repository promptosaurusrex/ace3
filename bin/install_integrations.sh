#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment

cd /opt/ace && \
if [ -d integrations ]; then
    find integrations -type f -name integration.md | LC_ALL=C sort | while read -r mdpath
    do
        dir=$(dirname "$mdpath")
        if [ -f "$dir/install.sh" ]; then
            echo "installing $dir"
            (cd "$dir" && ./install.sh)
        else
            echo "skipping $dir (no install.sh)"
        fi
    done
fi
