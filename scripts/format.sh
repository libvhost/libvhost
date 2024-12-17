#!/bin/bash
script_dir=$(readlink -f $(dirname $0))
git diff -U0 --no-color HEAD^ | ${script_dir}/clang-format-diff.py -i -p1 -style=file
