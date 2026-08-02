#!/bin/sh
set -eu

# Do not create group- or world-readable runtime material if future resolver
# options add local files.
umask 077

exec /usr/local/bin/hns-resolverd "$@"
