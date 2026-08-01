#!/bin/sh
set -eu

# Match the private-by-default service policy used by the native deployment.
umask 077

exec /usr/local/bin/hsrd "$@"
