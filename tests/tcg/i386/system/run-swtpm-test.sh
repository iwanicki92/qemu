#!/bin/sh
# Start a fresh swtpm for the test-smx-getsec QEMU run.
#
# The meson TCG framework invokes this script with the full QEMU
# command line as its arguments.  The command line must carry the
# TPM control socket as
#
#   -chardev socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER
#
# (the "path=SWTPM_SOCKET_PLACEHOLDER" part of the -chardev
# argument); the script
# starts swtpm in a private state directory, substitutes the real
# socket path into the command line, waits for swtpm to publish its
# control socket, and execs QEMU.  On exit the swtpm process is
# killed and the state directory removed.
#
# If swtpm is missing or its socket does not come up, the script
# exits non-zero so the test is reported as an environment failure
# rather than a guest failure.

set -eu

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/qemu-tcg-swtpm.XXXXXX")
swtpm_pid=""
trap '
    if [ -n "$swtpm_pid" ]; then
        kill "$swtpm_pid" 2>/dev/null || :
    fi
    rm -rf "$tmpdir"
' EXIT

cmd=""
for a in "$@"; do
    if [ "$a" = "socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER" ]; then
        a="socket,id=tpm0,path=$tmpdir/sock"
    fi
    cmd="$cmd $a"
done

command -v swtpm >/dev/null || {
    echo "run-swtpm-test.sh: swtpm is not in PATH" >&2
    exit 1
}

# swtpm 0.9+ CLI: control socket via --ctrl, TPM state in --tpmstate.
swtpm socket --tpm2 \
    --tpmstate "dir=$tmpdir" \
    --ctrl "type=unixio,path=$tmpdir/sock" \
    >/dev/null 2>&1 &
swtpm_pid=$!

i=0
while [ ! -S "$tmpdir/sock" ]; do
    if ! kill -0 "$swtpm_pid" 2>/dev/null; then
        echo "run-swtpm-test.sh: swtpm exited before creating its socket" >&2
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -gt 200 ]; then
        echo "run-swtpm-test.sh: swtpm socket did not appear" >&2
        exit 1
    fi
    sleep 0.1
done

# Word splitting of $cmd is deliberate: it is the QEMU command line.
# shellcheck disable=SC2086
exec $cmd
