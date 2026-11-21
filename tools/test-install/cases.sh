#!/bin/sh
# Runs inside a container (see run.sh): stub systemd, then try every case against the local test server.
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl; mkdir -p /etc/systemd/system
export CURL_CA_BUNDLE=/t/srv.crt
echo "  $(openssl version 2>/dev/null | cut -d' ' -f1-2)"
run() { name=$1; shift; rm -rf /var/lib/cybercop-agent /usr/local/bin/cybercop-agent
  out=$(sh /t/${SCRIPT:-install-test.sh} --server https://localhost:8443/$name "$@" CODE123 2>&1 </dev/null); rc=$?
  echo "  [$name${SCRIPT:+ $SCRIPT}] rc=$rc :: $(echo "$out" | grep -v '^fake agent' | tail -1)"
  [ "$name" = good ] && [ $rc = 0 ] && echo "     $(echo "$out" | grep 'signature checked')"
}
# expected: good installs (spare key); every other case refuses
for c in ${CASES:-good foreign unsigned old tampered swapped}; do run $c; done
SCRIPT=install-nokeys.sh run good
