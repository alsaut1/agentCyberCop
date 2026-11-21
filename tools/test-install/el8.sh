#!/bin/sh
# Runs inside an AlmaLinux 8 container (see run.sh): OpenSSL 1.1.1 cannot check Ed25519, so the installer needs
# python3-cryptography and must install it only with the user's consent.
dnf -q -y install openssl util-linux >/dev/null 2>&1
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl; mkdir -p /etc/systemd/system
export CURL_CA_BUNDLE=/t/srv.crt
T="sh /t/install-test.sh --server https://localhost:8443"
clean() { rm -rf /var/lib/cybercop-agent /usr/local/bin/cybercop-agent; }
pkg() { rpm -q python3-cryptography >/dev/null && echo "package installed" || echo "package not installed"; }
echo "  $(openssl version | cut -d' ' -f1-2); $(pkg)"
echo "-- no terminal, no consent (expected: stop, package not installed):"; clean
$T/good CODE </dev/null 2>&1 | tail -1 | sed 's/^/     /'; echo "     $(pkg)"
echo "-- terminal, answer n (expected: stop, package not installed):"; clean
echo n | script -qec "$T/good CODE" /dev/null 2>&1 | tr -d '\r' | tail -1 | sed 's/^/     /'; echo "     $(pkg)"
echo "-- terminal, answer y (expected: package installed, signature checked):"; clean
echo y | script -qec "$T/good CODE" /dev/null 2>&1 | tr -d '\r' | grep -v '^fake' | tail -2 | sed 's/^/     /'; echo "     $(pkg)"
echo "-- package present (expected: no question; good installs, foreign and swapped refused):"
for c in good foreign swapped; do clean; out=$($T/$c CODE </dev/null 2>&1); echo "     [$c] rc=$? :: $(echo "$out" | grep -v '^fake' | tail -1)"
  echo "$out" | grep -q "install python3-cryptography now" && echo "     !!! asked again"; done
