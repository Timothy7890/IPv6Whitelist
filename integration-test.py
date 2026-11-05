#!/usr/bin/env python3
"""Bounded root-only integration test. Uses documentation addresses, never sends packets."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time

assert os.geteuid() == 0, 'Administrator permission required'
uid = pwd.getpwnam('nobody').pw_uid
runtime = Path(f'/var/run/wifi-ipv6-{uid}')
control = runtime / 'control.sock'
assert not runtime.exists(), 'Isolated test runtime already exists; refusing to interfere'
addresses = ['2001:db8:ffff:5c19::a', '2001:db8:ffff:5c19::b']
scratch = Path(tempfile.mkdtemp(prefix='ipv6-whitelist-test-', dir='/private/var/run'))
helper = scratch / 'helper'
shutil.copyfile(sys.argv[1], helper)
helper.chmod(0o755)
subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(helper)], check=True)
process = None
gateway = None

def command(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=15)

def routes():
    result = command('/usr/sbin/netstat', '-rn', '-f', 'inet6')
    assert result.returncode == 0
    return [line.split() for line in result.stdout.splitlines() if len(line.split()) >= 4]

def defaults():
    return sorted(tuple(row[:4]) for row in routes() if row[0] == 'default')

def test_routes():
    return [row for row in routes() if row[0].removesuffix('/128') in addresses and 'I' not in row[2]]

def request(message):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(45)
        connection.connect(str(control))
        connection.sendall(json.dumps(message).encode() + b'\n')
        response = bytearray()
        while b'\n' not in response:
            block = connection.recv(8192)
            assert block, 'Helper closed without a response'
            response.extend(block)
            assert len(response) < 1048576
        return json.loads(response.split(b'\n')[0])

try:
    before = defaults()
    assert not test_routes(), 'Test addresses already have a route'
    process = subprocess.Popen([str(helper), '--uid', str(uid)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        if control.exists():
            break
        assert process.poll() is None, 'Helper failed to start: ' + process.stderr.read().decode(errors='replace')
        time.sleep(.1)
    initial = request({'command': 'status'})
    assert initial['ok'], initial
    gateway = initial['status'].get('wifiGateway')
    assert gateway, 'Current Wi-Fi has no usable IPv6 gateway'
    enabled = request({'command': 'enable', 'addresses': addresses})
    assert enabled['ok'], enabled
    assert len(enabled['status']['activeRoutes']) == 2, enabled
    for address in addresses:
        result = command('/sbin/route', '-n', 'get', '-inet6', address)
        assert 'interface: en0' in result.stdout, result.stdout
    changed = request({'command': 'update', 'addresses': addresses[:1]})
    assert changed['ok'] and len(changed['status']['activeRoutes']) == 1, changed
    assert len(test_routes()) == 1
    invalid = request({'command': 'update', 'addresses': ['::/0']})
    assert not invalid['ok'], invalid
    assert len(invalid['status']['activeRoutes']) == 1
    disabled = request({'command': 'disable'})
    assert disabled['ok'] and not disabled['status']['activeRoutes'], disabled
    assert not test_routes(), 'A documentation-address route was left behind'
    assert defaults() == before, 'Existing defaults changed'
    stopped = request({'command': 'stop'})
    assert stopped['ok'], stopped
    process.wait(timeout=10)
    assert process.returncode == 0
    print(json.dumps({'result': 'PASS', 'checks': ['root helper startup', 'authenticated local IPC', 'add two /128 routes', 'unbound route selects en0', 'remove one entry', 'reject ::/0 without losing prior state', 'disable cleanup', 'stop cleanup', 'all original default routes preserved'], 'external_packets_sent': 0}, ensure_ascii=False))
finally:
    if process is not None and process.poll() is None:
        try:
            request({'command': 'stop'})
        except Exception:
            process.terminate()
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    # Fail-safe restricted to the two previously absent test routes and their exact gateway.
    for row in test_routes():
        if gateway and row[1] == gateway and row[3] == 'en0' and 'S' in row[2] and 'H' in row[2]:
            command('/sbin/route', '-n', 'delete', '-inet6', '-host', row[0].removesuffix('/128'), gateway)
    if runtime.exists():
        shutil.rmtree(runtime)
    shutil.rmtree(scratch)
