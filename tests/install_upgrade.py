"""Run with python3 tests/install_upgrade.py on Linux; no system services are changed."""
from pathlib import Path
import os
import subprocess
import tempfile

script = (Path(__file__).resolve().parents[1] / 'scripts/install.sh').read_text()
function = script[script.index('install_chainproxy() {'):]
function = function[:function.index('\n}\n') + 3]
verify = script[script.index('REAL_SB=$(command -v sing-box') : script.index('# 3. 安装 chainproxy')]

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    old = root / 'chainproxy'
    new = root / 'candidate'
    engine = root / 'sing-box'
    events = root / 'events'
    for path, version in [(old, 'old'), (new, 'new'), (engine, 'sing-box-test')]:
        path.write_text('#!/bin/sh\nprintf "' + version + '\\n"\n')
        path.chmod(0o755)
    env = dict(os.environ, PATH=tmp + ':' + os.environ['PATH'],
               CHAINPROXY_BIN=str(old), CANDIDATE=str(new), EVENTS=str(events))
    setup = """
set -euo pipefail
log_info() { :; }
log_ok() { :; }
log_err() { :; }
systemctl() {
    printf '%s:%s\\n' "$1" "$("$CHAINPROXY_BIN" --version)" >> "$EVENTS"
}
ln() {
    printf 'unexpected ln\\n' >> "$EVENTS"
    return 1
}
"""
    before = engine.read_bytes()
    subprocess.run(['bash', '-c', setup + verify], env=env, check=True)
    assert engine.read_bytes() == before and not engine.is_symlink()
    assert not events.exists(), 'Engine validation must not rewrite installation paths'
    print('PASS existing sing-box is verified without replacing files or symlinks')

    subprocess.run(['bash', '-c', setup + function + '\ninstall_chainproxy "$CANDIDATE"'], env=env, check=True)
    assert events.read_text().splitlines() == ['is-active:old', 'stop:old']
    assert subprocess.check_output([old, '--version'], text=True).strip() == 'new'
    print('PASS old service stops with old executable before replacement')

    events.unlink()
    new.write_text('#!/bin/sh\nexit 1\n')
    before = old.read_bytes()
    result = subprocess.run(['bash', '-c', setup + function + '\ninstall_chainproxy "$CANDIDATE"'], env=env)
    assert result.returncode != 0 and not events.exists() and old.read_bytes() == before
    print('PASS invalid candidate keeps old executable and service untouched')

    new.write_text('#!/bin/sh\nprintf "next\\n"\n')
    setup += '\nsystemctl() { if [ "$1" = is-active ]; then return 0; fi; return 1; }\n'
    result = subprocess.run(['bash', '-c', setup + function + '\ninstall_chainproxy "$CANDIDATE"'], env=env)
    assert result.returncode != 0 and old.read_bytes() == before
    print('PASS failed service stop aborts replacement')
