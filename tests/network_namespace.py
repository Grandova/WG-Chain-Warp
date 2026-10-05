#!/usr/bin/env python3
"""Real packet tests: production Rust routing, sing-box client, kernel WG and Dante peers.
Run as root in a disposable Linux test environment; see docs/routing.md.
"""
import argparse
import ipaddress
import json
import os
import re
from pathlib import Path
import selectors
import signal
import subprocess as sp
import sys
import tempfile
import time


def run(*args, input=None, check=True):
    result = sp.run(args, input=input, text=True, stdout=sp.PIPE, stderr=sp.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result.stdout.strip()


HTTP = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', required=True)
    parser.add_argument('--tools', default='/usr')
    parser.add_argument('--output', required=True)
    parser.add_argument('--external-health', action='store_true')
    args = parser.parse_args()
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    driver = str(Path(args.driver).resolve())
    tools = Path(args.tools).resolve()
    wg = str(tools / 'bin/wg')
    dante = str(tools / 'sbin/danted')
    dnsmasq = str(tools / 'sbin/dnsmasq')
    tag = f'cp{os.getpid()}'
    names = {n: f'{tag}-{n}' for n in ['client', 'gateway', 'internet']}
    children = []
    active = None
    def host_state():
        # A running host naturally advances counters while namespace tests run.
        nft = re.sub(r'counter packets \d+ bytes \d+', 'counter', run('nft', 'list', 'ruleset'))
        return [run('ip', '-j', 'route', 'show', 'table', 'all'), run('ip', '-j', 'rule'), nft]

    baseline_host = host_state()

    def cmd(ns, *command):
        return ['nsenter', '--net=/run/netns/' + names[ns], *command]

    def ns(ns, *command, **kwargs):
        return run(*cmd(ns, *command), **kwargs)

    def spawn(ns, *command):
        log = open(root / (ns + '-' + str(len(children)) + '.log'), 'w')
        p = sp.Popen(cmd(ns, *command), stdout=log, stderr=log, text=True)
        children.append(p)
        return p

    def fetch(nsname, address='203.0.113.9', extra=()):
        return ns(nsname, 'curl', '--noproxy', '*', '-fsS', '--max-time', '8', *extra, f'http://{address}:8080/')

    def start(config, label, engine=False):
        nonlocal active
        file = root / (label + '.json')
        file.write_text(json.dumps(config))
        log = open(root / (label + '-driver.log'), 'w')
        active = sp.Popen(cmd('gateway', driver, 'engine' if engine else 'start', str(file), str(root / label)), stdin=sp.PIPE, stdout=sp.PIPE, stderr=log, text=True)
        selector = selectors.DefaultSelector()
        selector.register(active.stdout, selectors.EVENT_READ)
        ready = selector.select(30)
        if not ready or active.stdout.readline().strip() != 'READY':
            raise AssertionError('Driver failed: ' + (root / (label + '-driver.log')).read_text())
        selector.close()

    def stop():
        nonlocal active
        if active:
            active.communicate('stop\n', timeout=15)
            assert active.returncode == 0, 'Driver cleanup failed'
            active = None

    def state():
        return {
            'routes4': ns('gateway', 'ip', '-j', '-4', 'route', 'show', 'table', 'all'),
            'routes6': ns('gateway', 'ip', '-j', '-6', 'route', 'show', 'table', 'all'),
            'rules4': ns('gateway', 'ip', '-j', '-4', 'rule'),
            'rules6': ns('gateway', 'ip', '-j', '-6', 'rule'),
            'nft': ns('gateway', 'nft', 'list', 'ruleset'),
            'sysctl': ns('gateway', 'sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.eth0.rp_filter', 'net.ipv4.conf.all.send_redirects', 'net.ipv6.conf.all.forwarding', 'net.ipv6.conf.lan0.forwarding', 'net.ipv6.conf.lan0.accept_ra'),
        }

    def assert_clean(before):
        after = state()
        for key in before:
            assert after[key] == before[key], f'Residue in {key}: {after[key]} != {before[key]}'
        assert 'chain0' not in ns('gateway', 'ip', '-j', 'link')
        assert not ns('gateway', 'conntrack', '-L', '--mark', '0x88/0x88'), 'Inbound conntrack mark leaked'

    def passed(message):
        print('PASS ' + message, flush=True)

    try:
        for name in names.values():
            run('ip', 'netns', 'add', name)
        for name in names:
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        # Create veths inside the namespace, without adding a route to the real host.
        ns('gateway', 'ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'wan0', 'netns', names['internet'])
        ns('gateway', 'ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', names['client'])
        for name, iface, address in [('gateway','eth0','192.0.2.2/30'), ('internet','wan0','192.0.2.1/30'), ('gateway','lan0','198.18.0.129/25'), ('client','eth0','198.18.0.130/25')]:
            ns(name, 'ip', 'addr', 'add', address, 'dev', iface)
            ns(name, 'ip', 'link', 'set', iface, 'up')
        for name, iface, address in [('gateway','eth0','2001:db8:1::2/64'), ('internet','wan0','2001:db8:1::1/64'), ('gateway','lan0','2001:db8:2::1/64'), ('client','eth0','2001:db8:2::2/64')]:
            ns(name, 'ip', '-6', 'addr', 'add', address, 'dev', iface, 'nodad')
        ns('gateway','ip','-6','route','add','default','via','2001:db8:1::1')
        ns('client','ip','-6','route','add','default','via','2001:db8:2::1')
        ns('internet','ip','-6','route','add','2001:db8:2::/64','via','2001:db8:1::2')
        ns('internet','ip','-6','addr','add','2001:db8:3::9/128','dev','lo','nodad')
        ns('client', 'ip', 'addr', 'add', '198.18.0.131/25', 'dev', 'eth0')
        ns('gateway', 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
        ns('client', 'ip', 'route', 'add', 'default', 'via', '198.18.0.129')
        ns('internet', 'ip', 'route', 'add', '198.18.0.128/25', 'via', '192.0.2.2')
        for address in ['203.0.113.9/32', '203.0.113.10/32', '1.1.1.1/32', '8.8.8.8/32', '192.0.2.5/32']:
            ns('internet', 'ip', 'addr', 'add', address, 'dev', 'lo')
        ns('gateway', 'sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.lan0.forwarding=1')
        ns('gateway', 'nft', '-f', '-', input='table inet unrelated { chain input { type filter hook input priority 10; policy accept; }; chain foreign_mark { type filter hook prerouting priority -160; policy accept; iifname "eth0" fib daddr type local ct direction original ct mark set ct mark | 0x20000; }; }\n')
        # Prove snapshot restoration of the owned table, not just deletion of an absent table.
        ns('gateway', 'nft', '-f', '-', input='table inet chainproxy { chain saved { counter comment "baseline"; }; }\n')
        for name in ['gateway', 'internet', 'client']:
            spawn(name, 'python3', '-u', '-c', HTTP)
        dns_hosts = root/'dns-hosts'
        dns_hosts.write_text('192.0.2.1 vpn.test\n203.0.113.9 target.test\n1.1.1.1 one.one.one.one\n')
        dns_process = spawn('internet', dnsmasq, '--keep-in-foreground', '--no-resolv', '--no-hosts', '--bind-interfaces', '--user=root', '--addn-hosts=' + str(dns_hosts), '--pid-file=' + str(root/'dns.pid'))
        if args.external_health:
            relay = str(Path(__file__).with_name('tls_relay.py'))
            sock = str(root / ('health-' + tag + '.sock'))
            default = json.loads(run('ip', '-j', 'route', 'show', 'table', 'main', 'default'))[0]['dev']
            log = open(root/'tls-relay.log', 'w')
            children.append(sp.Popen(['python3', relay, '--socket', sock, '--outside-interface', default], stdout=log, stderr=log))
            time.sleep(0.2)
            spawn('internet', 'python3', relay, '--socket', sock)
        # /etc/resolv.conf is bind-mounted by the runner in a private mount namespace.
        keys = []
        for index in range(2):
            server = run(wg, 'genkey')
            client = run(wg, 'genkey')
            pub_server = run(wg, 'pubkey', input=server)
            pub_client = run(wg, 'pubkey', input=client)
            keyfile = root / f'wg{index}.key'
            keyfile.write_text(server + '\n')
            keyfile.chmod(0o600)
            iface = f'wg{index}'
            ns('internet', 'ip', 'link', 'add', iface, 'type', 'wireguard')
            ns('internet', wg, 'set', iface, 'private-key', str(keyfile), 'listen-port', str(51820+index), 'peer', pub_client, 'allowed-ips', f'10.{64+index}.0.2/32,2001:db8:{64+index}::2/128')
            ns('internet', 'ip', 'addr', 'add', f'10.{64+index}.0.1/24', 'dev', iface)
            ns('internet', 'ip', '-6', 'addr', 'add', f'2001:db8:{64+index}::1/64', 'dev', iface, 'nodad')
            ns('internet', 'ip', 'link', 'set', iface, 'up')
            keys.append((client, pub_server))
        dante_config = root/'dante.conf'
        dante_config.write_text('logoutput: stderr\ninternal: 192.0.2.1 port = 1080\nexternal: wan0\nuser.privileged: root\nuser.unprivileged: nobody\nclientmethod: none\nsocksmethod: none\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect udpassociate udpreply\nlog: connect disconnect error\n}\n')
        spawn('internet', dante, '-f', str(dante_config), '-p', str(root/'dante.pid'))
        tcp_dante = root/'dante-tcp.conf'
        tcp_dante.write_text(dante_config.read_text().replace('port = 1080', 'port = 1081').replace('connect udpassociate udpreply', 'connect'))
        spawn('internet', dante, '-f', str(tcp_dante), '-p', str(root/'dante-tcp.pid'))
        time.sleep(2.5)  # Wait for IPv6 link-local DAD before taking the baseline.
        assert all(p.poll() is None for p in children), "A test server failed to start; inspect server logs"
        before = state()
        (root/'baseline.json').write_text(json.dumps(before, indent=2))
        def config(mode='standalone_wg', host=False, forward=True):
            nodes = []
            for i, (private, public) in enumerate(keys):
                endpoint = 'vpn.test' if i == 0 else '203.0.113.10'
                nodes.append({'wireguard_config': f'[Interface]\nPrivateKey = {private}\nAddress = 10.{64+i}.0.2/32, 2001:db8:{64+i}::2/128\n[Peer]\nPublicKey = {public}\nEndpoint = {endpoint}:{51820+i}\nAllowedIPs = 0.0.0.0/0, ::/0\n'})
            return {'mode': mode, 'uplink_interface':'eth0', 'vpn1':nodes[0], 'vpn2':nodes[1], 'socks5':{'server':'vpn.test','port':1080}, 'gateway':{'enabled':True,'auto_allow_lan':False,'allowed_subnets':['198.18.0.128/25']}, 'routing':{'proxy_host_outbound':host,'proxy_forwarded_outbound':forward}, 'dns':{'mode':'chain'}, 'log_level':'debug'}

        for host, forward in [(False,True), (True,True), (True,False), (False,False)]:
            label = f'host-{host}-lan-{forward}'
            start(config(host=host, forward=forward), label)
            assert fetch('gateway') == ('10.64.0.2' if host else '192.0.2.2')
            assert fetch('client') == ('10.64.0.2' if forward else '198.18.0.130')
            assert fetch('gateway','198.18.0.131') == '198.18.0.129'
            assert fetch('internet','192.0.2.2', ('--interface','203.0.113.9')) == '203.0.113.9'
            route = ns('gateway','ip','route','get','203.0.113.10','mark','0x400')
            assert 'dev eth0' in route and 'chain0' not in route
            assert ns('gateway','ip','route','show','table','main','default') == 'default via 192.0.2.1 dev eth0'
            (root/(label+'-rules.txt')).write_text(ns('gateway','ip','rule'))
            (root/(label+'-nft.txt')).write_text(ns('gateway','nft','list','table','inet','chainproxy'))
            stop(); assert_clean(before)
            passed(label + ': real HTTP host/LAN/return/LAN-local + physical mark + cleanup')

        http6 = HTTP.replace("ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()", """
import socket
class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()
Server(('::', 8080), Handler).serve_forever()
""")
        spawn('internet', 'python3', '-u', '-c', http6)
        spawn('gateway', 'python3', '-u', '-c', http6)
        for host in [False, True]:
            v6 = config(host=host)
            v6['routing']['ipv6'] = True
            v6['gateway']['allowed_subnets'].append('2001:db8:2::/64')
            start(v6, 'ipv6-' + str(host))
            assert fetch('client', '[2001:db8:3::9]') == '2001:db8:64::2'
            assert fetch('gateway', '[2001:db8:3::9]') == ('2001:db8:64::2' if host else '2001:db8:1::2')
            assert fetch('internet', '[2001:db8:1::2]', ('--interface','2001:db8:3::9')) == '2001:db8:3::9'
            assert 'dev eth0' in ns('gateway','ip','-6','route','get','2001:db8:3::9','mark','0x400')
            stop(); assert_clean(before)
        passed('IPv6 host/LAN proxy, inbound replies, underlay bypass and cleanup')

        for dns_mode in ['chain', 'physical', 'custom']:
            dns_config = config(host=True)
            dns_config['dns'] = {'mode': dns_mode, 'custom_servers': ['1.1.1.1']}
            start(dns_config, 'dns-' + dns_mode)
            assert '203.0.113.9' in ns('client','dig','+short','+time=3','+tries=1','@192.0.2.2','target.test')
            assert '203.0.113.9' in ns('client','dig','+tcp','+short','+time=3','+tries=1','@192.0.2.2','target.test')
            assert '203.0.113.9' in ns('client','dig','+short','+time=3','+tries=1','@1.1.1.1','target.test')
            stop(); assert_clean(before)
        passed('chain/physical/custom DNS: UDP and TCP gateway listener, plus TUN DNS hijack')

        for prefix in [25, 23, 16]:
            ns('gateway','ip','addr','add',f'198.19.7.130/{prefix}','dev','eth0')
            auto = config()
            auto['gateway']['auto_allow_lan'] = True
            baseline = state()
            start(auto, 'prefix-' + str(prefix))
            subnet = str(ipaddress.ip_network(f'198.19.7.130/{prefix}', strict=False))
            rules = ns('gateway','nft','list','table','inet','chainproxy')
            assert subnet in rules, (subnet, rules)
            stop(); assert_clean(baseline)
            ns('gateway','ip','addr','del',f'198.19.7.130/{prefix}','dev','eth0')
        assert_clean(before)
        passed('actual interface prefix detection: /25, /23, /16')

        conflict = root/'conflict.json'; conflict.write_text(json.dumps(config()))
        for rule in [('priority','70','fwmark','0x20000','lookup','main'), ('priority','700','lookup','2022')]:
            ns('gateway','ip','rule','add',*rule)
            baseline = state()
            result = sp.run(cmd('gateway',driver,'start',str(conflict),str(root/'conflict')),capture_output=True,text=True)
            assert result.returncode != 0, 'Must reject occupied routing resources'
            assert_clean(baseline)
            ns('gateway','ip','rule','del',*rule)
        assert_clean(before)
        passed('foreign priority/table ownership conflicts rejected without deletion')

        for mode, expected in [('wg_chain_warp','10.65.0.2'), ('socks_chain_warp','10.65.0.2'), ('standalone_socks','192.0.2.1'), ('standalone_warp','10.65.0.2')]:
            start(config(mode=mode, host=True), mode)
            assert fetch('client') == expected
            assert fetch('gateway') == expected
            # Test mixed port using the independent curl SOCKS client.
            result = ns('gateway','curl','--noproxy','','-fsS','--max-time','8','--socks5-hostname','127.0.0.1:25432','http://203.0.113.9:8080/')
            assert result == expected
            stop(); assert_clean(before)
            passed(mode + ': kernel WireGuard / Dante interoperability')

        for dns_mode in ['chain', 'custom']:
            tcp_only = config(mode='standalone_socks', host=True)
            tcp_only['socks5']['port'] = 1081
            tcp_only['dns'] = {'mode': dns_mode, 'custom_servers': ['1.1.1.1']}
            start(tcp_only, 'socks-tcp-dns-' + dns_mode)
            assert '203.0.113.9' in ns('gateway','dig','+short','+time=3','+tries=1','@1.1.1.1','target.test')
            assert '203.0.113.9' in ns('client','dig','+tcp','+short','+time=3','+tries=1','@192.0.2.2','target.test')
            assert ns('gateway','curl','--noproxy','','-fsS','--max-time','8','--socks5-hostname','127.0.0.1:25432','http://target.test:8080/') == '192.0.2.1'
            stop(); assert_clean(before)
        passed('TCP-only Dante: standalone SOCKS chain/custom DNS and domain HTTP')

        for i in range(10):
            start(config(host=bool(i%2)), f'cycle-{i}')
            assert fetch('client') == '10.64.0.2'
            stop(); assert_clean(before)
        passed('10 start/stop cycles: no routes/rules/TUN/nft/sysctl residue')
        assert ns('gateway','conntrack','-L','--mark','0x20000/0x20000'), 'Foreign conntrack bits must survive cleanup'
        passed('foreign conntrack mark bits preserved while inbound-return bits are cleared')

        if args.external_health:
            server = {'mode': 'socks5_server', 'uplink_interface': 'eth0',
                      'socks5_server': {'listen': '0.0.0.0', 'port': 1082,
                                        'users': [{'username':'alice','password':'test:p@ss'},
                                                  {'username':'bob','password':'second-pass'}]}}
            start(server, 'socks-server', engine=True)
            assert state() == before, 'Server mode changed routing, firewall or sysctl'
            assert 'chain0' not in ns('gateway','ip','-j','link')
            for auth in ['alice:test:p@ss', 'bob:second-pass']:
                assert ns('client','curl','--noproxy','','-fsS','--max-time','8','--socks5-hostname','198.18.0.129:1082','--proxy-user',auth,'http://target.test:8080/') == '192.0.2.2'
            for auth in [[], ['--proxy-user','alice:wrong'], ['--proxy-user','unknown:second-pass']]:
                result = sp.run(cmd('client','curl','--noproxy','','-fsS','--max-time','5','--socks5-hostname','198.18.0.129:1082',*auth,'http://target.test:8080/'), capture_output=True)
                assert result.returncode != 0, 'Unauthenticated access allowed'
            bad_server = json.loads(json.dumps(server))
            bad_server['socks5_server']['port'] = 8080
            bad_path = root/'server-port-conflict.json'; bad_path.write_text(json.dumps(bad_server))
            active.stdin.write(str(bad_path) + '\n'); active.stdin.flush()
            reply = json.loads(active.stdout.readline())
            assert not reply['success'] and reply['state'] == 'Running', reply
            assert ns('client','curl','--noproxy','','-fsS','--max-time','8','--socks5-hostname','198.18.0.129:1082','--proxy-user','bob:second-pass','http://target.test:8080/') == '192.0.2.2'
            stop(); assert_clean(before)
            server['socks5_server']['listen'] = '127.0.0.1'
            start(server, 'socks-server-loopback', engine=True)
            assert ns('gateway','curl','--noproxy','','-fsS','--max-time','8','--socks5-hostname','127.0.0.1:1082','--proxy-user','alice:test:p@ss','http://target.test:8080/') == '192.0.2.2'
            result = sp.run(cmd('client','curl','--noproxy','','-fsS','--max-time','3','--socks5-hostname','198.18.0.129:1082','--proxy-user','alice:test:p@ss','http://target.test:8080/'), capture_output=True)
            assert result.returncode != 0, 'Loopback listener exposed on LAN'
            stop(); assert_clean(before)
            passed('SOCKS server: curl multi-user auth, auth rejection, listen binding, failed reload rollback; no network mutations')

            start(config(host=True), 'engine-transaction', engine=True)
            assert fetch('client') == '10.64.0.2'
            # Fail after mutation/launch, then verify the previous committed proxy really resumes.
            bad = config(mode='standalone_socks', host=True)
            bad['socks5']['port'] = 1
            bad_path = root/'bad-reload.json'; bad_path.write_text(json.dumps(bad))
            active.stdin.write(str(bad_path) + '\n'); active.stdin.flush()
            reply = json.loads(active.stdout.readline())
            assert not reply['success'] and reply['state'] == 'Running', reply
            assert fetch('client') == '10.64.0.2'
            dns_hosts.write_text('192.0.2.5 vpn.test\n203.0.113.9 target.test\n1.1.1.1 one.one.one.one\n')
            dns_process.send_signal(signal.SIGHUP)
            time.sleep(0.2)
            ns('internet','nft','-f','-',input='table inet endpoint_test { chain input { type filter hook input priority filter; policy accept; ip daddr 192.0.2.1 udp dport 51820 drop; }; }\n')
            active.stdin.write(str(root/'engine-transaction.json') + '\n'); active.stdin.flush()
            reply = json.loads(active.stdout.readline())
            assert reply['success'], reply
            assert fetch('client') == '10.64.0.2'
            assert '192.0.2.5' not in ns('gateway','ip','route','show','table','main'), 'No endpoint pinning in main'
            ns('internet','nft','delete','table','inet','endpoint_test')
            dns_hosts.write_text('192.0.2.1 vpn.test\n203.0.113.9 target.test\n1.1.1.1 one.one.one.one\n')
            dns_process.send_signal(signal.SIGHUP)
            passed('endpoint DNS IP change picked up on reload, without stale main host routes')
            stop(); assert_clean(before)
            passed('full engine APPLY/COMMIT and failed reload restores previous running configuration')
            for i in range(10):
                start(config(host=bool(i%2)), f'engine-cycle-{i}', engine=True)
                assert fetch('client') == '10.64.0.2'
                stop(); assert_clean(before)
            passed('10 complete engine start/stop transactions with real HTTPS health checks')

            start(config(host=True), 'crash-recovery', engine=True)
            active.kill(); active.wait(); active = None
            deadline = time.monotonic() + 5
            while 'chain0' in ns('gateway','ip','-j','link') and time.monotonic() < deadline:
                time.sleep(0.1)
            assert 'chain0' not in ns('gateway','ip','-j','link'), 'Orphaned sing-box after daemon death'
            assert fetch('internet','192.0.2.2', ('--interface','203.0.113.9')) == '203.0.113.9'
            ns('gateway',driver,'recover',str(root/'crash-recovery.json'),str(root/'crash-recovery'))
            assert_clean(before)
            passed('daemon SIGKILL: child exits, inbound survives, new engine restores durable snapshot')

        failed = root/'failure.json'; failed.write_text(json.dumps(config(host=True)))
        ns('gateway', driver, 'failure', str(failed), str(root/'failure'))
        assert_clean(before)
        assert fetch('internet','192.0.2.2', ('--interface','203.0.113.9')) == '203.0.113.9'
        assert fetch('gateway') == '192.0.2.2'
        passed('engine watchdog timeout: HTTP inbound and physical egress restored')
    finally:
        if active:
            try: stop()
            except Exception: active.kill(); active.wait()
        for p in reversed(children):
            p.terminate()
            try: p.wait(timeout=5)
            except sp.TimeoutExpired: p.kill(); p.wait()
        for name in names.values():
            run('ip','netns','del',name,check=False)
        after_host = host_state()
        for label, before, after in zip(['routes', 'rules', 'nft'], baseline_host, after_host):
            assert before == after, f'Real host {label} configuration changed'
        passed('real host routes/rules/firewall unchanged')


if __name__ == '__main__':
    main()
