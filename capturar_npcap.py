"""Captura passiva Npcap da conexão candidata do jogo; arquivos somente no D."""
import argparse
import csv
import ctypes as C
import ipaddress
import json
import os
import sys
import struct
import time
from contextlib import nullcontext
from datetime import datetime, timezone
from rede_diagnostico import OUT, run

GAME_PORTS = (10001, 10002, 10003, 10004, 10005)
GAME_PORTS_TEXT = '/'.join(map(str, GAME_PORTS))


class Address(C.Structure):
    pass


Address._fields_ = [('next', C.POINTER(Address)), ('addr', C.c_void_p),
                    ('netmask', C.c_void_p), ('broadcast', C.c_void_p), ('destination', C.c_void_p)]


class Device(C.Structure):
    pass


Device._fields_ = [('next', C.POINTER(Device)), ('name', C.c_char_p),
                   ('description', C.c_char_p), ('addresses', C.POINTER(Address)), ('flags', C.c_uint)]


class Program(C.Structure):
    _fields_ = [('length', C.c_uint), ('instructions', C.c_void_p)]


class Header(C.Structure):
    _fields_ = [('seconds', C.c_int32), ('microseconds', C.c_int32),
                ('caplen', C.c_uint32), ('length', C.c_uint32)]


def main(argv=None, on_packet=None, stop_event=None, on_ready=None, on_connections=None,
         on_status=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=10,
                        help='Duração em segundos; use 0 para capturar sem limite (padrão: 10).')
    parser.add_argument('--inventory', action='store_true')
    parser.add_argument('--wait-for-connection', action='store_true',
                        help='Wait until the game process and a candidate connection are available.')
    args = parser.parse_args(argv)
    if args.seconds < 0:
        parser.error('--seconds deve ser zero ou um número positivo')
    OUT.mkdir(exist_ok=True)
    base = OUT / ('npcap_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    report = {'devices': [], 'packets': 0, 'bytes': 0}
    handle = None
    try:
        dll_dir = os.add_dll_directory(r'C:\Windows\System32\Npcap')
        lib = C.CDLL(r'C:\Windows\System32\Npcap\wpcap.dll')
        def bind(name, result, *params):
            fn = getattr(lib, name)
            fn.restype, fn.argtypes = result, list(params)
            return fn
        find = bind('pcap_findalldevs', C.c_int, C.POINTER(C.POINTER(Device)), C.c_char_p)
        free = bind('pcap_freealldevs', None, C.POINTER(Device))
        open_live = bind('pcap_open_live', C.c_void_p, C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p)
        close = bind('pcap_close', None, C.c_void_p)
        error = bind('pcap_geterr', C.c_char_p, C.c_void_p)
        compile_filter = bind('pcap_compile', C.c_int, C.c_void_p, C.POINTER(Program), C.c_char_p, C.c_int, C.c_uint32)
        set_filter = bind('pcap_setfilter', C.c_int, C.c_void_p, C.POINTER(Program))
        free_code = bind('pcap_freecode', None, C.POINTER(Program))
        nonblock = bind('pcap_setnonblock', C.c_int, C.c_void_p, C.c_int, C.c_char_p)
        next_packet = bind('pcap_next_ex', C.c_int, C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte)))
        datalink = bind('pcap_datalink', C.c_int, C.c_void_p)
        errbuf = C.create_string_buffer(256)
        devices = C.POINTER(Device)()
        if find(C.byref(devices), errbuf) != 0:
            raise RuntimeError(errbuf.value.decode(errors='replace'))
        try:
            cursor = devices
            while cursor:
                d = cursor.contents
                ips = []
                addr = d.addresses
                while addr:
                    if addr.contents.addr:
                        raw = C.string_at(addr.contents.addr, 16)
                        if int.from_bytes(raw[:2], 'little') == 2:
                            ips.append(str(ipaddress.IPv4Address(raw[4:8])))
                    addr = addr.contents.next
                report['devices'].append({'name': d.name.decode(), 'description': (d.description or b'').decode(errors='replace'), 'ipv4': ips})
                cursor = d.next
        finally:
            free(devices)
        if args.inventory:
            return
        def checked(*parts):
            result = run(*parts)
            if result['returncode']:
                raise RuntimeError(f'{parts[0]} falhou: ' + result['stderr'] + result['stdout'])
            return result['stdout']
        game_pid = None
        def discover_connections():
            nonlocal game_pid
            games = [r for r in csv.reader(checked('tasklist', '/fo', 'csv', '/nh').splitlines())
                     if r and r[0].lower() == 'sevendeadlysins_origin-win64-shipping.exe']
            game_pid = int(games[0][1]) if len(games) == 1 else None
            if game_pid is None:
                return []
            rows = [r.split() for r in checked('netstat', '-ano', '-p', 'tcp').splitlines()]
            found = {}
            for row in rows:
                if len(row) != 5 or row[-1] != str(game_pid) or row[3] != 'ESTABLISHED':
                    continue
                try:
                    local, local_port = row[1].rsplit(':', 1)
                    remote, remote_port = row[2].rsplit(':', 1)
                    local_port, remote_port = int(local_port), int(remote_port)
                    ipaddress.IPv4Address(local)
                    ipaddress.IPv4Address(remote)
                except (ValueError, TypeError):
                    continue
                if remote_port not in GAME_PORTS:
                    continue
                key = (local, local_port, remote, remote_port)
                found[key] = {'local_ip': local, 'local_port': local_port,
                              'remote_ip': remote, 'remote_port': remote_port,
                              'pid': game_pid}
            return sorted(found.values(), key=lambda c: (-(c['remote_port']), c['local_port']))
        while True:
            if stop_event and stop_event.is_set():
                report['stopped_utc'] = datetime.now(timezone.utc).isoformat()
                return report
            games = [r for r in csv.reader(checked('tasklist', '/fo', 'csv', '/nh').splitlines())
                     if r and r[0].lower() == 'sevendeadlysins_origin-win64-shipping.exe']
            if len(games) == 1:
                game_pid = int(games[0][1])
                connections = discover_connections()
                if connections:
                    break
                wait_message = f'Jogo encontrado; aguardando conexão ativa nas portas {GAME_PORTS_TEXT}.'
            else:
                connections = []
                wait_message = 'Aguardando o processo do jogo (SevenDeadlySins_Origin-Win64-Shipping.exe).'
            if not args.wait_for_connection:
                if len(games) != 1:
                    raise RuntimeError('Processo do jogo ausente ou não único')
                raise RuntimeError(f'Conexões de jogo candidatas ausentes (portas {GAME_PORTS_TEXT})')
            if on_status:
                on_status(wait_message)
            if stop_event:
                stop_event.wait(1)
            else:
                time.sleep(1)
        local_hosts = {c['local_ip'] for c in connections}
        if len(local_hosts) != 1:
            raise RuntimeError('Conexões candidatas usam mais de uma interface local')
        local = next(iter(local_hosts))
        matches = [d for d in report['devices'] if local in d['ipv4']]
        if len(matches) != 1:
            raise RuntimeError('Interface correspondente não é única')
        port_filter = ' or '.join(f'port {port}' for port in GAME_PORTS)
        expression = f'tcp and host {local} and ({port_filter})'
        primary = connections[0]
        report.update(filter=expression, pid=game_pid, interface=matches[0]['name'],
                      remote_port=primary['remote_port'], local_port=primary['local_port'],
                      connections=connections)
        handle = open_live(matches[0]['name'].encode(), 65535, 0, 100, errbuf)
        if not handle:
            raise RuntimeError(errbuf.value.decode(errors='replace'))
        program = Program()
        if compile_filter(handle, C.byref(program), expression.encode(), 1, 0xffffffff) != 0:
            raise RuntimeError(error(handle).decode(errors='replace'))
        try:
            if set_filter(handle, C.byref(program)) != 0:
                raise RuntimeError(error(handle).decode(errors='replace'))
        finally:
            free_code(C.byref(program))
        if nonblock(handle, 1, errbuf) != 0:
            raise RuntimeError(errbuf.value.decode(errors='replace'))
        link = datalink(handle)
        if on_packet and link != 1:
            raise RuntimeError('Captura ao vivo exige Ethernet')
        report['datalink'] = link
        header, data = C.POINTER(Header)(), C.POINTER(C.c_ubyte)()
        report['started_utc'] = datetime.now(timezone.utc).isoformat()
        if on_ready:
            on_ready(report.copy())
        if on_connections:
            on_connections(connections)
        last_connection_refresh = time.monotonic()
        last_connection_keys = {(c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port'])
                                for c in connections}
        deadline = time.monotonic() + args.seconds if args.seconds else None
        # Live mode delivers packets immediately and does not retain raw traffic.
        report['raw_pcap_saved'] = on_packet is None
        with (base.with_suffix('.pcap').open('wb') if on_packet is None else nullcontext(None)) as out:
            if out:
                out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
            while ((deadline is None or time.monotonic() < deadline) and
                   (on_packet is not None or report['bytes'] < 16 * 1024 * 1024) and
                   not (stop_event and stop_event.is_set())):
                if on_connections and time.monotonic()-last_connection_refresh >= 1:
                    previous_pid = report.get('pid')
                    latest = discover_connections()
                    latest_keys = {(c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port'])
                                   for c in latest}
                    pid_changed = game_pid != previous_pid
                    if latest_keys != last_connection_keys or pid_changed:
                        connections = latest
                        report['pid'] = game_pid
                        report['connections'] = connections
                        on_connections(connections, reset=pid_changed)
                        last_connection_keys = latest_keys
                    last_connection_refresh = time.monotonic()
                result = next_packet(handle, C.byref(header), C.byref(data))
                if result == 0:
                    time.sleep(0.01)
                    continue
                if result != 1:
                    raise RuntimeError(error(handle).decode(errors='replace'))
                h = header.contents
                if h.caplen > 65535:
                    raise RuntimeError('Tamanho de pacote inesperado')
                packet = C.string_at(data, h.caplen)
                if out:
                    out.write(struct.pack('<IIII', h.seconds, h.microseconds, h.caplen, h.length))
                    out.write(packet)
                if on_packet:
                    on_packet(packet, h.seconds + h.microseconds / 1e6)
                report['packets'] += 1
                report['bytes'] += h.caplen
        report['stopped_utc'] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        report['error'] = str(exc)
    finally:
        if handle:
            close(handle)
        base.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        if sys.stdout is not None:
            print(base.with_suffix('.json'))
    return report


if __name__ == '__main__':
    main()

