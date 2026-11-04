"""Reconstrução TCP offline e hipóteses de enquadramento; não interpreta dano."""
import argparse
import collections
import json
import struct
from pathlib import Path


def segments(path):
    raw = path.read_bytes()
    if len(raw) < 24 or raw[:4] != b'\xd4\xc3\xb2\xa1' or struct.unpack_from('<I', raw, 20)[0] != 1:
        raise ValueError('Esperado PCAP Ethernet little endian')
    offset = 24
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise ValueError('Registro truncado')
        sec, us, size, original = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        p = raw[offset:offset+size]
        offset += size
        if len(p) != size:
            raise ValueError('Pacote truncado')
        if len(p) < 34 or p[12:14] != b'\x08\x00':
            continue
        ip = p[14:]
        ihl, total = (ip[0] & 15)*4, int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or ihl < 20 or total > len(ip) or ip[9] != 6:
            continue
        if int.from_bytes(ip[6:8], 'big') & 0x3fff:
            raise ValueError('Fragmentação IP requer remontagem antes do TCP')
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        thl = (tcp[12] >> 4)*4
        if thl < 20 or thl > len(tcp):
            raise ValueError('Cabeçalho TCP inválido')
        sport, dport, seq = struct.unpack_from('!HHI', tcp)
        payload = tcp[thl:]
        if payload:
            key = (ip[12:16].hex(), sport, ip[16:20].hex(), dport)
            yield key, (seq + bool(tcp[13] & 2)) & 0xffffffff, payload, sec + us/1e6


def reconstruct(items):
    base = items[0][0]
    positions = {}
    duplicates = conflicts = 0
    for seq, payload, timestamp in items:
        relative = ((seq-base+2**31) % 2**32)-2**31
        for i, byte in enumerate(payload):
            pos = relative+i
            if pos in positions:
                duplicates += 1
                conflicts += positions[pos] != byte
            else:
                positions[pos] = byte
    runs = []
    start = previous = None
    buf = bytearray()
    for pos in sorted(positions):
        if previous is not None and pos != previous+1:
            runs.append((start, bytes(buf)))
            buf = bytearray()
            start = None
        if start is None:
            start = pos
        buf.append(positions[pos])
        previous = pos
    if buf:
        runs.append((start, bytes(buf)))
    return runs, {'unique_bytes': len(positions), 'duplicate_bytes': duplicates, 'conflicting_bytes': conflicts,
                  'gaps': [runs[i+1][0]-(runs[i][0]+len(runs[i][1])) for i in range(len(runs)-1)]}


def candidates(data):
    results = []
    for start in range(min(32, len(data))):
        for width in (2, 4):
            for endian in ('little', 'big'):
                for field_offset in (0, 1, 2, 4):
                    for adjustment in sorted({0, width, width+field_offset, 6}):
                        pos, sizes = start, []
                        while pos+field_offset+width <= len(data):
                            length = int.from_bytes(data[pos+field_offset:pos+field_offset+width], endian)+adjustment
                            if length < field_offset+width or length > 1048576 or pos+length > len(data):
                                break
                            sizes.append(length)
                            pos += length
                        if len(sizes) >= 4:
                            results.append({'start': start, 'width': width, 'endian': endian, 'field_offset': field_offset,
                                            'adjustment': adjustment, 'frames': len(sizes), 'consumed': pos-start,
                                            'trailing': len(data)-pos, 'first_lengths': sizes[:12]})
    # Multiple rules can be equivalent; retain unique hypotheses.
    unique = {json.dumps(r, sort_keys=True): r for r in results}
    return sorted(unique.values(), key=lambda r: (r['consumed'], r['frames']), reverse=True)[:8]


def analyze(path):
    grouped = collections.defaultdict(list)
    for key, seq, payload, timestamp in segments(path):
        grouped[key].append((seq, payload, timestamp))
    report = {'file': path.name, 'flows': []}
    for index, (key, items) in enumerate(grouped.items()):
        runs, stats = reconstruct(items)
        direction = 'server_to_client' if key[1] == 10004 else 'client_to_server'
        entry = dict(direction=direction, segments=len(items), **stats, runs=[])
        for number, (start, data) in enumerate(runs):
            output = path.with_suffix(f'.flow{index}.run{number}.bin')
            output.write_bytes(data)
            entry['runs'].append({'file': output.name, 'relative_start': start, 'length': len(data),
                                  'framing_candidates': candidates(data)})
        report['flows'].append(entry)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    args = parser.parse_args()
    report = analyze(args.pcap)
    args.pcap.with_suffix('.flows.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))

