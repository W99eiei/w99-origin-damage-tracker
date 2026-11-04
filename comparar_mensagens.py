"""Compara campos candidatos do cabeçalho; IDs ainda sem significado validado."""
import collections
import json
from pathlib import Path
from analisar_fluxo import segments, reconstruct


def frames(data):
    offset = 0
    while offset < len(data):
        if offset+6 > len(data):
            raise ValueError('Cabeçalho incompleto')
        size = int.from_bytes(data[offset:offset+2], 'big')+6
        if size < 8 or offset+size > len(data):
            raise ValueError('Mensagem incompleta ou pequena demais para o campo candidato')
        yield offset, data[offset:offset+size]
        offset += size


def inspect(path):
    grouped = collections.defaultdict(list)
    for key, seq, payload, timestamp in segments(path):
        grouped[key].append((seq, payload, timestamp))
    report = {'file': path.name, 'flows': []}
    for key, items in grouped.items():
        runs, stats = reconstruct(items)
        if stats['conflicting_bytes'] or stats['gaps'] or len(runs) != 1:
            raise ValueError('Fluxo não contínuo ou conflitante')
        types = {}
        previous = None
        increments = collections.Counter()
        count = 0
        for offset, frame in frames(runs[0][1]):
            count += 1
            candidate = int.from_bytes(frame[6:8], 'big')
            entry = types.setdefault(str(candidate), {'count': 0, 'sizes': collections.Counter()})
            entry['count'] += 1
            entry['sizes'][len(frame)] += 1
            sequence = int.from_bytes(frame[2:4], 'big')
            if previous is not None:
                increments[(sequence-previous) % 65536] += 1
            previous = sequence
        report['flows'].append({'direction': 'server_to_client' if key[1] == 10004 else 'client_to_server',
                                'messages': count, 'candidate_sequence_deltas': dict(increments), 'candidate_types': types})
    return report


if __name__ == '__main__':
    folder = Path(__file__).resolve().parent / 'analise_rede'
    reports = [inspect(folder / name) for name in ('npcap_20261031T212448Z.pcap', 'npcap_20261031T212529Z.pcap')]
    (folder / 'comparacao_mensagens.json').write_text(json.dumps(reports, indent=2), encoding='utf-8')
    for report in reports:
        print(report['file'])
        for flow in report['flows']:
            print(flow['direction'], 'mensagens:', flow['messages'], 'incrementos:', flow['candidate_sequence_deltas'])
            print('IDs candidatos (contagem):', {k: v['count'] for k, v in flow['candidate_types'].items()})

