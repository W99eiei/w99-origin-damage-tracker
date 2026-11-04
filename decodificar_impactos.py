"""Decodificação offline experimental do protocolo 10040 da versão analisada."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from analisar_fluxo import segments, reconstruct
from comparar_mensagens import frames
from app_paths import RESOURCE_DIR

ROOT = RESOURCE_DIR


def load_table():
    bundled_table = ROOT/'analise_engine/protocol_table.bin'
    if bundled_table.is_file():
        data = bundled_table.read_bytes()
        if len(data) != 256:
            raise ValueError('Tabela de protocolo incluída está incompleta')
        return data

    # Development fallback: read the table from the locally analyzed game
    # executable. Shareable builds include protocol_table.bin and never depend
    # on the developer's installation path.
    report = json.loads((ROOT/'analise_engine/referencias_executavel.json').read_text(encoding='utf-8'))
    path = Path(report['executable'])
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != report['sha256']:
            raise ValueError('Executável diferente da versão analisada')
        address = 0xa2fc3a0
        section = next(s for s in report['sections'] if s['rva'] <= address < s['rva']+s['raw_size'])
        stream.seek(section['raw_offset']+address-section['rva'])
        data = stream.read(1024)
        if len(data) != 1024:
            raise ValueError('Tabela incompleta')
        return data[::4]


class Reader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, size):
        if size < 0 or self.position+size > len(self.data):
            raise ValueError('Corpo truncado')
        result = self.data[self.position:self.position+size]
        self.position += size
        return result

    def number(self, size, signed=False):
        return int.from_bytes(self.take(size), 'big', signed=signed)


def decode_body(frame, table):
    if len(frame) < 19 or int.from_bytes(frame[:2], 'big')+6 != len(frame):
        raise ValueError('Comprimento externo inválido')
    mode = frame[8]
    if mode != 0:
        raise ValueError(f'Modo não implementado: {mode}')
    seed = int.from_bytes(frame[9:17], 'big', signed=True)
    if seed < 0:
        raise ValueError('Seed negativo não suportado')
    length = int.from_bytes(frame[17:19], 'big')
    if length != len(frame)-19:
        raise ValueError('Comprimento interno inválido')
    return seed, bytes(byte ^ table[(seed+i) % 256] for i, byte in enumerate(frame[19:]))


def decode(frame, table):
    if int.from_bytes(frame[6:8], 'big') != 10040:
        raise ValueError('Não é ReportImpact')
    seed, body = decode_body(frame, table)
    reader = Reader(body)
    result = {'sequence': int.from_bytes(frame[2:4], 'big'), 'protocol_id': 10040,
              'header_clock_raw': seed, 'caster_guid': str(reader.number(8)),
              'skill_object_guid': str(reader.number(8)), 'skill_guid': reader.number(4)}
    size = reader.number(2)
    if size % 2:
        raise ValueError('SkillID UTF-16 com comprimento ímpar')
    result['skill_id'] = reader.take(size).decode('utf-16le').rstrip('\0')
    result['impact_index'] = reader.number(4, True)
    result['fire_index'] = reader.number(4, True)
    result['behavior_array_index'] = reader.number(2, True)
    count = reader.number(2)
    if len(body)-reader.position != 76*count:
        raise ValueError(f'Lista não fecha: count={count}, restantes={len(body)-reader.position}')
    impacts = []
    for _ in range(count):
        impact = {'actor_guid': str(reader.number(8)), 'extra_caster_guid': str(reader.number(8)),
                  'damage_type': reader.number(2, True)}
        for field in ('damage', 'hp', 'extra_hp', 'ap'):
            impact[field] = reader.number(8, True)
        impact['exhaust_shield_count'] = reader.number(4, True)
        for field in ('is_no_damage', 'is_no_damage_no_local', 'is_critical', 'is_back_attack',
                      'is_block', 'unknown_flag_59', 'is_reflect', 'is_heal'):
            impact[field] = reader.number(1)
        impact['impact_target_type'] = reader.number(2, True)
        impact['is_sync_behavior'] = reader.number(1)
        impact['sub_area_index'] = reader.number(2, True)
        impact['multi_hit_count'] = reader.number(4, True)
        impact['multi_hit_interval'] = reader.number(4, True)
        impact['is_burst_active'] = reader.number(1)
        impacts.append(impact)
    result['impacts'] = impacts
    result['body_bytes_consumed'] = reader.position
    return result


def analyze(path, table):
    grouped = {}
    for key, seq, payload, timestamp in segments(path):
        if key[1] == 10004:
            grouped.setdefault(key, []).append((seq, payload, timestamp))
    results, errors = [], []
    for items in grouped.values():
        runs, stats = reconstruct(items)
        if stats['gaps'] or stats['conflicting_bytes'] or len(runs) != 1:
            raise ValueError('Fluxo descontínuo ou conflitante')
        for offset, frame in frames(runs[0][1]):
            if int.from_bytes(frame[6:8], 'big') != 10040:
                continue
            try:
                result = decode(frame, table)
                result['stream_offset'] = offset
                results.append(result)
            except (ValueError, UnicodeError) as exc:
                errors.append({'stream_offset': offset, 'error': str(exc)})
    return {'source': path.name, 'validation': 'Layout estático e consumo integral; valores ainda sem comparação visual.',
            'decoded_messages': len(results), 'errors': errors, 'messages': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    args = parser.parse_args()
    report = analyze(args.pcap, load_table())
    args.pcap.with_suffix('.impacts.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Mensagens decodificadas:', report['decoded_messages'], 'Erros:', report['errors'][:3])
    for msg in report['messages'][:3]:
        print('Habilidade:', msg['skill_id'], 'Resultados:', [{k: x[k] for k in ('damage','hp','is_critical','is_heal')} for x in msg['impacts']])

