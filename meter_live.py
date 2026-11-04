"""Núcleo incremental do medidor individual; nenhuma chamada de rede ativa ao jogo."""
import time
import re
import json
from collections import deque, Counter
from pathlib import Path
from decodificar_impactos import decode, decode_body
from app_paths import APP_DIR, RESOURCE_DIR

IDLE_RESET_SECONDS = 60
KNOWN_PLAYERS_PATH = APP_DIR/'identidades_jogadores.json'
DEFAULT_PLAYERS_PATH = RESOURCE_DIR/'identidades_jogadores.json'
PLAYER_KEY_PREFIXES = {bytes.fromhex('27f036'), bytes.fromhex('26d036'),
                       bytes.fromhex('270036'), bytes.fromhex('275036'),
                       bytes.fromhex('275037')}
ACTOR_KEY_PREFIXES = {bytes.fromhex('273036'), bytes.fromhex('273037'),
                      bytes.fromhex('27f037'), bytes.fromhex('26d037')}
LIFECYCLE_PROTOCOL_NAMES = {
    10183: 'P2C_ReportDungeonClearInfo',
    10188: 'P2C_ReportDungeonStateChanged',
    10194: 'P2C_ReportDungeonStart',
    10195: 'P2C_ResultDungeonStart',
    10199: 'P2C_ResultDungeonExit',
    10508: 'P2C_ReportDungeonEnter',
    10509: 'P2C_ReportDungeonLeave',
    10810: 'P2C_ResultDungeonMatchStart',
    10813: 'P2C_ReportDungeonMatchEnd',
    11036: 'P2C_ResultDungeonRewardEnd',
    11037: 'P2C_ReportDungeonReward',
    11354: 'P2C_ReportDungeonMvp',
}
RAID_MODE_PROTOCOL_NAMES = {
    11215: 'P2C_ReportRaidEliteKillUpdate',
    11216: 'P2C_ReportRaidEliteKillSummary',
    11217: 'P2C_ReportRaidPledgeUIOpen',
    11219: 'P2C_ResultRaidPledgeToggle',
    11221: 'P2C_ResultRaidPledgeLike',
    11222: 'P2C_ReportRaidPledgeStateSync',
    11224: 'P2C_ResultRaidPledgeConfirm',
    11225: 'P2C_ReportRaidPledgeConfirmed',
    11226: 'P2C_ReportRaidStartConfirmRequest',
    11228: 'P2C_ResultRaidStartReady',
    11229: 'P2C_ReportRaidStartDeny',
    11250: 'P2C_ReportRaidPledgeProgress',
}
LIFECYCLE_PROTOCOL_NAMES.update(RAID_MODE_PROTOCOL_NAMES)
# Equipment/team snapshots are captured locally so the payloads can be decoded
# and associated with the correct hero; they are not sent anywhere.
EQUIPMENT_CAPTURE_TYPES = {
    # Server snapshots/results for inventory, equipment and hero teams.
    10003, 10010, 10012, 10013, 10015, 10016, 10214, 10215,
    10216, 10218, 10220, 10221, 10231, 10265, 10266, 10280,
    10311, 10313, 10316, 10401, 10402, 10403, 10423, 10495,
    10496, 11119, 11300,
    # Viewing another player's card requests and returns their public profile.
    10282, 10283, 10284,
    # Client requests reveal which UI action triggered the following snapshot.
    10011, 10014, 10217, 10219, 10230, 10310, 10312, 10365,
    10367, 10404,
}
CLIENT_EQUIPMENT_REQUEST_TYPES = {10011, 10014, 10217, 10219, 10230, 10282,
                                  10310, 10312, 10365, 10367, 10404}
CLIENT_EQUIPMENT_REQUEST_NAMES = {
    10011: 'C2P_RequestItemEquip', 10014: 'C2P_RequestItemUnEquip',
    10217: 'C2P_RequestChangeHeroTeam', 10219: 'C2P_RequestChangeCurHero',
    10230: 'C2P_RequestHeroData', 10282: 'C2P_RequestOtherPlayerData',
    10310: 'C2P_RequestCostumeEquip',
    10312: 'C2P_RequestCostumeUnEquip', 10365: 'C2P_RequestRegistHeroTeamName',
    10367: 'C2P_RequestRegistHeroTeamSlot', 10404: 'C2P_RequestEquipOptionDecide',
}
OTHER_PLAYER_PROTOCOL_NAMES = {
    10283: 'P2C_ResultOtherPlayerData',
    10284: 'P2C_ReportOtherPlayerData',
}
DAMAGE_AUX_PROTOCOL_NAMES = {
    10130: 'P2C_ReportBuffImpact',
    11054: 'P2C_ReportBuffImpactList',
}
PROTOCOL_CAPTURE_TYPES = ({10009, 10021, 10022, 10130, 10138, 10140, 10189, 10508, 10559, 11054} |
                          set(LIFECYCLE_PROTOCOL_NAMES) | EQUIPMENT_CAPTURE_TYPES)


def decode_buff_impact(body):
    """Decodifica o formato observado de um único P2C_ReportBuffImpact.

    Layout confirmado na captura: GUID de origem/destino, GUID auxiliar,
    campos de estado, valor, HP do alvo, campo reservado, tamanho de string
    em big-endian e nome da habilidade UTF-16LE. Variantes ainda não
    confirmadas são ignoradas em vez de produzir um valor possivelmente falso.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) < 69:
        raise ValueError('P2C_ReportBuffImpact truncado')
    source = int.from_bytes(body[0:8], 'big')
    target = int.from_bytes(body[8:16], 'big')
    amount = int.from_bytes(body[32:40], 'big')
    hp = int.from_bytes(body[40:48], 'big')
    skill_length = int.from_bytes(body[56:60], 'big')
    if (not source or source == 0xffffffffffffffff or
            not target or target == 0xffffffffffffffff or
            skill_length < 2 or skill_length % 2 or
            60 + skill_length + 9 != len(body)):
        raise ValueError('Variante de P2C_ReportBuffImpact não validada')
    skill_id = body[60:60+skill_length].decode('utf-16le').rstrip('\0')
    if not skill_id or not re.fullmatch(r'[A-Za-z0-9_]+', skill_id):
        raise ValueError('Nome de habilidade inválido em P2C_ReportBuffImpact')
    is_heal = 'heal' in skill_id.casefold()
    return {
        'protocol_id': 10130,
        'caster_guid': str(source),
        'skill_id': skill_id,
        'impacts': [{
            'actor_guid': str(target),
            'extra_caster_guid': str(int.from_bytes(body[16:24], 'big')),
            'damage_type': 0,
            'damage': amount,
            'hp': hp,
            'extra_hp': int.from_bytes(body[48:56], 'big'),
            'ap': 0,
            'exhaust_shield_count': 0,
            'is_no_damage': 0,
            'is_no_damage_no_local': 0,
            'is_critical': 0,
            'is_back_attack': 0,
            'is_block': 0,
            'unknown_flag_59': 0,
            'is_reflect': 0,
            'is_heal': int(is_heal),
            'impact_target_type': 0,
            'is_sync_behavior': 0,
            'sub_area_index': -1,
            'multi_hit_count': 0,
            'multi_hit_interval': 0,
            'is_burst_active': 0,
        }],
    }


def is_player_key(value):
    if len(value) < 8:
        return False
    # Current party snapshots use 27?37??... UIDs; both the second and fourth
    # bytes vary between players/sessions. PartyData's name marker disambiguates
    # these IDs from other objects in the same family.
    current_uid = value[0] == 0x27 and value[2] == 0x37
    legacy_uid = value[:3] in PLAYER_KEY_PREFIXES and 0xf5 <= value[3] <= 0xff
    return current_uid or legacy_uid


def is_actor_key(value):
    return len(value) >= 8 and value[:3] in ACTOR_KEY_PREFIXES


def load_known_players():
    """Carrega associações de identidade confirmadas pelo usuário nesta máquina."""
    try:
        path = KNOWN_PLAYERS_PATH if KNOWN_PLAYERS_PATH.is_file() else DEFAULT_PLAYERS_PATH
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    players = data.get('players', {}) if isinstance(data, dict) else {}
    if not isinstance(players, dict):
        return {}
    return {str(key): name.strip() for key, name in players.items()
            if str(key).isdigit() and isinstance(name, str) and 1 <= len(name.strip()) <= 40}


def decode_party_members(body):
    """Extrai UIDs opacos e nicks de registros estruturados de PartyData."""
    members = {}
    for pos in range(len(body)-18):
        key = body[pos:pos+8]
        if (key in (bytes(8), b'\xff'*8) or
                body[pos+8:pos+13] != bytes.fromhex('00000004a8')):
            continue
        byte_length = int.from_bytes(body[pos+16:pos+18], 'big')
        if not 2 <= byte_length <= 80 or byte_length % 2 or pos+18+byte_length > len(body):
            continue
        try:
            name = body[pos+18:pos+18+byte_length].decode('utf-16le').rstrip('\0')
        except UnicodeError:
            continue
        if (not name or len(name.strip()) > 40 or any(ord(char) < 32 for char in name) or
                not any(char.isalnum() for char in name)):
            continue
        player_key = str(int.from_bytes(body[pos:pos+8], 'big'))
        members[player_key] = {'player_key': player_key, 'name': name}
    return list(members.values())


def decode_appearing_player(body):
    """Extrai a chave e o nick da mensagem de aparição de jogador observada."""
    if not is_player_key(body):
        return None
    candidates = []
    for alignment in range(2):
        for match in re.finditer(rb'(?:[\x20-\x7e]\x00){3,128}', body[alignment:]):
            name = match.group().decode('utf-16le', 'ignore').rstrip('\0')
            if (name and '_' not in name and any(char.isalpha() for char in name) and
                    not name.startswith(('epwp_', 'epeq_', 'eplb_', 'epacc_', 'epar_', 'epset_'))):
                candidates.append((alignment+match.start(), name))
    if not candidates:
        return None
    player_key = str(int.from_bytes(body[:8], 'big'))
    return {'player_key': player_key, 'name': min(candidates)[1]}


def decode_appearing_actor_owner(body):
    """Lê o par ator/dono observado nos pacotes de aparição de atores."""
    if len(body) < 210 or not is_actor_key(body[:8]):
        return None
    actor_key, owner_key = body[:8], body[202:210]
    if not (is_actor_key(owner_key) or is_player_key(owner_key)):
        return None
    return {'actor': str(int.from_bytes(actor_key, 'big')),
            'owner': str(int.from_bytes(owner_key, 'big'))}


def tcp_segment(packet, server_port, client_port, server_ip=None, client_ip=None):
    if len(packet) < 34 or packet[12:14] != b'\x08\x00':
        return None
    ip = packet[14:]
    ihl, size = (ip[0] & 15)*4, int.from_bytes(ip[2:4], 'big')
    if ip[0] >> 4 != 4 or ihl < 20 or size > len(ip) or ip[9] != 6:
        return None
    if int.from_bytes(ip[6:8], 'big') & 0x3fff:
        raise ValueError('Fragmentação IP: medição interrompida para evitar totais incompletos')
    source_ip = '.'.join(str(part) for part in ip[12:16])
    destination_ip = '.'.join(str(part) for part in ip[16:20])
    tcp = ip[ihl:size]
    if len(tcp) < 20:
        return None
    port = int.from_bytes(tcp[:2], 'big')
    dest_port = int.from_bytes(tcp[2:4], 'big')
    if server_ip is not None and client_ip is not None:
        if (source_ip, port, destination_ip, dest_port) == (server_ip, server_port, client_ip, client_port):
            direction = 'server_to_client'
        elif (source_ip, port, destination_ip, dest_port) == (client_ip, client_port, server_ip, server_port):
            direction = 'client_to_server'
        else:
            return None
    else:
        if port not in (server_port, client_port) and dest_port not in (server_port, client_port):
            return None
        direction = 'server_to_client' if port == server_port or dest_port == client_port else 'client_to_server'
    thl = (tcp[12] >> 4)*4
    if thl < 20 or thl > len(tcp):
        raise ValueError('Cabeçalho TCP inválido')
    if tcp[13] & 7:
        return None
    if not tcp[thl:]:
        return None
    return direction, int.from_bytes(tcp[4:8], 'big'), tcp[thl:]


class Stream:
    """Reordena TCP, ignora retransmissões e espera alinhamento confirmado."""
    def __init__(self, ids):
        self.ids = set(ids)
        self.next = None
        self.pending = {}
        self.history = {}
        self.history_order = deque()
        self.buffer = bytearray()
        self.synced = False
        self.sequence = None
        self.gap_since = None
        self.gap_events = 0
        self.gap_recoveries = 0
        self.gap_failures = 0
        self.gap_seconds_total = 0.0
        self.gap_failure_recorded = False

    def valid_header(self, pos):
        b = self.buffer
        return (pos+8 <= len(b) and int.from_bytes(b[pos:pos+2], 'big') >= 2 and
                int.from_bytes(b[pos+6:pos+8], 'big') in self.ids)

    def check_gap(self, now):
        if self.gap_since is not None and now-self.gap_since > 3:
            if not self.gap_failure_recorded:
                self.gap_failures += 1
                self.gap_failure_recorded = True
            raise ValueError('Lacuna TCP por mais de 3 segundos; reinicie a captura')

    def feed(self, seq, data, now):
        if self.next is None:
            self.next = seq
        for index, byte in enumerate(data):
            pos = (seq+index) & 0xffffffff
            distance = ((pos-self.next+2**31) % 2**32)-2**31
            if distance < 0:
                if pos in self.history and self.history[pos] != byte:
                    raise ValueError('Retransmissão TCP conflitante')
                continue
            if distance > 1_000_000:
                raise ValueError('Janela TCP excedida')
            if pos in self.pending and self.pending[pos] != byte:
                raise ValueError('Sobreposição TCP conflitante')
            self.pending[pos] = byte
        while self.next in self.pending:
            byte = self.pending.pop(self.next)
            self.buffer.append(byte)
            self.history[self.next] = byte
            self.history_order.append(self.next)
            if len(self.history_order) > 131072:
                self.history.pop(self.history_order.popleft(), None)
            self.next = (self.next+1) & 0xffffffff
        if self.pending:
            if self.gap_since is None:
                self.gap_since = now
                self.gap_events += 1
        else:
            if self.gap_since is not None:
                self.gap_recoveries += 1
                self.gap_seconds_total += max(0.0, now-self.gap_since)
            self.gap_since = None
            self.gap_failure_recorded = False
        self.check_gap(now)
        if not self.synced:
            for pos in range(max(0, len(self.buffer)-8)):
                if not self.valid_header(pos):
                    continue
                end = pos+6+int.from_bytes(self.buffer[pos:pos+2], 'big')
                if self.valid_header(end) and ((int.from_bytes(self.buffer[pos+2:pos+4], 'big')+1) & 65535) == int.from_bytes(self.buffer[end+2:end+4], 'big'):
                    del self.buffer[:pos]
                    self.synced = True
                    break
            if not self.synced:
                if len(self.buffer) > 131084:
                    raise ValueError('Não foi possível alinhar o protocolo')
                return []
        results = []
        while len(self.buffer) >= 8:
            size = int.from_bytes(self.buffer[:2], 'big')+6
            if size < 8:
                raise ValueError('Comprimento de mensagem inválido após sincronização')
            if len(self.buffer) < size:
                break
            seqnum = int.from_bytes(self.buffer[2:4], 'big')
            if self.sequence is not None and seqnum != (self.sequence+1) & 65535:
                raise ValueError('Sequência de mensagens descontínua')
            self.sequence = seqnum
            results.append(bytes(self.buffer[:size]))
            del self.buffer[:size]
        return results


class Meter:
    def __init__(self):
        self.actors = {}
        self.selected = None
        self.members = {}
        self.local_player_names = load_known_players()
        self.self_player_name = ''
        self.self_player_uid = None
        self.party_names = dict(self.local_player_names)
        self.party_roster_seen = False
        self.party_roster_count = 0
        self.party_roster_uids = set()
        self.party_roster_at = None
        self.inferred_player_actor = None
        self.inferred_player_uid = None
        self.appearance_names = {}
        self.actor_owners = {}
        self.manual_members = False
        self.raid_active = False
        self.reset_after_raid = False
        self.raid_exit_at = None
        self.boss_target_guids = []
        self.reset()

    def set_self_player_name(self, name):
        """Bind the configured account nickname to a known or local solo UID."""
        self.self_player_name = name.strip() if isinstance(name, str) else ''
        matches = [uid for uid, known_name in self.local_player_names.items()
                   if known_name.casefold() == self.self_player_name.casefold()]
        if matches:
            self.self_player_uid = matches[0]
            return
        self.self_player_uid = None
        if self.self_player_name:
            self.self_player_uid = 'solo:' + self.self_player_name.casefold()
            self.party_names[self.self_player_uid] = self.self_player_name

    def reset(self):
        self.damage = self.heal = self.hits = self.critical = 0
        self.heal_totals = {}
        self.heal_hits = {}
        self.heal_skills = {}
        self.healing_timeline = {}
        self.player_healing_timeline = {}
        self.damage_taken_stats = {}
        self.player_actors_seen = {}
        self.combat_markers = []
        self.start = self.last = None
        self.skills = {}
        self.target_stats = {}
        self.boss_target_guid = None
        self.boss_target_hp = 0
        self.boss_target_guids = []
        self.totals = {uid: {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0}
                       for uid in set(self.members.values())}

    def _remember_actor(self, actor, label=None):
        """Keep a bounded list for manual controls without stopping capture."""
        if actor in self.actors:
            if label:
                self.actors[actor]['label'] = label
            return True
        if len(self.actors) >= 256:
            return False
        self.actors[actor] = {
            'label': label or self.party_names.get(actor) or
                     self.appearance_names.get(actor) or f'Ator {len(self.actors)+1}',
            'skills': [],
        }
        return True

    def begin_dungeon(self):
        """Começa um novo conteúdo sem carregar o dano do anterior."""
        self.reset()
        self.raid_active = False
        self.reset_after_raid = False
        self.raid_exit_at = None

    def clear_party_roster(self):
        """Remove aliados da atividade anterior, mantendo a identidade local."""
        self.party_names = dict(self.local_player_names)
        self.self_player_uid = None
        if self.self_player_name:
            matches = [uid for uid, name in self.local_player_names.items()
                       if name.casefold() == self.self_player_name.casefold()]
            if matches:
                self.self_player_uid = matches[0]
            else:
                self.self_player_uid = 'solo:' + self.self_player_name.casefold()
                self.party_names[self.self_player_uid] = self.self_player_name
        self.party_roster_seen = False
        self.party_roster_count = 0
        self.party_roster_uids = set()
        self.party_roster_at = None
        self.actor_owners.clear()
        self.inferred_player_actor = None
        self.inferred_player_uid = None
        self.members = {}
        self.totals = {uid: {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0}
                       for uid in set(self.members.values())}
        self.heal_totals.clear()
        self.heal_hits.clear()
        self.heal_skills.clear()
        self.healing_timeline.clear()
        self.player_healing_timeline.clear()
        self.damage_taken_stats.clear()
        self.player_actors_seen.clear()
        self.selected = None

    def add_combat_marker(self, label, timestamp, source='manual'):
        label = str(label or '').strip()[:40]
        if not label:
            label = 'Marcação'
        self.combat_markers.append({'label': label, 'timestamp': float(timestamp),
                                    'source': source})
        self.combat_markers = self.combat_markers[-100:]

    def timeline_origin(self):
        candidates = [value for value in (self.start, *[marker['timestamp']
                      for marker in self.combat_markers]) if value is not None]
        candidates.extend(self.healing_timeline)
        return min(candidates) if candidates else None

    def begin_raid(self):
        """Mantém um único combate contínuo até a saída da raid."""
        if self.start is None:
            self.reset()
        self.raid_active = True
        self.reset_after_raid = False
        self.raid_exit_at = None

    def end_raid(self, timestamp):
        self.raid_active = False
        self.reset_after_raid = True
        self.raid_exit_at = timestamp

    def configure(self, members):
        if not isinstance(members, list) or len(members) > 16:
            raise ValueError('Selecione até 16 aliados')
        chosen = {}
        for member in members:
            if not isinstance(member, dict):
                raise ValueError('Aliado inválido')
            actor, uid = member.get('actor'), member.get('uid')
            if not isinstance(actor, str) or actor not in self.actors or actor in chosen:
                raise ValueError('Ator desconhecido ou repetido')
            if not isinstance(uid, str) or uid not in self.party_names:
                raise ValueError('UID de jogador desconhecido')
            chosen[actor] = uid
        changed = chosen != self.members
        self.members = chosen
        self.manual_members = True
        self.selected = next(iter(chosen), None)
        if changed:
            self.reset()

    def select(self, actor):
        if actor not in self.actors:
            raise ValueError('Ator não observado nesta captura')
        uid = self.members.get(actor) or (actor if actor in self.party_names else None)
        if uid is None:
            raise ValueError('UID de party do ator não confirmado')
        self.members = {actor: uid}
        self.manual_members = True
        self.selected = actor
        self.reset()

    def set_party_members(self, members, timestamp=None):
        if not isinstance(members, list):
            return
        names = {item['player_key']: item['name'] for item in members
                 if isinstance(item, dict) and isinstance(item.get('player_key'), str)
                 and isinstance(item.get('name'), str) and item['name']}
        if not names:
            return

        previous_names = self.party_names
        # PartyData is a complete roster snapshot. Replace the prior group's
        # names so a later solo activity doesn't keep displaying old members.
        self.party_names = {**self.local_player_names, **names}
        self_uid_matches = [uid for uid, name in names.items()
                            if self.self_player_name and
                            name.casefold() == self.self_player_name.casefold()]
        if self_uid_matches:
            self.self_player_uid = self_uid_matches[0]
        elif len(names) == 1:
            # A one-player roster is the local account in a solo activity.
            self.self_player_uid = next(iter(names))
        if self.self_player_uid and self.self_player_name:
            self.party_names.setdefault(self.self_player_uid, self.self_player_name)
        self.party_roster_seen = True
        self.party_roster_count = len(names)
        self.party_roster_uids = set(names)
        self.party_roster_at = timestamp

        # Carry damage already recorded under a local/older UID to the UID in
        # this roster snapshot when the display name identifies the same user.
        for player_key, name in names.items():
            for old_uid, old_name in previous_names.items():
                has_target_data = any(old_uid in target['players'] for target in self.target_stats.values())
                if old_uid != player_key and old_name == name and (
                        old_uid in self.totals or has_target_data or old_uid in self.heal_totals or
                        old_uid in self.player_actors_seen or old_uid in self.damage_taken_stats or
                        old_uid in self.player_healing_timeline):
                    previous = self.totals.pop(
                        old_uid, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
                    current = self.totals.setdefault(player_key, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
                    for field in ('damage', 'heal', 'hits', 'critical'):
                        current[field] += previous.get(field, 0)
                    if old_uid in self.heal_totals:
                        self.heal_totals[player_key] = self.heal_totals.get(player_key, 0) + self.heal_totals.pop(old_uid)
                        self.heal_hits[player_key] = self.heal_hits.get(player_key, 0) + self.heal_hits.pop(old_uid, 0)
                        old_heal_skills = self.heal_skills.pop(old_uid, {})
                        current_heal_skills = self.heal_skills.setdefault(player_key, {})
                        for skill_id, skill_stats in old_heal_skills.items():
                            target_skill = current_heal_skills.setdefault(
                                skill_id, {'healing': 0, 'hits': 0})
                            target_skill['healing'] += skill_stats.get('healing', 0)
                            target_skill['hits'] += skill_stats.get('hits', 0)
                    old_heal_timeline = self.player_healing_timeline.pop(old_uid, {})
                    new_heal_timeline = self.player_healing_timeline.setdefault(player_key, {})
                    for second, amount in old_heal_timeline.items():
                        new_heal_timeline[second] = new_heal_timeline.get(second, 0) + amount
                    old_taken = self.damage_taken_stats.pop(old_uid, None)
                    if old_taken:
                        new_taken = self.damage_taken_stats.setdefault(
                            player_key, {'damage': 0, 'hits': 0, 'deaths': 0,
                                         'revives': 0, 'down': False, 'sources': {}})
                        for field in ('damage', 'hits', 'deaths', 'revives'):
                            new_taken[field] += old_taken.get(field, 0)
                        new_taken['down'] = new_taken['down'] or old_taken.get('down', False)
                        for source, amount in old_taken.get('sources', {}).items():
                            new_taken['sources'][source] = new_taken['sources'].get(source, 0) + amount
                    old_actors = self.player_actors_seen.pop(old_uid, set())
                    self.player_actors_seen.setdefault(player_key, set()).update(old_actors)
                    for target in self.target_stats.values():
                        old_player = target['players'].pop(old_uid, None)
                        if old_player:
                            new_player = target['players'].setdefault(
                                player_key, {'damage': 0, 'hits': 0, 'critical': 0,
                                             'skills': {}, 'timeline': {}})
                            for field in ('damage', 'hits', 'critical'):
                                new_player[field] += old_player.get(field, 0)
                            for skill_id, skill_stats in old_player.get('skills', {}).items():
                                new_skill = new_player['skills'].setdefault(
                                    skill_id, {'damage': 0, 'hits': 0, 'critical': 0})
                                for field in ('damage', 'hits', 'critical'):
                                    new_skill[field] += skill_stats.get(field, 0)
                            for second, amount in old_player.get('timeline', {}).items():
                                new_player['timeline'][second] = new_player['timeline'].get(second, 0) + amount
                    for actor, uid in list(self.members.items()):
                        if uid == old_uid:
                            self.members[actor] = player_key
                    break

        valid_uids = set(self.party_names)
        self.members = {actor: uid for actor, uid in self.members.items() if uid in valid_uids}
        active_uids = set(self.members.values())
        self.totals = {uid: total for uid, total in self.totals.items() if uid in active_uids}
        self.heal_totals = {uid: total for uid, total in self.heal_totals.items() if uid in active_uids}
        self.heal_hits = {uid: total for uid, total in self.heal_hits.items() if uid in active_uids}
        self.heal_skills = {uid: skills for uid, skills in self.heal_skills.items() if uid in active_uids}
        self.player_healing_timeline = {uid: timeline for uid, timeline in self.player_healing_timeline.items()
                                        if uid in active_uids}
        self.damage_taken_stats = {uid: stats for uid, stats in self.damage_taken_stats.items()
                                   if uid in self.party_names}
        self.player_actors_seen = {uid: actors for uid, actors in self.player_actors_seen.items()
                                   if uid in self.party_names}
        for target in self.target_stats.values():
            target['players'] = {uid: total for uid, total in target['players'].items()
                                 if uid in active_uids}
        for player_key, name in self.party_names.items():
            self._remember_actor(player_key, name)
        if self.manual_members:
            return
        for player_key in names:
            self.members[player_key] = player_key
            self.totals.setdefault(player_key, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
        for actor, owner in self.actor_owners.items():
            self._assign_owner(actor, owner)
        if self.selected not in self.members:
            self.selected = next(iter(self.members), None)
        self._refresh_boss_totals()

    def _refresh_boss_totals(self):
        """Expose boss-only DPS, aggregating simultaneous raid bosses."""
        candidates = [(guid, target) for guid, target in self.target_stats.items()
                      if target['hp_max'] > 0 and guid not in self.members]
        self.heal = sum(self.heal_totals.values())
        if not candidates:
            self.boss_target_guid = None
            self.boss_target_hp = 0
            self.damage = self.hits = self.critical = 0
            self.start = self.last = None
            self.skills = {}
            self.totals = {}
            self.boss_target_guids = []
            return
        largest_hp = max(target['hp_max'] for _, target in candidates)
        if self.raid_active:
            # Taranis can expose two boss actors at once. Their HP pools are
            # comparable, while puzzle mobs/adds have far less HP.
            boss_candidates = [(guid, target) for guid, target in candidates
                               if target['hp_max'] >= largest_hp * 0.25]
        else:
            boss_candidates = [max(candidates, key=lambda item: (item[1]['hp_max'], item[1]['damage']))]
        guid, target = max(boss_candidates, key=lambda item: (item[1]['hp_max'], item[1]['damage']))
        self.boss_target_guids = [candidate_guid for candidate_guid, _ in boss_candidates]
        self.boss_target_guid = guid
        self.boss_target_hp = sum(candidate['hp_max'] for _, candidate in boss_candidates)
        totals = {}
        skills = {}
        first_hit = None
        last_hit = None
        for _, candidate in boss_candidates:
            first_hit = candidate['first'] if first_hit is None else min(first_hit, candidate['first'])
            last_hit = candidate['last'] if last_hit is None else max(last_hit, candidate['last'])
            for uid, values in candidate['players'].items():
                player_total = totals.setdefault(uid, {'damage': 0, 'hits': 0, 'critical': 0})
                for field in ('damage', 'hits', 'critical'):
                    player_total[field] += values.get(field, 0)
                for skill_id, skill_values in values.get('skills', {}).items():
                    skills[skill_id] = skills.get(skill_id, 0) + skill_values.get('damage', 0)
        self.totals = {uid: {**values, 'heal': 0} for uid, values in totals.items()}
        self.damage = sum(values['damage'] for values in totals.values())
        self.hits = sum(values['hits'] for values in totals.values())
        self.critical = sum(values['critical'] for values in totals.values())
        self.start = first_hit
        self.last = last_hit
        self.skills = skills

    def set_appearing_player(self, player):
        """Guarda um nome observado, sem tratá-lo como integrante da party."""
        if not isinstance(player, dict):
            return
        player_key, name = player.get('player_key'), player.get('name')
        if not isinstance(player_key, str) or not isinstance(name, str) or not name:
            return
        self.appearance_names[player_key] = name
        if self.self_player_name and name.casefold() == self.self_player_name.casefold():
            self.self_player_uid = player_key
            self.party_names[player_key] = name
        if player_key in self.actors:
            self._remember_actor(player_key, self.party_names.get(player_key, name))

    def set_actor_owner(self, actor, owner):
        self.actor_owners[actor] = owner
        self._assign_owner(actor, owner)

    def _assign_owner(self, actor, owner):
        if self.manual_members:
            return
        uid = owner if owner in self.party_names else self.members.get(owner)
        if uid and uid in self.party_names:
            self.members[actor] = uid
            self._remember_actor(actor)
            self.totals.setdefault(uid, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
            if actor in self.actors:
                self.selected = self.selected or actor

    def _party_uid_for_actor(self, actor):
        if actor in self.members:
            return self.members[actor]
        if actor in self.party_names:
            return actor
        owner = self.actor_owners.get(actor)
        if owner in self.party_names:
            return owner
        return self.members.get(owner)

    def _record_incoming_impacts(self, message):
        caster = str(message.get('caster_guid', ''))
        caster_uid = self._party_uid_for_actor(caster)
        for impact in message.get('impacts', []):
            target = str(impact.get('actor_guid', ''))
            uid = self._party_uid_for_actor(target)
            if not uid:
                continue
            stats = self.damage_taken_stats.setdefault(
                uid, {'damage': 0, 'hits': 0, 'deaths': 0, 'revives': 0,
                      'down': False, 'sources': {}})
            hp = max(0, int(impact.get('hp', 0) or 0))
            amount = max(0, int(impact.get('damage', 0) or 0))
            if impact.get('is_heal'):
                if stats['down'] and hp > 0:
                    stats['revives'] += 1
                    stats['down'] = False
                continue
            if caster_uid is not None or amount <= 0:
                continue
            stats['damage'] += amount
            stats['hits'] += 1
            skill = str(message.get('skill_id') or 'Desconhecida')
            stats['sources'][skill] = stats['sources'].get(skill, 0) + amount
            if hp == 0 and not stats['down']:
                stats['deaths'] += 1
                stats['down'] = True

    def event(self, message, now):
        actor = message['caster_guid']
        self._record_incoming_impacts(message)
        if actor in self.party_names:
            self._remember_actor(actor, self.party_names[actor])
            if not self.manual_members:
                self.members[actor] = actor
                self.totals.setdefault(actor, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
                self.selected = self.selected or actor
        if not self.manual_members and message['skill_id'].startswith('grade_'):
            local_names = set(self.local_player_names.values())
            if self.party_names.get(actor) in local_names:
                self.inferred_player_actor = actor
                self.inferred_player_uid = next(uid for uid, name in self.local_player_names.items()
                                                if name == self.party_names[actor])
            owner = self.actor_owners.get(actor)
            solo_roster = self.party_roster_seen and self.party_roster_count == 1
            ownerless_solo_actor = not self.party_roster_seen and owner is None
            if solo_roster and self.self_player_uid is None:
                self.self_player_uid = next(iter(self.party_names))
            if ownerless_solo_actor and self.self_player_uid is None:
                if len(self.local_player_names) == 1:
                    self.self_player_uid, inferred_name = next(iter(self.local_player_names.items()))
                else:
                    self.self_player_uid, inferred_name = 'solo:local', 'Você'
                self.party_names.setdefault(self.self_player_uid,
                                            self.self_player_name or inferred_name)
            if (self.self_player_uid and
                    (owner == self.self_player_uid or solo_roster or ownerless_solo_actor)):
                uid = self.self_player_uid
                self.members[actor] = uid
                self.totals.setdefault(uid, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
                self.selected = self.selected or actor
        # When the game does not send a party roster, the local identity file
        # can still identify the user's player actor from its playable-skill ID.
        if (not self.manual_members and not self.party_roster_seen and
                self.inferred_player_actor is None and message['skill_id'].startswith('grade_')):
            known_names = {}
            for uid, name in self.party_names.items():
                known_names.setdefault(name, uid)
            if len(known_names) == 1:
                uid = next(iter(known_names.values()))
                self.inferred_player_actor = actor
                self.inferred_player_uid = uid
                self.members[actor] = uid
                self.totals.setdefault(uid, {'damage': 0, 'heal': 0, 'hits': 0, 'critical': 0})
                self.selected = actor
        if actor not in self.members:
            return
        uid = self.members[actor]
        self.player_actors_seen.setdefault(uid, set()).add(actor)
        self._remember_actor(actor)
        actor_data = self.actors.get(actor)
        if actor_data is not None:
            skills = actor_data['skills']
            if message['skill_id'] not in skills:
                skills.append(message['skill_id'])
                del skills[:-6]
        positive = [i for i in message['impacts'] if i['damage'] > 0]
        damaging = [i for i in positive if not i['is_heal']]
        if positive and self.reset_after_raid:
            self.reset()
            self.reset_after_raid = False
            self.raid_exit_at = None
        elif (self.last is not None and now-self.last >= IDLE_RESET_SECONDS
              and not self.raid_active):
            self.reset()
        for impact in positive:
            if impact['is_heal']:
                self.heal_totals[uid] = self.heal_totals.get(uid, 0) + impact['damage']
                self.heal_hits[uid] = self.heal_hits.get(uid, 0) + 1
                second = int(now)
                self.healing_timeline[second] = self.healing_timeline.get(second, 0) + impact['damage']
                player_timeline = self.player_healing_timeline.setdefault(uid, {})
                player_timeline[second] = player_timeline.get(second, 0) + impact['damage']
                skill_stats = self.heal_skills.setdefault(uid, {}).setdefault(
                    message['skill_id'], {'healing': 0, 'hits': 0})
                skill_stats['healing'] += impact['damage']
                skill_stats['hits'] += 1
                continue
        if damaging:
            if self.start is None:
                self.start = now
            self.last = now
        elif not positive:
            if self.start is None:
                return
            self.last = now
        for impact in damaging:
            target_guid = str(impact.get('actor_guid', ''))
            if not target_guid or target_guid in self.members:
                continue
            target = self.target_stats.setdefault(target_guid, {
                'hp_max': 0, 'players': {}, 'skills': {}, 'first': now, 'last': now,
                'damage': 0, 'timeline': {},
            })
            target['first'] = min(target['first'], now)
            target['last'] = now
            target['damage'] += impact['damage']
            second = int(now)
            target['timeline'][second] = target['timeline'].get(second, 0) + impact['damage']
            target['hp_max'] = max(target['hp_max'], max(0, impact.get('hp', 0)))
            player = target['players'].setdefault(
                uid, {'damage': 0, 'hits': 0, 'critical': 0, 'skills': {}, 'timeline': {}})
            player['damage'] += impact['damage']
            player['hits'] += 1
            player['critical'] += bool(impact['is_critical'])
            player_timeline = player.setdefault('timeline', {})
            player_timeline[second] = player_timeline.get(second, 0) + impact['damage']
            key = message['skill_id']
            player_skill = player['skills'].setdefault(
                key, {'damage': 0, 'hits': 0, 'critical': 0})
            player_skill['damage'] += impact['damage']
            player_skill['hits'] += 1
            player_skill['critical'] += bool(impact['is_critical'])
            target['skills'][key] = target['skills'].get(key, 0)+impact['damage']
        self._refresh_boss_totals()

    def snapshot(self, now):
        active = (self.last is not None and
                  (self.raid_active or (not self.reset_after_raid and
                                        now-self.last < IDLE_RESET_SECONDS)))
        end_at = now if active else (self.raid_exit_at or self.last)
        duration = max(1., (end_at-self.start)) if self.start is not None and end_at is not None else 0.
        grouped = {}
        for uid in set(self.members.values()):
            actors = [actor for actor, member_uid in self.members.items()
                      if member_uid == uid and actor in self.actors]
            actor_label = self.actors[actors[0]]['label'] if actors else None
            name = self.party_names.get(uid) or actor_label or self.appearance_names.get(uid) or 'Jogador'
            row = {'name': name, 'uid': uid, 'actors': actors, 'damage': 0, 'heal': 0,
                   'heal_hits': 0, 'hits': 0, 'critical': 0}
            for key in ('damage','heal','hits','critical'):
                row[key] = self.totals.get(uid, {}).get(key, 0)
            row['heal'] = self.heal_totals.get(uid, 0)
            row['heal_hits'] = self.heal_hits.get(uid, 0)
            taken = self.damage_taken_stats.get(uid, {})
            row['damage_taken'] = taken.get('damage', 0)
            row['damage_taken_hits'] = taken.get('hits', 0)
            row['deaths'] = taken.get('deaths', 0)
            row['revives'] = taken.get('revives', 0)
            row['survival_observed'] = bool(taken.get('hits', 0) or taken.get('deaths', 0) or
                                            taken.get('revives', 0))
            grouped[uid] = row
        ranking = sorted([{**row, 'dps': row['damage']/duration if duration else 0,
                           'share': 100*row['damage']/self.damage if self.damage else 0}
                          for row in grouped.values()], key=lambda row: (-row['damage'], row['name']))
        origin = self.timeline_origin()
        markers = [{'label': marker['label'], 'source': marker['source'],
                    'second': max(0, round(marker['timestamp']-origin, 2)) if origin is not None else 0}
                   for marker in self.combat_markers]
        return {'actors': self.actors, 'selected': self.selected, 'damage': self.damage,
                'heal': sum(self.heal_totals.values()),
                'members': {actor: self.party_names.get(
                                uid, self.actors.get(actor, {}).get('label') or
                                self.appearance_names.get(actor) or 'Ator')
                            for actor, uid in self.members.items()},
                'member_uids': self.members, 'player_names': self.party_names, 'ranking': ranking,
                'hits': self.hits, 'critical': self.critical, 'duration': duration,
                'dps': self.damage/duration if duration else 0, 'active': active,
                'boss_target_guid': self.boss_target_guid, 'boss_target_hp': self.boss_target_hp,
                'combat_markers': markers,
                'skills': sorted(self.skills.items(), key=lambda x: x[1], reverse=True)}


class Pipeline:
    def __init__(self, table, ids, callback, server_port=10004, client_port=0, protocol_callback=None,
                 roster_callback=None, owner_callback=None, appearance_callback=None,
                 server_ip=None, client_ip=None):
        self.table, self.callback = table, callback
        self.stream = Stream(ids)
        self.client_stream = Stream(ids)
        self.server_port = server_port
        self.client_port = client_port
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.protocol_callback = protocol_callback
        self.roster_callback = roster_callback
        self.owner_callback = owner_callback
        self.appearance_callback = appearance_callback
        self.messages = self.impacts = 0
        self.types = Counter()
        self.last_packet_at = None

    def packet(self, packet, timestamp):
        self.last_packet_at = timestamp
        value = tcp_segment(packet, self.server_port, self.client_port,
                            self.server_ip, self.client_ip)
        if not value:
            return
        direction, seq, payload = value
        if direction == 'server_to_client':
            stream = self.stream
        elif direction == 'client_to_server':
            stream = self.client_stream
        else:
            return
        for frame in stream.feed(seq, payload, timestamp):
            self.messages += 1
            message_type = int.from_bytes(frame[6:8], 'big')
            self.types[message_type] += 1
            # The gear diagnostics are passive protocol observations. Keep the
            # direction label in the log, but don't discard a known type if a
            # connection is classified from the opposite endpoint ordering.
            capture_this_message = message_type in PROTOCOL_CAPTURE_TYPES
            if self.protocol_callback and capture_this_message:
                try:
                    seed, body = decode_body(frame, self.table)
                    if direction == 'server_to_client' and self.roster_callback and message_type == 10140:
                        self.roster_callback(decode_party_members(body), timestamp)
                    if direction == 'server_to_client' and self.appearance_callback and message_type == 10022:
                        appearing_player = decode_appearing_player(body)
                        if appearing_player:
                            self.appearance_callback(appearing_player, timestamp)
                    if direction == 'server_to_client' and self.owner_callback and message_type == 10021:
                        actor_owner = decode_appearing_actor_owner(body)
                        if actor_owner:
                            self.owner_callback(actor_owner, timestamp)
                    self.protocol_callback({'protocol_id': message_type,
                                            'protocol_name': (CLIENT_EQUIPMENT_REQUEST_NAMES.get(message_type)
                                                              if direction == 'client_to_server' else
                                                              (LIFECYCLE_PROTOCOL_NAMES.get(message_type) or
                                                               OTHER_PLAYER_PROTOCOL_NAMES.get(message_type) or DAMAGE_AUX_PROTOCOL_NAMES.get(message_type))),
                                            'direction': direction,
                                            'sequence': stream.sequence,
                                            'mode': frame[8], 'clock_raw': seed, 'body_hex': body.hex()}, timestamp)
                except ValueError:
                    self.protocol_callback({'protocol_id': message_type,
                                            'protocol_name': (CLIENT_EQUIPMENT_REQUEST_NAMES.get(message_type)
                                                              if direction == 'client_to_server' else
                                                              (LIFECYCLE_PROTOCOL_NAMES.get(message_type) or
                                                               OTHER_PLAYER_PROTOCOL_NAMES.get(message_type) or DAMAGE_AUX_PROTOCOL_NAMES.get(message_type))),
                                            'direction': direction,
                                            'sequence': stream.sequence,
                                            'mode': frame[8], 'body_hex': None}, timestamp)
            if direction == 'server_to_client' and message_type == 10040:
                msg = decode(frame, self.table)
                self.impacts += 1
                self.callback(msg, timestamp)


class MultiPipeline:
    """Reúne vários fluxos TCP do mesmo processo de jogo sem compartilhar sequência."""
    def __init__(self, table, ids, callback, protocol_callback=None, roster_callback=None,
                 owner_callback=None, appearance_callback=None):
        self.args = (table, ids, callback)
        self.callbacks = {'protocol_callback': protocol_callback, 'roster_callback': roster_callback,
                          'owner_callback': owner_callback, 'appearance_callback': appearance_callback}
        self.pipelines = {}
        self.messages = self.impacts = 0
        self.types = Counter()
        self.last_packet_at = None

    @staticmethod
    def _key(connection):
        return (connection['local_ip'], int(connection['local_port']),
                connection['remote_ip'], int(connection['remote_port']))

    def add_connections(self, connections, reset=False):
        if reset:
            self.pipelines.clear()
            self.messages = self.impacts = 0
            self.types.clear()
        desired = {self._key(connection) for connection in connections}
        for key in tuple(self.pipelines):
            if key not in desired:
                del self.pipelines[key]
        for connection in connections:
            key = self._key(connection)
            if key in self.pipelines:
                continue
            self.pipelines[key] = Pipeline(
                *self.args, server_port=key[3], client_port=key[1],
                server_ip=key[2], client_ip=key[0], **self.callbacks)

    def packet(self, packet, timestamp):
        self.last_packet_at = timestamp
        for pipeline in self.pipelines.values():
            old_messages, old_impacts = pipeline.messages, pipeline.impacts
            old_types = pipeline.types.copy()
            pipeline.packet(packet, timestamp)
            self.messages += pipeline.messages-old_messages
            self.impacts += pipeline.impacts-old_impacts
            for message_type, count in pipeline.types.items():
                difference = count-old_types.get(message_type, 0)
                if difference:
                    self.types[message_type] += difference

    def check_gap(self, now):
        for pipeline in self.pipelines.values():
            pipeline.stream.check_gap(now)
            pipeline.client_stream.check_gap(now)

