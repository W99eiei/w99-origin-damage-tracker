"""Painel local do DPS Meter v0.5. Abra http://127.0.0.1:8765."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import json
import math
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import capturar_npcap
from decodificar_impactos import load_table
from equipment_profiles import (decode_other_player_profile,
                                decode_party_member_equipment_markers,
                                decode_party_hero_equipment_update)
from meter_live import (IDLE_RESET_SECONDS, RAID_MODE_PROTOCOL_NAMES, Meter, MultiPipeline,
                        decode_buff_impact)
from app_paths import APP_DIR, RESOURCE_DIR

ROOT = APP_DIR
ASSETS = RESOURCE_DIR
SHARE_BUILD = (ASSETS/'distribution_build.json').is_file()
POST_CONTENT_GRACE_SECONDS = 20


class App:
    def __init__(self):
        self.lock = threading.RLock()
        self.meter = Meter()
        self.self_player_name = self._load_self_player_name()
        self.auto_save_enabled = self._load_auto_save_enabled()
        self.meter.set_self_player_name(self.self_player_name)
        self.thread = None
        self.stop_event = threading.Event()
        self.status = 'Pronto — inicie a captura e use uma habilidade para identificar seu ator.'
        self.running = False
        self.error = None
        self.pipeline = None
        self.session_file = None
        self.session_log_path = None
        self.protocol_log_path = None
        self.session_records_written = 0
        self.protocol_records_written = 0
        self.other_player_profiles = {}
        self.party_build_markers = {}
        self.pending_party_equipment = {}
        self.party_equipment_observations = {}
        self.dungeon_state = 'awaiting_start'
        self.dungeon_is_raid = False
        self.raid_marker_seen = False
        self.dungeon_started_at = None
        self.dungeon_ended_at = None
        self.dungeon_instance_guid = None
        self.dungeon_end_signal = None
        self.dungeon_clear_signal = None
        self.last_content_start_at = None
        self.last_content_exit_at = None
        self.exited_roster_names = set()
        self.results_cleared = False
        self.last_saved_result = None
        self.auto_save_pending = False
        self.content_name = 'Conteúdo'
        self.phase_marker_number = 0

    def _load_self_player_name(self):
        path = ROOT/'dps_meter_settings.json'
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            name = data.get('self_player_name', '') if isinstance(data, dict) else ''
            return name.strip() if isinstance(name, str) else ''
        except FileNotFoundError:
            return next(iter(self.meter.local_player_names.values()), '')
        except (OSError, ValueError):
            return ''

    def _load_auto_save_enabled(self):
        path = ROOT/'dps_meter_settings.json'
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            return bool(data.get('auto_save_results', True)) if isinstance(data, dict) else True
        except (OSError, ValueError):
            return True

    def start(self):
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('Captura já está em execução')
            self.meter = Meter()
            self.meter.set_self_player_name(self.self_player_name)
            self.pipeline = None
            self.error = None
            self.session_file = None
            self.session_log_path = None
            self.protocol_log_path = None
            self.session_records_written = 0
            self.protocol_records_written = 0
            self.other_player_profiles = {}
            self.party_build_markers = {}
            self.pending_party_equipment = {}
            self.party_equipment_observations = {}
            self.dungeon_state = 'awaiting_start'
            self.dungeon_is_raid = False
            self.raid_marker_seen = False
            self.dungeon_started_at = None
            self.dungeon_ended_at = None
            self.dungeon_instance_guid = None
            self.dungeon_end_signal = None
            self.dungeon_clear_signal = None
            self.last_content_start_at = None
            self.last_content_exit_at = None
            self.exited_roster_names = set()
            self.results_cleared = False
            self.last_saved_result = None
            self.auto_save_pending = False
            self.content_name = 'Conteúdo'
            self.phase_marker_number = 0
            self.stop_event = threading.Event()
            self.status = 'Preparando a captura…'
            self.running = True
            self.thread = threading.Thread(target=self.capture, daemon=True)
            self.thread.start()

    def capture(self):
        try:
            table = load_table()
            ids = {int(k) for k in json.loads((ASSETS/'analise_engine/protocolos_ids.json').read_text())}
            ids.update((1, 6))
            folder = ROOT/'sessoes'
            folder.mkdir(exist_ok=True)
            path = folder/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+secrets.token_hex(3)+'.jsonl')
            protocol_path = path.with_suffix('.protocol.jsonl')
            with path.open('w', encoding='utf-8') as log, protocol_path.open('w',encoding='utf-8') as protocol_log:
                with self.lock:
                    self.session_log_path = path
                    self.protocol_log_path = protocol_path
                def event(message, timestamp):
                    with self.lock:
                        self._associate_pending_party_equipment(message, timestamp)
                        self._expire_results(timestamp)
                        # Some practice rooms emit damage without a fresh
                        # dungeon-start protocol. Start a new non-raid activity
                        # on its first real hit so the prior boss target is not
                        # kept as the highest-HP candidate.
                        has_damage = any(i['damage'] > 0 and not i['is_heal']
                                         for i in message['impacts'])
                        grace_active = (
                            self.dungeon_state == 'ended' and
                            self.dungeon_ended_at is not None and
                            timestamp < self.dungeon_ended_at + POST_CONTENT_GRACE_SECONDS
                        )
                        if (has_damage and self.dungeon_state == 'ended' and
                                not self.raid_marker_seen and not grace_active):
                            self._auto_save_pending_result(timestamp)
                            if (self.dungeon_ended_at is not None and
                                    (self.meter.party_roster_at is None or
                                     self.meter.party_roster_at <= self.dungeon_ended_at)):
                                self.meter.clear_party_roster()
                            self.meter.begin_dungeon()
                            self.dungeon_started_at = timestamp
                            self.last_content_start_at = timestamp
                            self.dungeon_ended_at = None
                            self.dungeon_end_signal = None
                            self.dungeon_clear_signal = None
                            self.results_cleared = False
                            self.auto_save_pending = False
                            self.dungeon_is_raid = self.raid_marker_seen
                            if self.dungeon_is_raid:
                                self.meter.begin_raid()
                            self.dungeon_state = 'in_progress'
                        self.meter.event(message, timestamp)
                    log.write(json.dumps({'captured_at': timestamp, **message}, ensure_ascii=False)+'\n')
                    log.flush()
                    with self.lock:
                        self.session_records_written += 1
                    if log.tell() > 50_000_000:
                        raise ValueError('Limite de 50 MB da sessão atingido; inicie outra captura')
                def protocol_event(message,timestamp):
                    self.track_dungeon_event(message, timestamp)
                    if (message.get('protocol_id') == 10130 and
                            message.get('direction') == 'server_to_client'):
                        body_hex = message.get('body_hex')
                        if isinstance(body_hex, str):
                            try:
                                buff_impact = decode_buff_impact(bytes.fromhex(body_hex))
                            except (ValueError, TypeError):
                                buff_impact = None
                            if (buff_impact is not None and
                                    all(impact.get('is_heal') for impact in buff_impact['impacts'])):
                                with self.lock:
                                    combat_started = self.meter.start is not None
                                if not combat_started:
                                    buff_impact = None
                            if buff_impact is not None:
                                # ReportBuffImpact carries damage-over-time and
                                # buff damage absent from ReportImpact. Route it
                                # through the same party/boss filters and session
                                # log as direct impacts.
                                event(buff_impact, timestamp)
                    if message.get('protocol_id') == 10140 and message.get('direction') == 'server_to_client':
                        body_hex = message.get('body_hex')
                        if isinstance(body_hex, str):
                            try:
                                parsed_members = decode_party_member_equipment_markers(bytes.fromhex(body_hex))
                            except (ValueError, TypeError):
                                parsed_members = []
                            with self.lock:
                                current_uids = set(self.meter.party_names)
                                for uid in tuple(self.party_build_markers):
                                    if current_uids and uid not in current_uids:
                                        self.party_build_markers.pop(uid, None)
                                for member in parsed_members:
                                    if member.get('characters'):
                                        uid = member['player_uid']
                                        self.party_build_markers[uid] = {
                                            'player_uid': uid,
                                            'name': member['name'],
                                            'captured_at': timestamp,
                                            'characters': member['characters'],
                                        }
                    if message.get('protocol_id') == 10221 and message.get('direction') == 'server_to_client':
                        body_hex = message.get('body_hex')
                        if isinstance(body_hex, str):
                            try:
                                update = decode_party_hero_equipment_update(bytes.fromhex(body_hex))
                            except (ValueError, TypeError):
                                update = None
                            if update:
                                if update.get('equipment'):
                                    with self.lock:
                                        self.pending_party_equipment[update['player_uid']] = {
                                            **update,
                                            'captured_at': timestamp,
                                        }
                    protocol_log.write(json.dumps({'captured_at':timestamp,**message})+'\n')
                    protocol_log.flush()
                    with self.lock:
                        self.protocol_records_written += 1
                def roster_event(members, timestamp):
                    with self.lock:
                        names = {item.get('name') for item in members
                                 if isinstance(item, dict) and isinstance(item.get('name'), str)}
                        stale_after_exit = (
                            self.last_content_exit_at is not None and
                            0 <= timestamp-self.last_content_exit_at <= 5 and
                            (self.last_content_start_at is None or
                             self.last_content_start_at <= self.last_content_exit_at) and
                            bool(names) and names.issubset(self.exited_roster_names))
                        if stale_after_exit:
                            return
                        self.meter.set_party_members(members, timestamp)
                def appearance_event(player, timestamp):
                    with self.lock:
                        self.meter.set_appearing_player(player)
                def owner_event(relation, timestamp):
                    with self.lock:
                        self.meter.set_actor_owner(relation['actor'], relation['owner'])
                def connections_event(connections, reset=False):
                    with self.lock:
                        if self.pipeline:
                            self.pipeline.add_connections(connections, reset=reset)
                with self.lock:
                    self.pipeline = MultiPipeline(table, ids, event, protocol_callback=protocol_event,
                                                  roster_callback=roster_event, owner_callback=owner_event,
                                                  appearance_callback=appearance_event)
                    self.session_file = path.name
                def packet(data, timestamp):
                    with self.lock:
                        self.pipeline.packet(data, timestamp)
                def ready(report):
                    with self.lock:
                        self.pipeline.add_connections(report.get('connections', []))
                        self.status = 'Capturando conexões do jogo — aguardando os dados da party e os impactos.'
                def capture_status(message):
                    with self.lock:
                        self.status = message
                report = capturar_npcap.main(['--seconds', '0', '--wait-for-connection'], on_packet=packet,
                                              stop_event=self.stop_event, on_ready=ready,
                                              on_connections=connections_event,
                                              on_status=capture_status)
                with self.lock:
                    self.error = self.error or report.get('error')
                    self.status = ('Erro: '+self.error) if self.error else 'Captura encerrada. Os resultados foram mantidos.'
                    report['protocol_types'] = dict(self.pipeline.types)
                    report['impact_messages'] = self.pipeline.impacts
                    path.with_suffix('.diagnostic.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
                self.status = 'Erro: '+str(exc)
        finally:
            with self.lock:
                self.running = False

    def track_dungeon_event(self, message, timestamp):
        """Atualiza o estado da raid a partir de mensagens servidor-cliente observadas."""
        protocol_id = message.get('protocol_id')
        protocol_name = message.get('protocol_name')
        with self.lock:
            body_hex = message.get('body_hex')
            if protocol_id == 10284 and isinstance(body_hex, str):
                try:
                    profile = decode_other_player_profile(bytes.fromhex(body_hex))
                except (ValueError, UnicodeError):
                    profile = None
                if profile and profile['characters']:
                    profile['captured_at'] = timestamp
                    self.other_player_profiles[profile['profile_key']] = profile
            if protocol_id == 10021 and isinstance(body_hex, str):
                try:
                    body_text = bytes.fromhex(body_hex).decode('utf-16le', errors='ignore').lower()
                except ValueError:
                    body_text = ''
                marker = re.search(r'dungeon_([a-z0-9]+)_', body_text)
                if marker:
                    token = marker.group(1)
                    known_names = {'taranis': 'Taranis'}
                    self.content_name = known_names.get(
                        token, token.replace('_', ' ').title())
                if 'dungeon_taranis_' in body_text:
                    self._begin_raid_from_marker(timestamp)

            if protocol_id in {10194, 10195, 10508, 10810}:
                if self.dungeon_state not in {'in_progress', 'clear_reported'}:
                    if self.dungeon_state == 'ended':
                        self._auto_save_pending_result(timestamp)
                    if (self.dungeon_state == 'ended' and self.dungeon_ended_at is not None and
                            (self.meter.party_roster_at is None or
                             self.meter.party_roster_at <= self.dungeon_ended_at)):
                        self.meter.clear_party_roster()
                    self.meter.begin_dungeon()
                    self.dungeon_started_at = timestamp
                    self.last_content_start_at = timestamp
                    self.dungeon_ended_at = None
                    self.dungeon_end_signal = None
                    self.dungeon_clear_signal = None
                    self.results_cleared = False
                    self.auto_save_pending = False
                    self.dungeon_is_raid = self.raid_marker_seen
                    if not self.dungeon_is_raid:
                        self.content_name = 'Conteúdo'
                    self.phase_marker_number = 0
                    if self.dungeon_is_raid:
                        self.meter.begin_raid()
                self.dungeon_state = 'in_progress'
            elif protocol_id in RAID_MODE_PROTOCOL_NAMES:
                self.raid_marker_seen = True
                if self.dungeon_state in {'in_progress', 'clear_reported'} and not self.dungeon_is_raid:
                    self.dungeon_is_raid = True
                    self.meter.begin_raid()
            elif protocol_id == 10188 and self.dungeon_is_raid:
                # In the captured Taranis stream, state 5 marks a boss/phase
                # result and state 8 marks the final exit. Do not end the raid
                # at the intermediate boss result.
                try:
                    body = bytes.fromhex(body_hex) if isinstance(body_hex, str) else b''
                except ValueError:
                    body = b''
                state_code = body[9] if len(body) > 9 and body[8] == 0 else None
                instance_guid = body[:8].hex() if len(body) >= 8 else None
                same_raid_instance = bool(
                    instance_guid and self.dungeon_instance_guid and
                    instance_guid == self.dungeon_instance_guid)
                if state_code == 2:
                    if (self.dungeon_state == 'ended' and same_raid_instance and
                            self.dungeon_ended_at is not None and
                            timestamp >= self.dungeon_ended_at):
                        # The in-game Retry button reuses the current raid
                        # instance and does not resend PartyData. Begin a clean
                        # attempt while retaining the confirmed roster/owners.
                        self._auto_save_pending_result(timestamp)
                        self.meter.begin_dungeon()
                        self.meter.begin_raid()
                        self.dungeon_started_at = timestamp
                        self.last_content_start_at = timestamp
                        self.dungeon_ended_at = None
                        self.dungeon_end_signal = None
                        self.dungeon_clear_signal = None
                        self.results_cleared = False
                        self.auto_save_pending = False
                        self.phase_marker_number = 0
                        self.raid_marker_seen = True
                        self.dungeon_state = 'in_progress'
                    elif instance_guid:
                        self.dungeon_instance_guid = instance_guid
                elif state_code == 8:
                    if instance_guid:
                        self.dungeon_instance_guid = instance_guid
                    self.meter.add_combat_marker('Fim da raid', timestamp, source='game')
                    self._finish_content(timestamp, protocol_name or 'P2C_ReportDungeonStateChanged (8)')
                elif state_code == 5:
                    if instance_guid:
                        self.dungeon_instance_guid = instance_guid
                    self.phase_marker_number += 1
                    self.meter.add_combat_marker(
                        f'Fim da fase {self.phase_marker_number}', timestamp, source='game')
            elif protocol_id in {10183, 11354}:
                if self.dungeon_state == 'in_progress' and not self.dungeon_is_raid:
                    self.dungeon_state = 'clear_reported'
                    self.dungeon_clear_signal = protocol_name
            elif protocol_id in {10199, 10509, 10813, 11036}:
                self._finish_content(timestamp, protocol_name)

    def _begin_raid_from_marker(self, timestamp):
        """Recognize Taranis from its map object identifiers in protocol 10021."""
        raid_already_active = self.dungeon_is_raid and self.meter.raid_active
        if self.dungeon_state == 'ended':
            self._auto_save_pending_result(timestamp)
            if (self.dungeon_ended_at is not None and
                    (self.meter.party_roster_at is None or
                     self.meter.party_roster_at <= self.dungeon_ended_at)):
                self.meter.clear_party_roster()
            self.meter.begin_dungeon()
            self.dungeon_started_at = timestamp
            self.last_content_start_at = timestamp
            self.dungeon_ended_at = None
            self.dungeon_end_signal = None
            self.dungeon_clear_signal = None
            self.results_cleared = False
            self.auto_save_pending = False
        elif self.dungeon_state == 'awaiting_start':
            self.meter.begin_dungeon()
            self.dungeon_started_at = timestamp
            self.last_content_start_at = timestamp
            self.results_cleared = False
        self.raid_marker_seen = True
        self.dungeon_is_raid = True
        if self.content_name == 'Conteúdo':
            self.content_name = 'Taranis'
        self.phase_marker_number = 0
        self.dungeon_state = 'in_progress'
        if not raid_already_active:
            self.meter.begin_raid()

    def _finish_content(self, timestamp, signal):
        if self.dungeon_state == 'ended':
            return
        self.exited_roster_names = {
            name for uid, name in self.meter.party_names.items()
            if uid not in self.meter.local_player_names
        }
        self.dungeon_state = 'ended'
        self.dungeon_ended_at = timestamp
        self.dungeon_end_signal = signal
        if self.dungeon_is_raid:
            self.meter.end_raid(timestamp)
        # Keep the roster and score live for a short grace period so late
        # impacts and the final result remain visible.
        self.last_content_exit_at = timestamp
        self.results_cleared = False
        self.auto_save_pending = True
        self.raid_marker_seen = False

    def _auto_save_pending_result(self, now):
        if not self.auto_save_pending:
            return
        if self.auto_save_enabled:
            try:
                self.last_saved_result = self._save_result(now, saved_automatically=True)
                self.status = 'Resultado salvo automaticamente após o conteúdo.'
            except ValueError:
                pass
            except OSError as exc:
                self.error = str(exc)
        self.auto_save_pending = False

    def _expire_results(self, now):
        """Archive and clear finished content after the result grace period."""
        if (self.dungeon_state == 'ended' and not self.results_cleared and
                self.dungeon_ended_at is not None and
                now >= self.dungeon_ended_at + POST_CONTENT_GRACE_SECONDS):
            self._auto_save_pending_result(now)
            # Keep raid party IDs through the result screen: Retry reuses the
            # same instance and does not necessarily send another PartyData.
            # The next explicit content start clears this old roster if needed.
            if not self.dungeon_is_raid:
                self.meter.clear_party_roster()
            self.meter.begin_dungeon()
            self.results_cleared = True

    def _save_result(self, now, saved_automatically=False):
        """Write detailed combat statistics without changing the live panel."""
        snapshot = self.meter.snapshot(now)
        if not snapshot['ranking'] or (snapshot['damage'] <= 0 and snapshot['heal'] <= 0):
            raise ValueError('Ainda não há dano ou cura contabilizados para salvar.')
        folder = self._statistics_directory()
        folder.mkdir(exist_ok=True)
        filename = (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') +
                    '_' + secrets.token_hex(3) + '.json')
        target_players = {}
        boss_guids = [guid for guid in (self.meter.boss_target_guids or
                                         [self.meter.boss_target_guid]) if guid]
        timeline_origin = self.meter.timeline_origin()
        for boss_guid in boss_guids:
            target = self.meter.target_stats.get(boss_guid, {})
            for uid, player in target.get('players', {}).items():
                combined = target_players.setdefault(uid, {'skills': {}})
                for skill_id, skill in player.get('skills', {}).items():
                    combined_skill = combined['skills'].setdefault(
                        skill_id, {'damage': 0, 'hits': 0, 'critical': 0})
                    for field in ('damage', 'hits', 'critical'):
                        combined_skill[field] += skill.get(field, 0)
        ranking = []
        for position, row in enumerate(snapshot['ranking'], 1):
            skill_stats = target_players.get(row['uid'], {}).get('skills', {})
            skills = sorted(({'skill_id': skill_id,
                              'damage': values.get('damage', 0),
                              'share_percent': round(100*values.get('damage', 0)/row['damage'], 2)
                                  if row['damage'] else 0,
                              'hits': values.get('hits', 0),
                              'critical_hits': values.get('critical', 0)}
                             for skill_id, values in skill_stats.items()),
                            key=lambda item: (-item['damage'], item['skill_id']))
            healing_skill_stats = self.meter.heal_skills.get(row['uid'], {})
            healing_skills = sorted(({'skill_id': skill_id,
                                      'healing': values.get('healing', 0),
                                      'share_percent': round(100*values.get('healing', 0)/row['heal'], 2)
                                          if row['heal'] else 0,
                                      'hits': values.get('hits', 0)}
                                     for skill_id, values in healing_skill_stats.items()),
                                    key=lambda item: (-item['healing'], item['skill_id']))
            hits = row.get('hits', 0)
            critical = row.get('critical', 0)
            heal_hits = row.get('heal_hits', 0)
            ranking.append({
                'rank': position,
                'name': row['name'],
                'uid': row['uid'],
                'damage': row['damage'],
                'damage_share_percent': round(row.get('share', 0), 2),
                'dps': round(row.get('dps', 0), 2),
                'hits': hits,
                'critical_hits': critical,
                'critical_rate_percent': round(100*critical/hits, 2) if hits else 0,
                'average_hit': round(row['damage']/hits, 2) if hits else 0,
                'skills': skills,
                'healing': row.get('heal', 0),
                'healing_share_percent': round(100*row.get('heal', 0)/snapshot['heal'], 2)
                    if snapshot['heal'] else 0,
                'heal_hits': heal_hits,
                'average_heal': round(row.get('heal', 0)/heal_hits, 2) if heal_hits else 0,
                'healing_skills': healing_skills,
                'damage_taken': row.get('damage_taken', 0),
                'damage_taken_hits': row.get('damage_taken_hits', 0),
                'survival_observed': row.get('survival_observed', False),
                'deaths': row.get('deaths', 0),
                'revives': row.get('revives', 0),
                'activity': self._player_activity(row['uid'], boss_guids,
                                                  timeline_origin, snapshot['duration']),
            })
        total_hits = snapshot['hits']
        total_critical = snapshot['critical']
        total_heal_hits = sum(row.get('heal_hits', 0) for row in snapshot['ranking'])
        timeline_buckets = {}
        if timeline_origin is not None:
            for boss_guid in boss_guids:
                target = self.meter.target_stats.get(boss_guid, {})
                for timestamp, amount in target.get('timeline', {}).items():
                    second = max(0, int(timestamp)-int(timeline_origin))
                    timeline_buckets.setdefault(second, {'damage': 0, 'healing': 0})['damage'] += amount
            for timestamp, amount in self.meter.healing_timeline.items():
                second = max(0, int(timestamp)-int(timeline_origin))
                timeline_buckets.setdefault(second, {'damage': 0, 'healing': 0})['healing'] += amount
        timeline = [{'second': second, **values}
                    for second, values in sorted(timeline_buckets.items())]
        skill_totals = [{'skill_id': skill_id, 'damage': damage,
                         'share_percent': round(100*damage/snapshot['damage'], 2)
                             if snapshot['damage'] else 0}
                        for skill_id, damage in snapshot['skills']]
        equipment_profiles = self._matched_equipment_profiles()
        party_build_markers = self._matched_party_build_markers()
        party_equipment_observations = self._matched_party_equipment_observations()
        hp_signature = sorted({int(round(math.log10(max(1, int(
            self.meter.target_stats.get(guid, {}).get('hp_max', 0))))*10))
            for guid in boss_guids
            if self.meter.target_stats.get(guid, {}).get('hp_max', 0) > 0})
        content_name = self.content_name or ('Raid' if self.dungeon_is_raid else 'Conteúdo')
        boss_key = (f"{content_name.casefold()}|{'-'.join(map(str, hp_signature))}"
                    if hp_signature else '')
        record = {
            'format_version': 10,
            'id': filename[:-5],
            'saved_at': datetime.now(timezone.utc).isoformat(),
            'saved_automatically': bool(saved_automatically),
            'content': 'Raid' if self.dungeon_is_raid else 'Conteúdo',
            'content_name': content_name,
            'boss_key': boss_key,
            'end_signal': self.dungeon_end_signal,
            'session_file': self.session_file,
            'total_damage': snapshot['damage'],
            'total_healing': snapshot['heal'],
            'total_heal_hits': total_heal_hits,
            'total_damage_taken': sum(row.get('damage_taken', 0) for row in snapshot['ranking']),
            'total_deaths_inferred': sum(row.get('deaths', 0) for row in snapshot['ranking']),
            'total_revives_observed': sum(row.get('revives', 0) for row in snapshot['ranking']),
            'duration': round(snapshot['duration'], 2),
            'dps': round(snapshot['dps'], 2),
            'total_hits': total_hits,
            'critical_hits': total_critical,
            'critical_rate_percent': round(100*total_critical/total_hits, 2) if total_hits else 0,
            'average_hit': round(snapshot['damage']/total_hits, 2) if total_hits else 0,
            'party_coverage': self._party_coverage(snapshot),
            'capture_quality': self._capture_quality(),
            'boss_target_hp': self.meter.boss_target_hp,
            'timeline': timeline,
            'combat_markers': snapshot.get('combat_markers', []),
            'boss_segments': self._raid_boss_segments(boss_guids, timeline_origin)
                if self.dungeon_is_raid else [],
            'ranking': ranking,
            'skill_totals': skill_totals,
            'equipment_profiles': equipment_profiles,
            'party_build_markers': party_build_markers,
            'party_equipment_observations': party_equipment_observations,
        }
        (folder/filename).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        return record['id']

    def _matched_equipment_profiles(self):
        """Attach only profiles uniquely matched to the current party roster.

        The profile request uses a separate opaque key. The result's canonical
        identity is still the party UID, reached through an exact, unique
        server-provided nickname match in the current roster snapshot.
        """
        if not self.meter.party_roster_seen:
            return {}
        by_name = {}
        for uid, name in self.meter.party_names.items():
            if isinstance(name, str) and name.strip():
                by_name.setdefault(name.strip().casefold(), []).append(uid)

        start_at = self.last_content_start_at
        oldest_accepted = start_at - 600 if start_at is not None else None
        matched = {}
        for profile in self.other_player_profiles.values():
            name = profile.get('name')
            captured_at = profile.get('captured_at')
            if not isinstance(name, str) or not isinstance(captured_at, (int, float)):
                continue
            if oldest_accepted is not None and captured_at < oldest_accepted:
                continue
            candidates = by_name.get(name.strip().casefold(), [])
            if len(candidates) != 1:
                continue
            uid = candidates[0]
            matched[uid] = {
                'player_uid': uid,
                'name': name,
                'captured_at': captured_at,
                'characters': copy.deepcopy(profile.get('characters', [])),
            }
        return matched

    def _matched_party_build_markers(self):
        """Attach only party-marker data keyed by the server-provided UID."""
        roster_uids = {str(uid) for uid in self.meter.party_names}
        return {
            uid: copy.deepcopy(profile)
            for uid, profile in self.party_build_markers.items()
            if uid in roster_uids
        }

    def _associate_pending_party_equipment(self, message, timestamp):
        """Link a 10221 item snapshot to the next observed hit from that UID."""
        impacts = message.get('impacts', [])
        if not any(item.get('damage', 0) > 0 and not item.get('is_heal')
                   for item in impacts if isinstance(item, dict)):
            return
        actor = str(message.get('caster_guid', ''))
        uid = (actor if actor in self.meter.party_names else
               self.meter.members.get(actor) or self.meter.actor_owners.get(actor))
        if uid is None:
            return
        uid = str(uid)
        pending = self.pending_party_equipment.get(uid)
        if not pending:
            return
        delay = timestamp - pending['captured_at']
        if delay < 0:
            return
        if delay > 10:
            self.pending_party_equipment.pop(uid, None)
            return
        skill_id = str(message.get('skill_id', '')).lower()
        character_key = self._character_key_from_skill(skill_id)
        if not character_key:
            return

        player_name = self.meter.party_names.get(uid) or pending.get('name') or 'Jogador'
        player = self.party_equipment_observations.setdefault(uid, {
            'player_uid': uid, 'name': player_name, 'snapshots': [],
        })
        snapshot = {
            'hero_code': pending.get('hero_code'),
            'hero_entity_key': pending.get('hero_entity_key'),
            'captured_at': pending['captured_at'],
            'confirmed_at': timestamp,
            'association_delay_seconds': round(delay, 3),
            'character_hint': character_key,
            'evidence_skill_id': skill_id,
            'association_method': 'UID + próximo acerto após P2C_ReportChangeCurHero (inferência)',
            'equipment': copy.deepcopy(pending.get('equipment', [])),
        }
        signature = (snapshot['hero_code'], snapshot['hero_entity_key'],
                     tuple(sorted(item['item_id'] for item in snapshot['equipment'])))
        existing = next((item for item in player['snapshots']
                         if (item.get('hero_code'), item.get('hero_entity_key'),
                             tuple(sorted(value['item_id'] for value in item.get('equipment', [])))) == signature), None)
        if existing:
            existing['last_seen_at'] = timestamp
            existing['observations'] = existing.get('observations', 1) + 1
            existing['association_delay_seconds'] = snapshot['association_delay_seconds']
            existing['evidence_skill_id'] = skill_id
            existing['character_hint'] = character_key
        else:
            snapshot['last_seen_at'] = timestamp
            snapshot['observations'] = 1
            player['snapshots'].append(snapshot)
            player['snapshots'] = player['snapshots'][-32:]
        self.pending_party_equipment.pop(uid, None)

    @staticmethod
    def _character_key_from_skill(skill_id):
        character_keys = (
            'meliodas', 'gowther', 'elizabeth', 'lancelot', 'jericho', 'diane',
            'howzer', 'merlin', 'klotho', 'manny', 'daisy', 'elaine', 'aragon',
            'thorin', 'calla', 'estia', 'king', 'ban', 'hawk',
        )
        for key in character_keys:
            if re.search(rf'(?:^|_){re.escape(key)}_', skill_id):
                return key
        return None

    def _matched_party_equipment_observations(self):
        roster_uids = {str(uid) for uid in self.meter.party_names}
        result = {}
        for uid, player in self.party_equipment_observations.items():
            if uid not in roster_uids:
                continue
            data = copy.deepcopy(player)
            hints = {}
            for snapshot in data.get('snapshots', []):
                identity = (snapshot.get('hero_code'), snapshot.get('hero_entity_key'))
                if snapshot.get('character_hint'):
                    hints.setdefault(identity, set()).add(snapshot['character_hint'])
            for snapshot in data.get('snapshots', []):
                identity = (snapshot.get('hero_code'), snapshot.get('hero_entity_key'))
                candidates = hints.get(identity, set())
                snapshot['character_candidates'] = sorted(candidates)
                snapshot['character_hint'] = next(iter(candidates)) if len(candidates) == 1 else None
            result[uid] = data
        return result

    def saved_results(self):
        results = []
        seen = set()
        for folder in self._statistics_folders():
            if not folder.is_dir():
                continue
            for path in folder.glob('*.json'):
                try:
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if record.get('id') in seen:
                        continue
                    results.append({key: record[key] for key in
                                    ('id', 'saved_at', 'saved_automatically', 'content', 'content_name',
                                     'boss_key', 'total_damage', 'total_healing')
                                    if key in record})
                    seen.add(record.get('id'))
                except (OSError, ValueError, KeyError):
                    continue
        return sorted(results, key=lambda row: row.get('saved_at', ''), reverse=True)

    def _statistics_directory(self):
        if SHARE_BUILD:
            return ROOT/'estatisticas'
        # Keep the archive shared between versioned portable app folders.
        return ROOT.parent/'estatisticas' if getattr(sys, 'frozen', False) else ROOT/'estatisticas'

    def _statistics_folders(self):
        folders = [self._statistics_directory()]
        if SHARE_BUILD:
            return folders
        if getattr(sys, 'frozen', False):
            folders.extend(ROOT.parent.glob('app_auto_boss_v*/estatisticas'))
        return list(dict.fromkeys(folders))

    def load_saved_result(self, result_id):
        if not re.fullmatch(r'\d{8}T\d{6}Z_[0-9a-f]{6}', result_id or ''):
            raise ValueError('Identificador de estatística inválido.')
        for folder in self._statistics_folders():
            path = folder/(result_id + '.json')
            try:
                return json.loads(path.read_text(encoding='utf-8'))
            except FileNotFoundError:
                continue
        raise ValueError('Estatística salva não encontrada.')

    def delete_saved_result(self, result_id):
        if not re.fullmatch(r'\d{8}T\d{6}Z_[0-9a-f]{6}', result_id or ''):
            raise ValueError('Identificador de estatística inválido.')
        deleted = False
        for folder in self._statistics_folders():
            path = folder/(result_id + '.json')
            try:
                path.unlink()
                deleted = True
            except FileNotFoundError:
                continue
        if not deleted:
            raise ValueError('Estatística salva não encontrada.')

    def _party_coverage(self, snapshot):
        roster_uids = set(self.meter.party_roster_uids)
        confirmed = self.meter.party_roster_seen and bool(roster_uids)
        if not confirmed:
            roster_uids = {row['uid'] for row in snapshot.get('ranking', [])}
        active_uids = {row['uid'] for row in snapshot.get('ranking', [])
                       if row.get('damage', 0) or row.get('heal', 0)}
        active_uids &= roster_uids
        names = self.meter.party_names
        return {
            'roster_confirmed': confirmed,
            'roster_count': len(roster_uids),
            'players_with_events': len(active_uids),
            'actors_observed': sum(len(self.meter.player_actors_seen.get(uid, ()))
                                   for uid in roster_uids),
            'without_events': [names.get(uid, 'Jogador') for uid in sorted(roster_uids-active_uids)],
        }

    def _player_activity(self, uid, boss_guids, timeline_origin, duration):
        buckets = {}
        if timeline_origin is not None:
            for boss_guid in boss_guids:
                target = self.meter.target_stats.get(boss_guid, {})
                player = target.get('players', {}).get(uid, {})
                for timestamp, amount in player.get('timeline', {}).items():
                    second = max(0, int(timestamp)-int(timeline_origin))
                    buckets.setdefault(second, {'damage': 0, 'healing': 0})['damage'] += amount
            for timestamp, amount in self.meter.player_healing_timeline.get(uid, {}).items():
                second = max(0, int(timestamp)-int(timeline_origin))
                buckets.setdefault(second, {'damage': 0, 'healing': 0})['healing'] += amount
        seconds = sorted(second for second, values in buckets.items()
                         if values['damage'] or values['healing'])
        longest_pause = max((right-left-1 for left, right in zip(seconds, seconds[1:])), default=0)
        window = max(1, min(10, int(duration) or 1))
        starts = seconds or [0]
        peak = max((sum(buckets.get(second+offset, {}).get('damage', 0)
                        for offset in range(window))/window for second in starts), default=0)
        return {
            'active_seconds': len(seconds),
            'longest_pause_seconds': longest_pause,
            'peak_damage_per_second_10s': round(peak, 2),
            'timeline': [{'second': second, **values}
                         for second, values in sorted(buckets.items())],
        }

    def _raid_boss_segments(self, boss_guids, timeline_origin):
        segments = []
        ordered = sorted((self.meter.target_stats.get(guid, {}) for guid in boss_guids
                          if guid in self.meter.target_stats and
                          self.meter.target_stats[guid].get('damage', 0) > 0),
                         key=lambda target: (target.get('first', 0), target.get('last', 0)))
        for index, target in enumerate(ordered, 1):
            first, last = target.get('first'), target.get('last')
            duration = max(1.0, float(last-first)) if first is not None and last is not None else 0.0
            players = []
            for uid, stats in target.get('players', {}).items():
                name = self.meter.party_names.get(uid, 'Jogador')
                damage = stats.get('damage', 0)
                players.append({
                    'name': name, 'uid': uid, 'damage': damage,
                    'dps': round(damage/duration, 2) if duration else 0,
                    'hits': stats.get('hits', 0), 'critical_hits': stats.get('critical', 0),
                    'skills': sorted(({'skill_id': skill_id, **skill}
                                      for skill_id, skill in stats.get('skills', {}).items()),
                                     key=lambda item: (-item.get('damage', 0), item['skill_id'])),
                })
            players.sort(key=lambda player: (-player['damage'], player['name']))
            segments.append({
                'label': f"{self.content_name} · alvo {index}",
                'start_second': max(0, int(first-timeline_origin))
                    if first is not None and timeline_origin is not None else 0,
                'duration': round(duration, 2),
                'hp_max_observed': target.get('hp_max', 0),
                'damage': target.get('damage', 0),
                'dps': round(target.get('damage', 0)/duration, 2) if duration else 0,
                'players': players,
            })
        return segments

    def snapshot(self):
        with self.lock:
            now = time.time()
            self._expire_results(now)
            if self.pipeline and self.running:
                try:
                    self.pipeline.check_gap(now)
                except ValueError as exc:
                    self.error = str(exc)
                    self.status = 'Erro: '+str(exc)
                    self.stop_event.set()
            at = now if self.running else (self.meter.last+IDLE_RESET_SECONDS if self.meter.last is not None else now)
            status = self.status
            if self.running and self.pipeline and not self.error:
                if self.status.startswith(('Aguardando o processo do jogo', 'Jogo encontrado; aguardando conexão ativa')):
                    status = self.status
                elif not self.pipeline.messages:
                    status = 'Captura ativa — aguardando sincronização das mensagens do jogo.'
                elif not self.pipeline.impacts:
                    status = 'Recebendo mensagens, mas nenhum impacto ainda. Acerte um inimigo para identificar seu ator.'
                elif not self.meter.selected:
                    status = 'Impactos recebidos — tentando identificar seu personagem automaticamente. Se necessário, use os controles abaixo.'
                else:
                    status = 'Dano contabilizado automaticamente.'
            meter_snapshot = copy.deepcopy(self.meter.snapshot(at))
            return {**meter_snapshot, 'party_coverage': self._party_coverage(meter_snapshot),
                    'capture_quality': self._capture_quality(),
                    'status': status, 'error': self.error,
                    'running': self.running, 'session_file': self.session_file,
                    'capture_diagnostics': {
                        'session_directory': str(self.session_log_path.parent) if self.session_log_path else None,
                        'session_log_bytes': self._file_size(self.session_log_path),
                        'protocol_log_bytes': self._file_size(self.protocol_log_path),
                        'session_records_written': self.session_records_written,
                        'protocol_records_written': self.protocol_records_written,
                    },
                    'dungeon_state': self.dungeon_state,
                    'dungeon_is_raid': self.dungeon_is_raid,
                    'dungeon_started_at': self.dungeon_started_at,
                    'dungeon_ended_at': self.dungeon_ended_at,
                    'dungeon_end_signal': self.dungeon_end_signal,
                    'dungeon_clear_signal': self.dungeon_clear_signal,
                    'last_saved_result': self.last_saved_result,
                    'auto_save_enabled': self.auto_save_enabled,
                    'self_player_name': self.self_player_name,
                    'messages': self.pipeline.messages if self.pipeline else 0,
                    'protocol_types': dict(self.pipeline.types) if self.pipeline else {},
                    'impact_messages': self.pipeline.impacts if self.pipeline else 0}

    def _capture_quality(self):
        streams = []
        if self.pipeline:
            for pipeline in self.pipeline.pipelines.values():
                streams.extend((pipeline.stream, pipeline.client_stream))
        failures = sum(stream.gap_failures for stream in streams)
        recovered = sum(stream.gap_recoveries for stream in streams)
        incomplete_reason = None
        if self.error and any(term in self.error.casefold()
                              for term in ('lacuna tcp', 'fragmentação ip', 'janela tcp excedida')):
            incomplete_reason = self.error
        return {
            'incomplete': bool(incomplete_reason),
            'incomplete_reason': incomplete_reason,
            'tcp_gaps_recovered': recovered,
            'tcp_gap_failures': failures,
            'status': 'incompleta' if incomplete_reason else 'sem lacuna não recuperada observada',
        }

    @staticmethod
    def _file_size(path):
        try:
            return path.stat().st_size if path else 0
        except OSError:
            return 0


def _create_native_window(url):
    import webview

    window = webview.create_window(
        'W99 Origin Damage Tracker', url=url, width=1180, height=760,
        min_size=(900, 620), resizable=True, background_color='#0c0b16',
        text_select=False, zoomable=False, menu=[], frameless=True,
        easy_drag=False,
    )
    return webview, window


def _set_overlay_clickthrough(window, enabled):
    if sys.platform != 'win32' or not window:
        raise RuntimeError('A janela de sobreposição ainda não está pronta.')
    deadline = time.monotonic() + 3
    while not window.native and time.monotonic() < deadline:
        time.sleep(0.05)
    if not window.native:
        raise RuntimeError('A janela de sobreposição ainda está carregando. Tente novamente.')
    hwnd = window.native.Handle.ToInt64()
    user32 = ctypes.windll.user32
    get_style = (user32.GetWindowLongPtrW if ctypes.sizeof(ctypes.c_void_p) == 8
                 else user32.GetWindowLongW)
    set_style = (user32.SetWindowLongPtrW if ctypes.sizeof(ctypes.c_void_p) == 8
                 else user32.SetWindowLongW)
    get_style.argtypes = [wintypes.HWND, ctypes.c_int]
    get_style.restype = ctypes.c_ssize_t
    set_style.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
    set_style.restype = ctypes.c_ssize_t
    exstyle = get_style(hwnd, -20)
    transparent = 0x00000020
    layered = 0x00080000
    no_activate = 0x08000000
    if enabled:
        exstyle |= transparent | layered | no_activate
    else:
        exstyle &= ~(transparent | no_activate)
    set_style(hwnd, -20, exstyle)
    updated_style = get_style(hwnd, -20)
    if bool(updated_style & transparent) != bool(enabled):
        raise RuntimeError('O Windows não aplicou a alteração de clique da sobreposição.')
    set_pos = user32.SetWindowPos
    set_pos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                        ctypes.c_int, ctypes.c_int, wintypes.UINT]
    set_pos.restype = wintypes.BOOL
    if not set_pos(hwnd, None, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020):
        raise ctypes.WinError()


def _set_overlay_opacity(window, opacity):
    if sys.platform != 'win32' or not window:
        raise RuntimeError('A sobreposição não está disponível nesta plataforma.')
    deadline = time.monotonic() + 3
    while not window.native and time.monotonic() < deadline:
        time.sleep(0.05)
    if not window.native:
        raise RuntimeError('A janela de sobreposição ainda está carregando. Tente novamente.')
    from System import Action
    native = window.native
    native.Invoke(Action(lambda: setattr(native, 'Opacity', float(opacity))))


def _is_game_foreground(overlay_window=None):
    """Return true for the game, or while the user is interacting with its overlay."""
    if sys.platform != 'win32':
        return False
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    get_foreground = user32.GetForegroundWindow
    get_foreground.restype = wintypes.HWND
    get_window_pid = user32.GetWindowThreadProcessId
    get_window_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    get_window_pid.restype = wintypes.DWORD
    hwnd = get_foreground()
    if not hwnd:
        return False
    if overlay_window is not None:
        try:
            if overlay_window.native and hwnd == overlay_window.native.Handle.ToInt64():
                return True
        except Exception:
            pass
    process_id = wintypes.DWORD()
    if not get_window_pid(hwnd, ctypes.byref(process_id)):
        return False
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    process = open_process(0x1000, False, process_id.value)
    if not process:
        return False
    try:
        query_path = kernel32.QueryFullProcessImageNameW
        query_path.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                               wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        query_path.restype = wintypes.BOOL
        path = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(path))
        if not query_path(process, 0, path, ctypes.byref(length)):
            return False
        executable = path.value[:length.value].replace('/', '\\').rsplit('\\', 1)[-1]
        return executable.casefold() == 'sevendeadlysins_origin-win64-shipping.exe'
    finally:
        kernel32.CloseHandle(process)


def _set_overlay_window_visible(window, visible):
    """Show/hide the topmost overlay without taking focus away from the game."""
    if sys.platform != 'win32' or not window:
        return False
    deadline = time.monotonic() + (1 if visible else 0)
    while not window.native and time.monotonic() < deadline:
        time.sleep(0.025)
    if not window.native:
        return False
    hwnd = window.native.Handle.ToInt64()
    user32 = ctypes.windll.user32
    show_window = user32.ShowWindow
    show_window.argtypes = [wintypes.HWND, ctypes.c_int]
    show_window.restype = wintypes.BOOL
    if visible:
        # SW_SHOWNOACTIVATE keeps the game foreground while the overlay appears.
        show_window(hwnd, 4)
        set_pos = user32.SetWindowPos
        set_pos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, wintypes.UINT]
        set_pos.restype = wintypes.BOOL
        return bool(set_pos(hwnd, wintypes.HWND(-1), 0, 0, 0, 0,
                            0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0040))
    show_window(hwnd, 0)  # SW_HIDE
    return True


def _apply_overlay_round_region(window, wait=True):
    if sys.platform != 'win32' or not window:
        return
    deadline = time.monotonic() + (3 if wait else 0)
    while not window.native and time.monotonic() < deadline:
        time.sleep(0.05)
    if not window.native:
        return
    hwnd = window.native.Handle.ToInt64()
    rect = wintypes.RECT()
    get_rect = ctypes.windll.user32.GetWindowRect
    get_rect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    get_rect.restype = wintypes.BOOL
    if not get_rect(hwnd, ctypes.byref(rect)):
        return
    width, height = rect.right-rect.left, rect.bottom-rect.top
    if width <= 0 or height <= 0:
        return
    dpi = 96
    try:
        get_dpi = ctypes.windll.user32.GetDpiForWindow
        get_dpi.argtypes = [wintypes.HWND]
        get_dpi.restype = wintypes.UINT
        dpi = get_dpi(hwnd) or dpi
    except (AttributeError, OSError):
        pass
    diameter = max(16, round(28*dpi/96))
    create_region = ctypes.windll.gdi32.CreateRoundRectRgn
    create_region.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_int]
    create_region.restype = ctypes.c_void_p
    region = create_region(0, 0, width+1, height+1, diameter, diameter)
    if not region:
        return
    set_region = ctypes.windll.user32.SetWindowRgn
    set_region.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL]
    set_region.restype = ctypes.c_int
    if not set_region(hwnd, region, True):
        ctypes.windll.gdi32.DeleteObject(region)


def server(port=8765, auto_start=False, app_window=False):
    app = App()
    token = secrets.token_urlsafe(32)
    native_window = {'window': None}
    overlay_state = {'window': None, 'visible': False, 'clickthrough': False,
                     'hover_unlocked': False, 'auto_content_visibility': False,
                     'content_suppressed': False, 'manual_hidden': False,
                     'manual_enabled': False,
                     'opacity': 0.90}
    overlay_lock = threading.RLock()
    server_thread = None

    def sync_overlay_game_visibility():
        """Keep the overlay visible only while the game's own window is foreground."""
        state = app.snapshot()
        content_state = state.get('dungeon_state')
        ended_at = state.get('dungeon_ended_at')
        with overlay_lock:
            if content_state in {'in_progress', 'clear_reported'}:
                overlay_state['content_suppressed'] = False
            elif (content_state == 'ended' and ended_at is not None and
                  time.time() >= ended_at + 20):
                overlay_state['content_suppressed'] = True

        with overlay_lock:
            current_overlay = overlay_state['window'] if overlay_state['visible'] else None
        game_foreground = _is_game_foreground(current_overlay)
        with overlay_lock:
            overlay = overlay_state['window']
            should_show = (overlay is not None and
                           ((overlay_state['auto_content_visibility'] and
                             not overlay_state['manual_hidden'] and
                             not overlay_state['content_suppressed']) or
                            overlay_state['manual_enabled']) and
                           game_foreground)
            if should_show == overlay_state['visible']:
                return
            try:
                if should_show:
                    if _set_overlay_window_visible(overlay, True):
                        overlay_state['visible'] = True
                else:
                    if overlay_state['clickthrough'] and overlay_state['hover_unlocked']:
                        _set_overlay_clickthrough(overlay, True)
                    overlay_state['hover_unlocked'] = False
                    if _set_overlay_window_visible(overlay, False):
                        overlay_state['visible'] = False
            except Exception:
                pass

    def overlay_game_focus_loop():
        while True:
            sync_overlay_game_visibility()
            time.sleep(0.30)

    def ensure_overlay_window():
        with overlay_lock:
            if overlay_state['window'] is not None:
                return overlay_state['window']
            if native_window.get('webview') is None:
                raise RuntimeError('A janela principal ainda está inicializando.')
            screen_width = ctypes.windll.user32.GetSystemMetrics(0) if sys.platform == 'win32' else 1024
            overlay = native_window['webview'].create_window(
                'W99 Origin Damage Tracker — Sobreposição',
                url=f'http://127.0.0.1:{port}/overlay',
                width=370, height=200, x=max(12, screen_width - 390), y=56,
                min_size=(300, 150), resizable=True,
                frameless=True, easy_drag=False, transparent=False,
                on_top=True, focus=False, hidden=True, shadow=False,
                background_color='#0c0b16', text_select=False,
                zoomable=False,
            )
            overlay_state['window'] = overlay
            _set_overlay_opacity(overlay, overlay_state['opacity'])
            _apply_overlay_round_region(overlay)

            def refresh_overlay_region(width=None, height=None):
                _apply_overlay_round_region(overlay_state['window'], wait=False)

            overlay.events.resized += refresh_overlay_region
            overlay_state['clickthrough'] = False
            overlay_state['hover_unlocked'] = False
            overlay_state['visible'] = False
            return overlay

    def overlay_unlock_hotkey():
        """Keep a global recovery shortcut available while pass-through is on."""
        if sys.platform != 'win32':
            return
        user32 = ctypes.windll.user32
        hotkey_id = 0x7D50
        mod_control, mod_shift, mod_norepeat = 0x0002, 0x0004, 0x4000
        vk_f10, wm_hotkey = 0x79, 0x0312
        register = user32.RegisterHotKey
        register.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
        register.restype = wintypes.BOOL
        if not register(None, hotkey_id, mod_control | mod_shift | mod_norepeat, vk_f10):
            return
        message = wintypes.MSG()
        get_message = user32.GetMessageW
        get_message.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                wintypes.UINT, wintypes.UINT]
        get_message.restype = ctypes.c_int
        try:
            while get_message(ctypes.byref(message), None, 0, 0) > 0:
                if message.message != wm_hotkey:
                    continue
                with overlay_lock:
                    overlay = overlay_state['window']
                    if (overlay is None or not overlay_state['visible'] or
                            not overlay_state['clickthrough']):
                        continue
                    try:
                        _set_overlay_clickthrough(overlay, False)
                        overlay_state['clickthrough'] = False
                        overlay_state['hover_unlocked'] = False
                    except Exception:
                        # Keep the shortcut listener alive so another press
                        # can retry if Windows temporarily rejects the update.
                        pass
        finally:
            user32.UnregisterHotKey(None, hotkey_id)

    def overlay_unlock_hover():
        """Restore overlay interaction when the cursor enters its lock hotspot."""
        if sys.platform != 'win32':
            return
        user32 = ctypes.windll.user32
        cursor = wintypes.POINT()
        rect = wintypes.RECT()
        get_cursor_pos = user32.GetCursorPos
        get_cursor_pos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        get_cursor_pos.restype = wintypes.BOOL
        get_window_rect = user32.GetWindowRect
        get_window_rect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        get_window_rect.restype = wintypes.BOOL
        was_in_lock_zone = False
        while True:
            with overlay_lock:
                overlay = overlay_state['window']
                visible = overlay_state['visible']
                clickthrough = overlay_state['clickthrough']
                hover_unlocked = overlay_state['hover_unlocked']
            in_lock_zone = False
            hwnd = None
            if visible and overlay is not None and overlay.native:
                try:
                    hwnd = overlay.native.Handle.ToInt64()
                    if get_window_rect(hwnd, ctypes.byref(rect)) and get_cursor_pos(ctypes.byref(cursor)):
                        # Lock icon sits beside the close button in the title bar.
                        in_lock_zone = (
                            rect.right - 76 <= cursor.x <= rect.right - 25 and
                            rect.top <= cursor.y <= rect.top + 42
                        )
                except Exception:
                    in_lock_zone = False
            if clickthrough and in_lock_zone and not was_in_lock_zone:
                with overlay_lock:
                    if (overlay_state['window'] is overlay and
                            overlay_state['visible'] and overlay_state['clickthrough'] and
                            not overlay_state['hover_unlocked']):
                        try:
                            _set_overlay_clickthrough(overlay, False)
                            overlay_state['hover_unlocked'] = True
                        except Exception:
                            pass
            elif clickthrough and hover_unlocked and not in_lock_zone:
                with overlay_lock:
                    if (overlay_state['window'] is overlay and
                            overlay_state['visible'] and overlay_state['clickthrough'] and
                            overlay_state['hover_unlocked']):
                        try:
                            _set_overlay_clickthrough(overlay, True)
                            overlay_state['hover_unlocked'] = False
                        except Exception:
                            pass
            was_in_lock_zone = in_lock_zone if visible else False
            time.sleep(0.05)

    if sys.platform == 'win32':
        threading.Thread(target=overlay_game_focus_loop, daemon=True,
                         name='overlay-game-focus').start()
        threading.Thread(target=overlay_unlock_hotkey, daemon=True,
                         name='overlay-unlock-hotkey').start()
        threading.Thread(target=overlay_unlock_hover, daemon=True,
                         name='overlay-unlock-hover').start()

    def close_overlay_with_main():
        with overlay_lock:
            overlay = overlay_state['window']
            overlay_state['window'] = None
            overlay_state['visible'] = False
            overlay_state['clickthrough'] = False
            overlay_state['hover_unlocked'] = False
            overlay_state['auto_content_visibility'] = False
            overlay_state['content_suppressed'] = False
            overlay_state['manual_hidden'] = False
            overlay_state['manual_enabled'] = False
            if overlay is not None:
                threading.Thread(target=overlay.destroy, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body, status=200, mime='application/json; charset=utf-8'):
            data = body if isinstance(body, bytes) else body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.headers.get('Host') != f'127.0.0.1:{port}':
                self.reply('{}', 403)
                return
            if self.path == '/':
                html = (ASSETS/'dps_live.html').read_text(encoding='utf-8').replace('__TOKEN__', token)
                self.reply(html, mime='text/html; charset=utf-8')
            elif self.path == '/overlay':
                html = (ASSETS/'dps_overlay.html').read_text(encoding='utf-8').replace('__TOKEN__', token)
                self.reply(html, mime='text/html; charset=utf-8')
            elif self.path.startswith('/assets/characters/'):
                filename = self.path.rsplit('/', 1)[-1]
                if not re.fullmatch(r'[a-z0-9_-]+\.(?:png|webp)', filename):
                    self.reply('{}', 404)
                    return
                try:
                    image = (ASSETS/'assets'/'characters'/filename).read_bytes()
                except OSError:
                    self.reply('{}', 404)
                    return
                mime = 'image/webp' if filename.endswith('.webp') else 'image/png'
                self.reply(image, mime=mime)
            elif self.path == '/api/state':
                state = app.snapshot()
                sync_overlay_game_visibility()
                with overlay_lock:
                    state['overlay_visible'] = overlay_state['visible']
                    state['overlay_auto_enabled'] = overlay_state['auto_content_visibility']
                    state['overlay_manual_hidden'] = overlay_state['manual_hidden']
                    state['overlay_manual_enabled'] = overlay_state['manual_enabled']
                    state['overlay_clickthrough'] = overlay_state['clickthrough']
                    state['overlay_opacity'] = overlay_state['opacity']
                self.reply(json.dumps(state, ensure_ascii=False))
            elif self.path == '/api/saved':
                with app.lock:
                    self.reply(json.dumps(app.saved_results(), ensure_ascii=False))
            elif self.path.startswith('/api/saved/'):
                result_id = self.path.removeprefix('/api/saved/')
                with app.lock:
                    self.reply(json.dumps(app.load_saved_result(result_id), ensure_ascii=False))
            else:
                self.reply('{}', 404)

        def do_POST(self):
            if self.headers.get('Host') != f'127.0.0.1:{port}' or self.headers.get('X-DPS-Token') != token:
                self.reply('{}', 403)
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 <= size <= 4096:
                    raise ValueError('Requisição muito grande')
                data = json.loads(self.rfile.read(size) or b'{}')
                if self.path == '/api/overlay/drag':
                    with overlay_lock:
                        overlay = overlay_state['window']
                        if overlay is None or not overlay_state['visible']:
                            raise ValueError('A sobreposição não está aberta.')
                        if overlay_state['clickthrough']:
                            raise ValueError('Desative o clique pass-through antes de mover a sobreposição.')
                        if sys.platform != 'win32' or not overlay.native:
                            raise RuntimeError('A movimentação nativa só está disponível no Windows.')
                    from System import Func, Type
                    def begin_overlay_drag():
                        hwnd = overlay.native.Handle.ToInt64()
                        user32 = ctypes.windll.user32
                        user32.ReleaseCapture()
                        cursor = wintypes.POINT()
                        get_cursor_pos = user32.GetCursorPos
                        get_cursor_pos.argtypes = [ctypes.POINTER(wintypes.POINT)]
                        get_cursor_pos.restype = wintypes.BOOL
                        if not get_cursor_pos(ctypes.byref(cursor)):
                            raise OSError('Não foi possível ler a posição do cursor.')
                        packed_point = ((cursor.y & 0xFFFF) << 16) | (cursor.x & 0xFFFF)
                        if packed_point & 0x80000000:
                            packed_point -= 0x100000000
                        send_message = user32.SendMessageW
                        send_message.argtypes = [wintypes.HWND, wintypes.UINT,
                                                 ctypes.c_size_t, ctypes.c_ssize_t]
                        send_message.restype = ctypes.c_ssize_t
                        send_message(hwnd, 0x00A1, 2, packed_point)
                    overlay.native.Invoke(Func[Type](begin_overlay_drag))
                    self.reply(json.dumps({'ok': True}))
                    return
                if self.path == '/api/window/drag':
                    main_window = native_window['window']
                    if main_window is None or not main_window.native:
                        raise RuntimeError('A janela principal ainda está carregando.')
                    from System import Func, Type
                    def begin_drag():
                        hwnd = main_window.native.Handle.ToInt64()
                        user32 = ctypes.windll.user32
                        user32.ReleaseCapture()
                        cursor = wintypes.POINT()
                        get_cursor_pos = user32.GetCursorPos
                        get_cursor_pos.argtypes = [ctypes.POINTER(wintypes.POINT)]
                        get_cursor_pos.restype = wintypes.BOOL
                        if not get_cursor_pos(ctypes.byref(cursor)):
                            raise OSError('Não foi possível ler a posição do cursor.')
                        packed_point = ((cursor.y & 0xFFFF) << 16) | (cursor.x & 0xFFFF)
                        if packed_point & 0x80000000:
                            packed_point -= 0x100000000
                        send_message = user32.SendMessageW
                        send_message.argtypes = [wintypes.HWND, wintypes.UINT,
                                                 ctypes.c_size_t, ctypes.c_ssize_t]
                        send_message.restype = ctypes.c_ssize_t
                        send_message(hwnd, 0x00A1, 2, packed_point)
                    main_window.native.Invoke(Func[Type](begin_drag))
                    self.reply(json.dumps({'ok': True}))
                    return
                if self.path == '/api/window/minimize':
                    main_window = native_window['window']
                    if main_window is None:
                        raise RuntimeError('A janela principal ainda está carregando.')
                    main_window.minimize()
                    self.reply(json.dumps({'ok': True}))
                    return
                if self.path == '/api/window/toggle-maximize':
                    main_window = native_window['window']
                    if main_window is None or not main_window.native:
                        raise RuntimeError('A janela principal ainda está carregando.')
                    if str(main_window.native.WindowState).endswith('Maximized'):
                        main_window.restore()
                        maximized = False
                    else:
                        main_window.maximize()
                        maximized = True
                    self.reply(json.dumps({'ok': True, 'maximized': maximized}))
                    return
                with app.lock:
                    if self.path == '/api/start':
                        app.start()
                    elif self.path == '/api/stop':
                        app.stop_event.set()
                        app.status = 'Encerrando captura…'
                    elif self.path == '/api/quit':
                        app.stop_event.set()
                        app.status = 'Encerrando DPS Meter…'
                        threading.Timer(0.3, http.shutdown).start()
                        overlay = overlay_state['window']
                        overlay_state['window'] = None
                        overlay_state['visible'] = False
                        overlay_state['clickthrough'] = False
                        overlay_state['hover_unlocked'] = False
                        overlay_state['auto_content_visibility'] = False
                        overlay_state['manual_hidden'] = False
                        overlay_state['manual_enabled'] = False
                        if overlay is not None:
                            threading.Timer(0.3, overlay.destroy).start()
                        if native_window['window'] is not None:
                            threading.Timer(0.3, native_window['window'].destroy).start()
                    elif self.path == '/api/overlay/open':
                        ensure_overlay_window()
                        with overlay_lock:
                            overlay_state['auto_content_visibility'] = True
                            overlay_state['content_suppressed'] = False
                            overlay_state['manual_hidden'] = False
                            overlay_state['manual_enabled'] = False
                        sync_overlay_game_visibility()
                    elif self.path == '/api/overlay/close':
                        with overlay_lock:
                            if overlay_state['window'] is not None:
                                _set_overlay_clickthrough(overlay_state['window'], False)
                                overlay_state['clickthrough'] = False
                                overlay_state['hover_unlocked'] = False
                                _set_overlay_window_visible(overlay_state['window'], False)
                            overlay_state['visible'] = False
                            overlay_state['auto_content_visibility'] = False
                            overlay_state['content_suppressed'] = False
                            overlay_state['manual_hidden'] = False
                            overlay_state['manual_enabled'] = False
                    elif self.path == '/api/overlay/manual':
                        enabled = bool(data.get('enabled'))
                        ensure_overlay_window()
                        with overlay_lock:
                            overlay = overlay_state['window']
                            if overlay_state['auto_content_visibility']:
                                # Manual hide/show overrides the automatic mode until reactivated.
                                overlay_state['manual_hidden'] = not enabled
                                overlay_state['manual_enabled'] = False
                            else:
                                overlay_state['manual_hidden'] = False
                                overlay_state['manual_enabled'] = enabled
                            if not enabled and overlay_state['visible']:
                                if overlay_state['clickthrough'] and overlay_state['hover_unlocked']:
                                    _set_overlay_clickthrough(overlay, True)
                                overlay_state['hover_unlocked'] = False
                                _set_overlay_window_visible(overlay, False)
                                overlay_state['visible'] = False
                        sync_overlay_game_visibility()
                    elif self.path == '/api/overlay/clickthrough':
                        if overlay_state['window'] is None or not overlay_state['visible']:
                            raise ValueError('Abra a sobreposição antes de alterar o modo de clique.')
                        enabled = bool(data.get('enabled'))
                        with overlay_lock:
                            _set_overlay_clickthrough(overlay_state['window'], enabled)
                            overlay_state['clickthrough'] = enabled
                            overlay_state['hover_unlocked'] = False
                    elif self.path == '/api/overlay/opacity':
                        opacity = float(data.get('opacity', overlay_state['opacity']))
                        if not 0.40 <= opacity <= 1.0:
                            raise ValueError('A transparência deve ficar entre 40% e 100%.')
                        with overlay_lock:
                            overlay_state['opacity'] = opacity
                            if overlay_state['window'] is not None:
                                _set_overlay_opacity(overlay_state['window'], opacity)
                    elif self.path == '/api/overlay/resize':
                        if overlay_state['window'] is None or not overlay_state['visible']:
                            raise ValueError('A sobreposição não está aberta.')
                        height = int(data.get('height', 0))
                        if not 150 <= height <= 450:
                            raise ValueError('Altura da sobreposição inválida.')
                        overlay_state['window'].resize(370, height)
                        _apply_overlay_round_region(overlay_state['window'])
                    elif self.path == '/api/self-player':
                        name = data.get('name', '')
                        if not isinstance(name, str) or len(name.strip()) > 40:
                            raise ValueError('Nick inválido.')
                        app.self_player_name = name.strip()
                        app.meter.set_self_player_name(app.self_player_name)
                        settings_path = ROOT/'dps_meter_settings.json'
                        temp_path = settings_path.with_suffix('.tmp')
                        temp_path.write_text(json.dumps(
                            {'self_player_name': app.self_player_name,
                             'auto_save_results': app.auto_save_enabled}, ensure_ascii=False, indent=2
                        ), encoding='utf-8')
                        temp_path.replace(settings_path)
                    elif self.path == '/api/settings/autosave':
                        app.auto_save_enabled = bool(data.get('enabled'))
                        settings_path = ROOT/'dps_meter_settings.json'
                        temp_path = settings_path.with_suffix('.tmp')
                        temp_path.write_text(json.dumps(
                            {'self_player_name': app.self_player_name,
                             'auto_save_results': app.auto_save_enabled}, ensure_ascii=False, indent=2
                        ), encoding='utf-8')
                        temp_path.replace(settings_path)
                    elif self.path == '/api/select':
                        app.meter.select(data.get('actor'))
                    elif self.path == '/api/members':
                        app.meter.configure(data.get('members'))
                    elif self.path == '/api/reset':
                        app.meter.reset()
                    elif self.path == '/api/marker':
                        label = data.get('label', '')
                        if not isinstance(label, str) or len(label.strip()) > 40:
                            raise ValueError('O nome da marcação deve ter até 40 caracteres.')
                        if app.meter.start is None and not app.meter.healing_timeline:
                            raise ValueError('Aguarde o início do combate para marcar uma fase.')
                        app.meter.add_combat_marker(label, time.time())
                    elif self.path == '/api/save':
                        app.last_saved_result = app._save_result(time.time())
                        if app.dungeon_state == 'ended':
                            app.auto_save_pending = False
                    elif self.path == '/api/saved/delete':
                        app.delete_saved_result(data.get('id'))
                    else:
                        self.reply('{}', 404)
                        return
                self.reply(json.dumps({'ok': True, 'enabled': app.auto_save_enabled}))
            except (ValueError, TypeError, AttributeError, OSError, RuntimeError) as exc:
                self.reply(json.dumps({'error': str(exc)}), 400)
    http = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    http.daemon_threads = True
    if auto_start:
        app.start()
    try:
        if sys.stdout is not None:
            print(f'DPS Meter: http://127.0.0.1:{port}', flush=True)
        if app_window:
            server_thread = threading.Thread(target=http.serve_forever, daemon=True)
            server_thread.start()
            threading.Event().wait(1)
            webview, native_window['window'] = _create_native_window(f'http://127.0.0.1:{port}')
            native_window['webview'] = webview
            native_window['window'].events.closing += close_overlay_with_main
            webview.start(gui='edgechromium', debug=False, menu=[],
                          icon=str(ASSETS/'assets'/'7ds_dps_meter.ico'))
            http.shutdown()
            server_thread.join()
        else:
            http.serve_forever()
    finally:
        app.stop_event.set()
        close_overlay_with_main()
        if server_thread and server_thread.is_alive():
            http.shutdown()
            server_thread.join(timeout=5)
        if app.thread:
            app.thread.join(timeout=5)
        http.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    server(parser.parse_args().port)

