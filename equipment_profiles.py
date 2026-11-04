"""Passive extraction of public equipment fields from other-player profile replies."""
import re


_WIDE_TEXT = re.compile(r'[A-Za-z][A-Za-z0-9_]{4,}')
_EQUIP_SET = re.compile(r'^epeq_([a-z][a-z0-9]*)_([a-z0-9]+)$', re.I)
_PARTY_EQUIP_MARKER = re.compile(r'^epeq_([a-z][a-z0-9]*)_([a-z0-9]+)_lv(\d+)$', re.I)
_ARMOR = re.compile(r'^random_armor_t(\d+)_type([a-z]+)_(\d+)$', re.I)
_ACCESSORY = {
    'earring': 'Brinco',
    'necklace': 'Colar',
    'ring': 'Anel',
    'special': 'Especial',
}
_CHARACTER_NAMES = {
    'ban': 'Ban',
    'king': 'King',
    'diane': 'Diane',
    'meliodas': 'Meliodas',
    'gowther': 'Gowther',
    'elaine': 'Elaine',
    'lancelot': 'Lancelot',
    'calla': 'Calla',
    'estia': 'Estia',
    'merlin': 'Merlin',
    'klotho': 'Klotho',
    'jericho': 'Jericho',
    'thorin': 'Thorin',
    'daisy': 'Daisy',
    'elizabeth': 'Elizabeth',
    'howzer': 'Howzer',
    'manny': 'Manny',
    'hawk': 'Hawk',
    'aragon': 'Aragon',
}


def decode_party_member_equipment_markers(body):
    """Read per-player epeq markers embedded in P2C_ReportPartyData (10140).

    These markers identify a hero/equipment record family, not individual gear
    item IDs or stat rolls. They are kept separate from a full 10284 profile.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) < 24:
        return []

    members = []
    for pos in range(len(body) - 18):
        if body[pos + 8:pos + 13] != bytes.fromhex('00000004a8'):
            continue
        name_size = int.from_bytes(body[pos + 16:pos + 18], 'big')
        if (name_size < 2 or name_size > 80 or name_size % 2 or
                pos + 18 + name_size > len(body)):
            continue
        try:
            name = body[pos + 18:pos + 18 + name_size].decode('utf-16le').rstrip('\0').strip()
        except UnicodeError:
            continue
        if (not name or len(name) > 40 or any(ord(ch) < 32 for ch in name) or
                not any(ch.isalnum() for ch in name)):
            continue
        uid = str(int.from_bytes(body[pos:pos + 8], 'big'))
        if not any(member['player_uid'] == uid for member in members):
            members.append({'player_uid': uid, 'name': name, '_offset': pos})

    # Decode both UTF-16 byte alignments because PartyData interleaves strings
    # with binary values, so a string can begin at an odd byte offset.
    markers = {}
    for alignment in (0, 1):
        text = body[alignment:].decode('utf-16le', errors='ignore')
        for match in _WIDE_TEXT.finditer(text):
            parsed = _PARTY_EQUIP_MARKER.fullmatch(match.group())
            if not parsed:
                continue
            offset = alignment + match.start() * 2
            markers[offset] = match.group()

    for index, member in enumerate(members):
        end = members[index + 1]['_offset'] if index + 1 < len(members) else len(body)
        characters = []
        seen = set()
        for offset, marker in sorted(markers.items()):
            if not member['_offset'] <= offset < end or marker in seen:
                continue
            seen.add(marker)
            match = _PARTY_EQUIP_MARKER.fullmatch(marker)
            character_key, variant, level = match.groups()
            characters.append({
                'character': _CHARACTER_NAMES.get(character_key.lower(), character_key.title()),
                'character_key': character_key.lower(),
                'marker': marker,
                'variant': variant.upper(),
                'level': int(level),
            })
        member.pop('_offset')
        member['characters'] = characters
    return members


def decode_party_hero_equipment_update(body):
    """Read the UID and item identifiers in a P2C_ReportChangeCurHero (10221).

    The packet identifies the player and carries some readable item IDs, but
    the character name is not readable in this payload. The caller must link it
    to a nearby hit from that UID before presenting a character association.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) < 16:
        return None
    uid_bytes = body[:8]
    if uid_bytes[0] != 0x27 or uid_bytes[2] != 0x37:
        return None
    uid = str(int.from_bytes(uid_bytes, 'big'))

    tokens = {}
    for alignment in (0, 1):
        text = body[alignment:].decode('utf-16le', errors='ignore')
        for match in _WIDE_TEXT.finditer(text):
            value = match.group()
            if (value.startswith('random_armor_') or
                    value.startswith(('random_earring_', 'random_necklace_',
                                      'random_ring_', 'random_special_'))):
                tokens[alignment + match.start() * 2] = value

    equipment = []
    armor_count = 0
    accessory_count = {}
    seen = set()
    for _, item_id in sorted(tokens.items()):
        if item_id in seen:
            continue
        seen.add(item_id)
        armor_match = _ARMOR.fullmatch(item_id)
        if armor_match:
            armor_count += 1
            slot = f'Armadura · peça {armor_count}'
        else:
            kind_match = re.match(r'^random_(earring|necklace|ring|special)_', item_id, re.I)
            if not kind_match:
                continue
            kind = kind_match.group(1).lower()
            accessory_count[kind] = accessory_count.get(kind, 0) + 1
            slot = _ACCESSORY.get(kind, 'Especial')
            if accessory_count[kind] > 1:
                slot += f' · peça {accessory_count[kind]}'
        equipment.append({'slot': slot, 'item_id': item_id,
                          'label': _item_label(item_id, slot)})

    return {
        'player_uid': uid,
        'hero_code': int.from_bytes(body[16:18], 'big') if len(body) >= 18 else None,
        'hero_entity_key': body[8:16].hex(),
        'equipment': equipment,
    }


def _item_label(item_id, slot):
    match = _ARMOR.fullmatch(item_id)
    if match:
        tier, kind, number = match.groups()
        slot_name = 'Armadura' if slot.startswith('Armadura') else slot
        return f'{slot_name} T{tier} · tipo {kind.upper()} · #{number}'
    match = re.fullmatch(r'random_(earring|necklace|ring)_t(\d+)_type([a-z]+)_(\d+)', item_id, re.I)
    if match:
        kind, tier, variant, number = match.groups()
        return f"{_ACCESSORY[kind.lower()]} T{tier} · tipo {variant.upper()} · #{number}"
    match = re.fullmatch(r'random_special_t(\d+)_boss_([a-z0-9]+)_(\d+)', item_id, re.I)
    if match:
        tier, boss, number = match.groups()
        return f'Especial T{tier} · {boss.title()} · #{number}'
    return item_id.replace('_', ' ').strip().capitalize()


def decode_other_player_profile(body):
    """Decode the name and candidate gear sets from one 10284 response body.

    The body is already decrypted by the protocol table. This deliberately
    returns equipment item IDs rather than inventing localized names or stats.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) < 12:
        return None

    result_code = int.from_bytes(body[:4], 'big', signed=True)
    profile_key = body[4:8].hex()
    name_size = int.from_bytes(body[8:10], 'big')
    if (name_size < 2 or name_size > 160 or name_size % 2 or
            10 + name_size > len(body)):
        return None
    try:
        name = body[10:10+name_size].decode('utf-16le').rstrip('\0').strip()
    except UnicodeError:
        return None
    if not name or len(name) > 40 or any(ord(ch) < 32 for ch in name):
        return None

    text = body.decode('utf-16le', errors='ignore')
    tokens = [(match.start()*2, match.group()) for match in _WIDE_TEXT.finditer(text)]
    set_markers = [(offset, value) for offset, value in tokens
                   if _EQUIP_SET.fullmatch(value)]
    characters = []
    for index, (marker_offset, marker) in enumerate(set_markers):
        start_offset = set_markers[index-1][0] if index else max(0, marker_offset-512)
        next_offset = (set_markers[index+1][0] if index+1 < len(set_markers)
                       else min(len(body), marker_offset+1024))

        armor_ids = [value for offset, value in tokens
                     if start_offset < offset < marker_offset and
                     _ARMOR.fullmatch(value)]
        armor_ids = armor_ids[-3:]

        accessory_ids = {}
        for offset, value in tokens:
            if not marker_offset < offset < next_offset:
                continue
            match = re.match(r'^random_(earring|necklace|ring|special)_', value, re.I)
            if match:
                accessory_ids.setdefault(match.group(1).lower(), value)

        equipment = []
        for slot_index, item_id in enumerate(armor_ids, 1):
            equipment.append({'slot': f'Armadura · peça {slot_index}',
                              'item_id': item_id,
                              'label': _item_label(item_id, f'Armadura · peça {slot_index}')})
        for kind in ('earring', 'necklace', 'ring', 'special'):
            item_id = accessory_ids.get(kind)
            if item_id:
                slot = _ACCESSORY[kind]
                equipment.append({'slot': slot, 'item_id': item_id,
                                  'label': _item_label(item_id, slot)})

        if not equipment:
            continue
        match = _EQUIP_SET.fullmatch(marker)
        character_key = match.group(1).lower() if match else 'unknown'
        variant = match.group(2).upper() if match else ''
        character_name = _CHARACTER_NAMES.get(character_key, character_key.title())
        characters.append({
            'character': character_name,
            'character_key': character_key,
            'set_id': marker,
            'set_name': f'Conjunto {character_name} · variante {variant}' if variant else marker,
            'equipment': equipment,
        })

    return {
        'profile_key': profile_key,
        'result_code': result_code,
        'name': name,
        'characters': characters,
        'captured_at': None,
    }

