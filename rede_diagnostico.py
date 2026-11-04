"""Inventário de rede e estado do PktMon, sem captura de pacotes."""
import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from app_paths import APP_DIR

OUT = APP_DIR / 'analise_rede'


def run(*args):
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
    p = subprocess.run(args, capture_output=True, timeout=30, creationflags=flags)
    def decode(value):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('cp1252', errors='replace')
    return {'returncode': p.returncode, 'stdout': decode(p.stdout), 'stderr': decode(p.stderr)}


def main():
    OUT.mkdir(exist_ok=True)
    tasks = run('tasklist', '/fo', 'csv', '/nh')
    matches = [row for row in csv.reader(tasks['stdout'].splitlines()) if row and row[0].lower() == 'sevendeadlysins_origin-win64-shipping.exe']
    if len(matches) != 1:
        raise RuntimeError('Processo do jogo ausente ou nao unico')
    pid = int(matches[0][1])
    raw = run('netstat', '-ano')
    sockets = []
    for line in raw['stdout'].splitlines():
        fields = line.split()
        if fields and fields[-1] == str(pid):
            sockets.append(fields)
    report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'pid': pid, 'sockets': sockets,
              'pktmon_status': run('pktmon', 'status'), 'pktmon_filters': run('pktmon', 'filter', 'list')}
    (OUT / 'inventario.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

