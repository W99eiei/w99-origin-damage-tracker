"""Standalone Windows entry point for W99 Origin Damage Tracker."""
import ctypes
import traceback
from pathlib import Path

from app_paths import APP_DIR
from dps_live_server import server


def main():
    try:
        server(port=8765, auto_start=True, app_window=True)
    except Exception as exc:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        log_path = APP_DIR/'dps_meter_error.log'
        log_path.write_text(traceback.format_exc(), encoding='utf-8')
        message = f'Não foi possível iniciar o W99 Origin Damage Tracker.\n\n{exc}\n\nDetalhes: {log_path}'
        ctypes.windll.user32.MessageBoxW(None, message, 'W99 Origin Damage Tracker', 0x10)


if __name__ == '__main__':
    main()

