"""Daily API input/decision log; timestamps use the application's Kyiv timezone."""
from datetime import datetime
import json
from pathlib import Path
import threading
from src.archive_replay import KYIV_ARCHIVE


class MainAPIDebugLogger:
    def __init__(self, directory='logs'):
        self.directory=Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        self._lock=threading.Lock()

    def write(self, record):
        now=datetime.now(KYIV_ARCHIVE)
        path=self.directory/f'main_api_debug_{now:%Y-%m-%d}.jsonl'
        entry=dict(timestamp=now.isoformat(timespec='milliseconds'),**record)
        line=json.dumps(entry,ensure_ascii=False,default=str)
        with self._lock:
            with path.open('a',encoding='utf-8') as stream:
                stream.write(line+'\n')
        return str(path.resolve())
