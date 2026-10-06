import json
import os
from dataclasses import dataclass, asdict

CONFIG_FILE = "config.json"

@dataclass
class AppConfig:
    # Сетевые параметры
    host: str = "192.168.0.221"
    port: int = 502
    unit_id: int = 255
    timeout: float = 2.0
    poll_interval_ms: int = 200
    auto_reconnect: bool = True

    # Регистры Modbus
    write_reg_address: int = 0      # %MW0
    read_reg_address: int = 1       # %MW1
    
    # Режимы записи
    cyclic_write: bool = False
    write_on_change: bool = True
    last_write_value: int = 0

    @classmethod
    def load(cls, file_path: str = CONFIG_FILE) -> "AppConfig":
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except Exception:
                pass
        return cls()

    def save(self, file_path: str = CONFIG_FILE) -> None:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving config: {e}")
