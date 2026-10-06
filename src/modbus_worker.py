import time
import threading
import queue
from typing import Optional, Callable
from pymodbus.client import ModbusTcpClient
from src.config import AppConfig

class ModbusWorker:
    """
    Фоновый рабочий поток для циклического обмена Modbus TCP с ПЛК TM221.
    Позволяет непрерывно читать %MW регистр и записывать %MW регистр.
    """
    def __init__(self, config: AppConfig, event_queue: queue.Queue):
        self.config = config
        self.event_queue = event_queue
        
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._write_queue = queue.Queue()
        self._connected = False
        
        # Статистика
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.last_latency_ms = 0.0

        # Текущее значение для циклической записи
        self.current_write_val: int = config.last_write_value
        self.cyclic_write_enabled: bool = config.cyclic_write

    def start(self):
        """Запуск фонового потока соединения и обмена."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="ModbusWorkerThread", daemon=True)
        self._thread.start()

    def stop(self):
        """Остановка потока и отключение."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def queue_write(self, value: int, address: Optional[int] = None):
        """Поместить запрос на разовую/немедленную запись в очередь."""
        target_addr = address if address is not None else self.config.write_reg_address
        self.current_write_val = value & 0xFFFF
        self._write_queue.put((target_addr, self.current_write_val))

    def set_cyclic_write(self, enabled: bool, value: Optional[int] = None):
        """Включить/выключить циклическую запись каждого цикла."""
        self.cyclic_write_enabled = enabled
        if value is not None:
            self.current_write_val = value & 0xFFFF

    def _post_event(self, event_type: str, data: dict):
        self.event_queue.put({"type": event_type, "data": data, "timestamp": time.time()})

    def _run_loop(self):
        client = None
        reconnect_delay = 1.0

        self._post_event("status", {"state": "connecting", "message": f"Подключение к {self.config.host}:{self.config.port}..."})

        while not self._stop_event.is_set():
            # Попытка подключения
            try:
                client = ModbusTcpClient(
                    host=self.config.host,
                    port=self.config.port,
                    timeout=self.config.timeout
                )
                connected = client.connect()
            except Exception as e:
                connected = False
                err_msg = f"Ошибка сокета: {e}"

            if not connected:
                self._connected = False
                self.failed_requests += 1
                self._post_event("status", {
                    "state": "error",
                    "message": f"Не удалось подключиться к {self.config.host}:{self.config.port}"
                })
                
                if not self.config.auto_reconnect or self._stop_event.is_set():
                    break
                
                # Ждем перед повторной попыткой
                for _ in range(int(reconnect_delay * 10)):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.1)
                continue

            # Успешно подключено
            self._connected = True
            self._post_event("status", {
                "state": "connected",
                "message": f"Связь установлена с {self.config.host}:{self.config.port}"
            })

            # Рабочий цикл обмена
            while not self._stop_event.is_set():
                cycle_start = time.perf_counter()
                cycle_success = True

                # 1. Запись по очереди (ручная отправка или по изменению)
                pending_writes = []
                while not self._write_queue.empty():
                    try:
                        pending_writes.append(self._write_queue.get_nowait())
                    except queue.Empty:
                        break

                # Если есть команды из очереди - записываем их
                for w_addr, w_val in pending_writes:
                    t0 = time.perf_counter()
                    self.total_requests += 1
                    try:
                        res = client.write_register(
                            address=w_addr,
                            value=w_val & 0xFFFF,
                            device_id=self.config.unit_id
                        )
                        dt = (time.perf_counter() - t0) * 1000
                        if res is None or res.isError():
                            self.failed_requests += 1
                            cycle_success = False
                            err = str(res) if res else "Таймаут записи"
                            self._post_event("error", {"op": "write", "msg": f"Ошибка записи %MW{w_addr}: {err}"})
                        else:
                            self.successful_requests += 1
                            self.last_latency_ms = dt
                            self._post_event("write_ok", {
                                "address": w_addr,
                                "value": w_val & 0xFFFF,
                                "latency_ms": dt
                            })
                    except Exception as e:
                        self.failed_requests += 1
                        cycle_success = False
                        self._post_event("error", {"op": "write", "msg": f"Исключение при записи %MW{w_addr}: {e}"})

                # Если включена циклическая запись и очереди не было, пишем текущее значение
                if not pending_writes and self.cyclic_write_enabled:
                    t0 = time.perf_counter()
                    self.total_requests += 1
                    try:
                        res = client.write_register(
                            address=self.config.write_reg_address,
                            value=self.current_write_val & 0xFFFF,
                            device_id=self.config.unit_id
                        )
                        dt = (time.perf_counter() - t0) * 1000
                        if res is None or res.isError():
                            self.failed_requests += 1
                            cycle_success = False
                            err = str(res) if res else "Таймаут циклической записи"
                            self._post_event("error", {"op": "write", "msg": f"Ошибка циклический записи %MW{self.config.write_reg_address}: {err}"})
                        else:
                            self.successful_requests += 1
                            self.last_latency_ms = dt
                            self._post_event("write_ok", {
                                "address": self.config.write_reg_address,
                                "value": self.current_write_val & 0xFFFF,
                                "latency_ms": dt
                            })
                    except Exception as e:
                        self.failed_requests += 1
                        cycle_success = False
                        self._post_event("error", {"op": "write", "msg": f"Исключение записи: {e}"})

                # 2. Чтение регистра (%MW1 или настроенного)
                t0 = time.perf_counter()
                self.total_requests += 1
                try:
                    res = client.read_holding_registers(
                        address=self.config.read_reg_address,
                        count=1,
                        device_id=self.config.unit_id
                    )
                    dt = (time.perf_counter() - t0) * 1000
                    if res is None or res.isError():
                        self.failed_requests += 1
                        cycle_success = False
                        err = str(res) if res else "Таймаут ответа ПЛК"
                        self._post_event("error", {"op": "read", "msg": f"Ошибка чтения %MW{self.config.read_reg_address}: {err}"})
                    else:
                        self.successful_requests += 1
                        self.last_latency_ms = dt
                        val = res.registers[0]
                        self._post_event("read_ok", {
                            "address": self.config.read_reg_address,
                            "value": val,
                            "latency_ms": dt
                        })
                except Exception as e:
                    self.failed_requests += 1
                    cycle_success = False
                    self._post_event("error", {"op": "read", "msg": f"Исключение при чтении: {e}"})

                # Отправка сводки статистики
                self._post_event("stats", {
                    "total": self.total_requests,
                    "success": self.successful_requests,
                    "failed": self.failed_requests,
                    "latency_ms": self.last_latency_ms
                })

                # Если были ошибки подряд и сокет упал
                if not cycle_success and not client.connected:
                    self._post_event("status", {"state": "disconnected", "message": "Соединение разорвано. Переподключение..."})
                    break

                # Выдерживаем интервал опроса
                elapsed = (time.perf_counter() - cycle_start) * 1000
                sleep_time = max(0.01, (self.config.poll_interval_ms - elapsed) / 1000.0)
                
                # Дробный сон для быстрой реакции на stop_event
                steps = int(sleep_time / 0.05) + 1
                dt_step = sleep_time / steps
                for _ in range(steps):
                    if self._stop_event.is_set():
                        break
                    time.sleep(dt_step)

            # Закрываем клиент при выходе из цикла
            try:
                client.close()
            except Exception:
                pass
            self._connected = False

        self._connected = False
        self._post_event("status", {"state": "disconnected", "message": "Связь отключена"})
