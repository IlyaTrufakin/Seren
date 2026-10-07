"""Modbus transport with coalesced control snapshots and independent heartbeat."""
from copy import deepcopy
import queue
import threading
import time
from pymodbus.client import ModbusTcpClient
from src.config import AppConfig


class ModbusWorker:
    def __init__(self, config: AppConfig, event_queue):
        self.config, self.event_queue = config, event_queue
        self._thread = self._client = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._write_queue = queue.Queue(maxsize=100)
        self._connected = False
        self.total_requests = self.successful_requests = self.failed_requests = 0
        self.last_latency_ms = 0.0
        self.current_write_val = config.last_write_value
        self.cyclic_write_enabled = config.cyclic_write
        self._control = None
        self._revision = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name='ModbusWorker', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._connected = False
        # Interrupt blocking network reads, without reusing this client's socket.
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=0.3)

    connect = start
    disconnect = stop

    def update_config(self, config):
        self.config = config
        self.cyclic_write_enabled = config.cyclic_write

    def is_connected(self):
        return self._connected

    def queue_write(self, value, address=None):
        address = self.config.write_reg_address if address is None else address
        value = int(value) & 0xffff
        if address == self.config.write_reg_address:
            self.current_write_val = value
        self._write_queue.put_nowait((address, [value]))

    def queue_write_registers(self, values, start_address=None):
        address = self.config.write_reg_address if start_address is None else start_address
        values = [int(v) & 0xffff for v in values]
        if not values:
            return
        if address == self.config.write_reg_address:
            self.current_write_val = values[0]
        self._write_queue.put_nowait((address, values))

    def set_cyclic_write(self, enabled, value=None):
        self.cyclic_write_enabled = enabled
        if value is not None:
            self.current_write_val = value & 0xffff

    def set_control_snapshot(self, word, sound, heartbeat_bit=15, reaction=None):
        if not 0 <= heartbeat_bit <= 15 or len(sound) != 5:
            raise ValueError('Некорректный снимок управления')
        clean_word = int(word) & 0xffff & ~(1 << heartbeat_bit)
        values = [int(v) for v in sound]
        if any(not 0 <= v <= 65535 for v in values):
            raise ValueError('Звуковые параметры вне диапазона WORD')
        with self._lock:
            signature = (clean_word, tuple(values), heartbeat_bit)
            if self._control is None or self._control['signature'] != signature:
                self._revision += 1
            self._control = dict(signature=signature, revision=self._revision, word=clean_word,
                                 sound=values, heartbeat_bit=heartbeat_bit, reaction=deepcopy(reaction or {}),
                                 updated_at=time.monotonic())

    def clear_control_snapshot(self):
        with self._lock:
            self._control = None

    def _post_event(self, kind, data):
        self.event_queue.put(dict(type=kind, data=data, timestamp=time.time()))

    def _write(self, client, address, values):
        self.total_requests += 1
        started = time.perf_counter()
        try:
            if len(values) == 1:
                response = client.write_register(address=address, value=values[0], device_id=self.config.unit_id)
            else:
                response = client.write_registers(address=address, values=values, device_id=self.config.unit_id)
            if response is None or response.isError():
                raise IOError(str(response) if response is not None else 'Таймаут записи')
            self.successful_requests += 1
            self.last_latency_ms = (time.perf_counter() - started) * 1000
            self._post_event('write_ok', dict(address=address, value=values[0], values=values,
                                             count=len(values), latency_ms=self.last_latency_ms))
            return True
        except Exception as exc:
            self.failed_requests += 1
            self._post_event('error', dict(op='write', msg=f'Ошибка записи %MW{address}: {exc}'))
            return False

    def _read(self, client):
        self.total_requests += 1
        started = time.perf_counter()
        try:
            response = client.read_holding_registers(address=self.config.read_reg_address,
                                                     count=1, device_id=self.config.unit_id)
            if response is None or response.isError() or not response.registers:
                raise IOError(str(response) if response is not None else 'Таймаут чтения')
            self.successful_requests += 1
            self.last_latency_ms = (time.perf_counter() - started) * 1000
            self._post_event('read_ok', dict(address=self.config.read_reg_address, value=response.registers[0],
                                           latency_ms=self.last_latency_ms))
            return True
        except Exception as exc:
            self.failed_requests += 1
            self._post_event('error', dict(op='read', msg=f'Ошибка чтения: {exc}'))
            return False

    def _control_cycle(self, client, last_sent, last_heartbeat):
        with self._lock:
            snapshot = deepcopy(self._control)
        if snapshot is None:
            return True, last_sent, last_heartbeat
        if time.monotonic() - snapshot['updated_at'] > 3:
            # A stuck evaluator must eventually trip the PLC watchdog, rather than report healthy forever.
            return True, last_sent, last_heartbeat
        heartbeat = int(time.monotonic()) % 2
        if last_sent == snapshot['revision'] and heartbeat == last_heartbeat:
            return True, last_sent, last_heartbeat
        word = snapshot['word'] | (heartbeat << snapshot['heartbeat_bit'])
        # Preserve PLC-owned MW1. Two acknowledged requests, not an atomic PLC transaction.
        ok = self._write(client, 2, snapshot['sound'])
        if ok and not self._stop_event.is_set():
            ok = self._write(client, self.config.write_reg_address, [word])
        else:
            ok = False
        if ok:
            reaction = snapshot['reaction']
            reaction['modbus_word'] = word
            self._post_event('control_ack', dict(word=word, sound=snapshot['sound'], reaction=reaction,
                                               revision=snapshot['revision'], changed=last_sent != snapshot['revision']))
            return True, snapshot['revision'], heartbeat
        return False, last_sent, last_heartbeat

    def _run_loop(self):
        pending = {}
        try:
            while not self._stop_event.is_set():
                client = None
                self._connected = False
                self._post_event('status', dict(state='connecting', message=f'Подключение к {self.config.host}:{self.config.port}'))
                try:
                    client = ModbusTcpClient(host=self.config.host, port=self.config.port,
                                             timeout=float(self.config.timeout), retries=0)
                    self._client = client
                    if not client.connect():
                        raise ConnectionError('ПЛК недоступен')
                    if self._stop_event.is_set():
                        break
                    self._connected = True
                    self._post_event('status', dict(state='connected', message='Связь с ПЛК установлена'))
                    last_sent = last_heartbeat = None
                    while not self._stop_event.is_set():
                        started = time.monotonic()
                        while True:
                            try:
                                address, values = self._write_queue.get_nowait()
                                pending[address] = values
                            except queue.Empty:
                                break
                        with self._lock:
                            controlled = self._control is not None
                        # Automatic control owns MW0 and MW2..MW6; discard stale manual commands there.
                        if controlled:
                            pending = {a: v for a, v in pending.items() if not (
                                a == self.config.write_reg_address or a <= 6 and a + len(v) > 2)}
                        failed = False
                        for address, values in list(pending.items()):
                            if self._stop_event.is_set() or not self._write(client, address, values):
                                failed = True
                                break
                            del pending[address]
                        if not failed and controlled:
                            ok, last_sent, last_heartbeat = self._control_cycle(client, last_sent, last_heartbeat)
                            failed = not ok
                        elif not failed and self.cyclic_write_enabled:
                            failed = not self._write(client, self.config.write_reg_address, [self.current_write_val])
                        if not failed and not self._stop_event.is_set():
                            failed = not self._read(client)
                        self._post_event('stats', dict(total=self.total_requests, success=self.successful_requests,
                                                      failed=self.failed_requests, latency_ms=self.last_latency_ms))
                        if failed:
                            break
                        self._stop_event.wait(max(0.01, self.config.poll_interval_ms / 1000 - (time.monotonic()-started)))
                except Exception as exc:
                    self._post_event('error', dict(msg=f'Соединение: {exc}'))
                finally:
                    self._connected = False
                    if client:
                        try:
                            client.close()
                        except Exception:
                            pass
                    self._client = None
                if not self.config.auto_reconnect or self._stop_event.is_set():
                    break
                self._post_event('status', dict(state='connecting', message='Повтор подключения через 1 с'))
                self._stop_event.wait(1.0)
        finally:
            self._connected = False
            self._post_event('status', dict(state='disconnected', message='Связь отключена'))
