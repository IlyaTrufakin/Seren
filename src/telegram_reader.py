import time
import threading
import queue
import re
import urllib.request
from typing import List, Callable, Optional, Dict
import html

class TelegramWebReader:
    """
    Быстрый неблокирующий ридер публичных каналов Telegram через веб-зеркало t.me/s/.
    Работает без авторизации, без api_id и без телефона, получая свежие посты.
    """
    def __init__(self, channels: List[str], on_message: Callable[[dict], None], poll_interval: float = 4.0):
        self.channels = [c.replace("https://t.me/", "").replace("@", "").strip() for c in channels if c.strip()]
        self.on_message = on_message
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_texts: Dict[str, set] = {ch: set() for ch in self.channels}
        self.last_error: Optional[str] = None
        self.is_running = False

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, name="TgWebReaderThread", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _fetch_channel_messages(self, channel: str) -> List[dict]:
        url = f"https://t.me/s/{channel}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                raw_html = resp.read().decode("utf-8", errors="ignore")
                self.last_error = None
        except Exception as e:
            self.last_error = f"Ошибка сети при опросе @{channel}: {e}"
            return []

        # Поиск блоков сообщений: текст и время
        # Регулярка для извлечения виджетов сообщений
        msg_blocks = re.findall(
            r'<div class="tgme_widget_message_wrap[^"]*".*?<div class="tgme_widget_message_text[^>]*>(.*?)</div>.*?<time datetime="([^"]+)"',
            raw_html,
            re.DOTALL
        )
        results = []
        for text_html, dt_str in msg_blocks:
            # Очистка HTML
            clean_text = re.sub(r'<br\s*/?>', '\n', text_html)
            clean_text = re.sub(r'<[^>]+>', ' ', clean_text)
            clean_text = html.unescape(clean_text).strip()
            if not clean_text:
                continue
            results.append({
                "channel": channel,
                "text": clean_text,
                "datetime_iso": dt_str,
                "timestamp": time.time()
            })
        return results

    def _run_loop(self):
        # Первичный прогон: запоминаем существующие последние сообщения, чтобы не спамить старыми
        for ch in self.channels:
            msgs = self._fetch_channel_messages(ch)
            if ch not in self._seen_texts:
                self._seen_texts[ch] = set()
            for m in msgs:
                self._seen_texts[ch].add(m["text"])

        # Основной цикл
        while not self._stop_event.is_set():
            for ch in self.channels:
                if self._stop_event.is_set():
                    break
                msgs = self._fetch_channel_messages(ch)
                if ch not in self._seen_texts:
                    self._seen_texts[ch] = set()

                for m in msgs:
                    txt = m["text"]
                    if txt not in self._seen_texts[ch]:
                        self._seen_texts[ch].add(txt)
                        # Ограничиваем размер кэша последних сообщений
                        if len(self._seen_texts[ch]) > 100:
                            self._seen_texts[ch] = set(list(self._seen_texts[ch])[-60:])
                        try:
                            self.on_message(m)
                        except Exception as e:
                            print(f"[TG Reader] Callback error: {e}")

                # Небольшая пауза между каналами
                time.sleep(0.5)

            # Выдерживаем общий интервал опроса
            steps = int(self.poll_interval * 10)
            for _ in range(steps):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)


class TelegramTelethonReader:
    """
    Полноценный клиент Telethon на официальном MTProto API.
    Использует постоянное соединение и push-уведомления.
    """
    def __init__(self, api_id: int, api_hash: str, channels: List[str], on_message: Callable[[dict], None], session_name: str = "seren_tg"):
        self.api_id = api_id
        self.api_hash = api_hash
        self.channels = [c.replace("https://t.me/", "").replace("@", "").strip() for c in channels if c.strip()]
        self.on_message = on_message
        self.session_name = session_name
        self._thread: Optional[threading.Thread] = None
        self._loop = None
        self._client = None
        self.is_running = False
        self.last_error: Optional[str] = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._run_async_loop, name="TelethonThread", daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False
        if self._client and self._loop:
            try:
                import asyncio
                asyncio.run_coroutine_threadsafe(self._client.disconnect(), self._loop)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_async_loop(self):
        import asyncio
        from telethon import TelegramClient, events

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main():
            try:
                self._client = TelegramClient(self.session_name, self.api_id, self.api_hash)
                await self._client.connect()
                if not await self._client.is_user_authorized():
                    self.last_error = "Требуется разовая авторизация Telethon в Telegram"
                    return

                @self._client.on(events.NewMessage(chats=self.channels))
                async def handler(event):
                    try:
                        chat = await event.get_chat()
                        ch_name = getattr(chat, 'username', None) or getattr(chat, 'title', 'unknown')
                        self.on_message({
                            "channel": ch_name,
                            "text": event.raw_text,
                            "datetime_iso": event.date.isoformat(),
                            "timestamp": time.time()
                        })
                    except Exception as ex:
                        print(f"[Telethon] Message handler error: {ex}")

                await self._client.run_until_disconnected()
            except Exception as e:
                self.last_error = f"Ошибка Telethon: {e}"

        try:
            self._loop.run_until_complete(main())
        finally:
            self._loop.close()
