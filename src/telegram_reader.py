"""Telegram readers report transport health independently of message traffic."""
import asyncio
from collections import OrderedDict
from datetime import datetime
import hashlib
import html
import re
import threading
import time
import urllib.request
from typing import Callable, List


def normalize_channel(channel):
    return channel.strip().replace('https://t.me/', '').replace('@', '').strip('/').lower()


class TelegramWebReader:
    def __init__(self, channels: List[str], on_message: Callable, poll_interval=4.0, on_health=None):
        self.channels = [normalize_channel(c) for c in channels if c.strip()]
        self.on_message, self.on_health = on_message, on_health
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = None
        self._seen = {c: OrderedDict() for c in self.channels}
        self.last_error = None
        self.is_running = False

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, name='TgWebReader', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=0.2)

    def _health(self, channel, ok, error=''):
        if self.on_health and not self._stop_event.is_set():
            self.on_health(channel, ok, error)

    @staticmethod
    def parse_messages(raw_html, channel):
        # Every message owns its ID, text and time; textless posts cannot borrow the next post.
        chunks = re.split(r'<div class="tgme_widget_message_wrap[^\"]*"', raw_html)[1:]
        result = []
        for chunk in chunks:
            ident = re.search(r'data-post="([^\"]+)"', chunk)
            text = re.search(r'<div class="tgme_widget_message_text[^>]*>(.*?)</div>', chunk, re.S)
            date = re.search(r'<time datetime="([^\"]+)"', chunk)
            if not (ident and text and date):
                continue
            cleaned = html.unescape(re.sub(r'<[^>]+>', ' ', re.sub(r'<br\s*/?>', '\n', text[1])))
            try:
                published = datetime.fromisoformat(date[1].replace('Z', '+00:00')).timestamp()
            except ValueError:
                continue
            result.append(dict(id=ident[1], channel=channel, text=cleaned.strip(),
                               datetime_iso=date[1], timestamp=published))
        return result

    def _fetch_channel_messages(self, channel):
        req = urllib.request.Request(f'https://t.me/s/{channel}', headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
            if 'tgme_channel_info' not in raw and 'tgme_widget_message' not in raw:
                raise ValueError('Страница канала недоступна или не распознана')
            self.last_error = None
            self._health(channel, True)
            return self.parse_messages(raw, channel)
        except Exception as exc:
            self.last_error = f'Ошибка @{channel}: {exc}'
            self._health(channel, False, self.last_error)
            return []

    def _run_loop(self):
        try:
            while not self._stop_event.is_set():
                for channel in self.channels:
                    if self._stop_event.is_set():
                        break
                    for message in self._fetch_channel_messages(channel):
                        if self._stop_event.is_set():
                            break
                        seen = self._seen[channel]
                        fingerprint = hashlib.sha256(message['text'].encode()).hexdigest()
                        ident = message['id']
                        if seen.get(ident) == fingerprint:
                            continue
                        seen[ident] = fingerprint
                        seen.move_to_end(ident)
                        while len(seen) > 200:
                            seen.popitem(last=False)
                        try:
                            self.on_message(message)
                        except Exception as exc:
                            self.last_error = f'Ошибка обработки сообщения: {exc}'
                    if self._stop_event.wait(0.2):
                        break
                self._stop_event.wait(max(0.1, self.poll_interval))
        finally:
            self.is_running = False


class TelegramTelethonReader:
    def __init__(self, api_id, api_hash, channels, on_message, session_name='seren_tg', on_health=None):
        self.api_id, self.api_hash = api_id, api_hash
        self.channels = [normalize_channel(c) for c in channels if c.strip()]
        self.on_message, self.on_health = on_message, on_health
        self.session_name = session_name
        self._thread = self._loop = self._client = None
        self._stop_event = threading.Event()
        self.is_running = False
        self.last_error = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.is_running = True
        self._thread = threading.Thread(target=self._run_async_loop, name='TelethonReader', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._client and self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(self._client.disconnect(), self._loop)
        if self._thread:
            self._thread.join(timeout=0.2)

    def _health(self, channel, ok, error=''):
        if self.on_health and not self._stop_event.is_set():
            self.on_health(channel, ok, error)

    def _run_async_loop(self):
        from telethon import TelegramClient, events
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main():
            try:
                self._client = TelegramClient(self.session_name, self.api_id, self.api_hash)
                await self._client.connect()
                if not await self._client.is_user_authorized():
                    raise RuntimeError('Требуется разовая авторизация Telethon в Telegram')
                entities = {}
                for channel in self.channels:
                    if self._stop_event.is_set():
                        return
                    try:
                        entity = await self._client.get_entity(channel)
                        entities[channel] = entity
                        # Verify access to each configured channel; replay is age-filtered by the evaluator.
                        messages = await self._client.get_messages(entity, limit=20)
                        self._health(channel, True)
                        for msg in reversed(messages):
                            if msg.raw_text:
                                self.on_message(dict(id=str(msg.id), channel=channel, text=msg.raw_text,
                                                     timestamp=msg.date.timestamp(), datetime_iso=msg.date.isoformat()))
                    except Exception as exc:
                        self._health(channel, False, str(exc))

                @self._client.on(events.NewMessage(chats=list(entities.values())))
                async def handler(event):
                    if self._stop_event.is_set():
                        return
                    chat = await event.get_chat()
                    channel = normalize_channel(getattr(chat, 'username', '') or '')
                    if channel in entities:
                        self._health(channel, True)
                        self.on_message(dict(id=str(event.id), channel=channel, text=event.raw_text,
                                             timestamp=event.date.timestamp(), datetime_iso=event.date.isoformat()))

                while not self._stop_event.is_set():
                    for channel, entity in entities.items():
                        try:
                            # Successful access probe, even in channels without new posts.
                            await self._client.get_messages(entity, limit=1)
                            self._health(channel, True)
                        except Exception as exc:
                            self._health(channel, False, str(exc))
                    await asyncio.sleep(5)
            except Exception as exc:
                self.last_error = str(exc)
                for channel in self.channels:
                    self._health(channel, False, self.last_error)
            finally:
                if self._client:
                    await self._client.disconnect()

        try:
            self._loop.run_until_complete(main())
        finally:
            self.is_running = False
            self._loop.close()
