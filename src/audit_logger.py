import os
import time
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List


class ThreatAuditLogger:
    """
    Файловый регистратор значимых оперативных событий от онлайн-источников (Telegram / API)
    и реакции системы/приложения (%MW0..%MW6, уровень тревоги, сектор, сирена).

    Записывает ТОЛЬКО актуальные события (мусор и рутинные тики игнорируются)
    с точными временными метками для оценки правильности срабатывания.
    """
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self._lock = threading.Lock()
        os.makedirs(self.log_dir, exist_ok=True)

    def _get_log_filepath(self) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"threat_audit_{date_str}.log")

    def _write_block(self, header_title: str, source_info: List[str], reaction_info: List[str], confirmed=False):
        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        filepath = self._get_log_filepath()

        lines = [
            "=" * 84,
            f"[{now_dt}] {header_title}",
            "-" * 84,
            "ВХОДЯЩИЕ ДАННЫЕ ИСТОЧНИКА:"
        ]
        for s in source_info:
            lines.append(f"  {s}")

        lines.append("-" * 84)
        lines.append("ПОДТВЕРЖДЁННАЯ КОМАНДА ПЛК:" if confirmed else
                     "РАСЧЁТ СИСТЕМЫ (передача в ПЛК подтверждается отдельной записью):")
        for r in reaction_info:
            lines.append(f"  {r}")
        lines.append("=" * 84)
        lines.append("\n")

        text_block = "\n".join(lines)

        with self._lock:
            try:
                with open(filepath, "a", encoding="utf-8") as f:
                    f.write(text_block)
                    f.flush()
            except Exception as e:
                print(f"[ThreatAuditLogger] Ошибка записи лога: {e}")

    def log_telegram_event(self, ev_data: Dict[str, Any], reaction: Dict[str, Any]):
        """Запись значимого сообщения Telegram и реакции системы на него."""
        header = f"ОПЕРАТИВНОЕ СООБЩЕНИЕ: TELEGRAM @{ev_data.get('channel', 'TG')}"

        src_info = [
            f"Канал: @{ev_data.get('channel', 'TG')} | Время публикации: {ev_data.get('time_str', '')}",
            f"Категория: {ev_data.get('category', '')} | Бейдж: {ev_data.get('badge_threat', '')} {ev_data.get('badge_target', '')}",
            f"Определенный сектор: {ev_data.get('sector_name', 'Не указан')}",
            f"Критичность: {'КРИТИЧЕСКАЯ' if ev_data.get('is_critical') else 'Обычная'}",
            f"Текст сообщения: \"{ev_data.get('text', '')}\""
        ]

        reaction_info = self._format_reaction(reaction)
        self._write_block(header, src_info, reaction_info)

    def log_diagnostic(self, title: str, message: str):
        self._write_block(title, [message], [])

    def log_plc_confirmation(self, data: Dict[str, Any]):
        """FC06/FC16 acknowledged both writes; does not assert actual relay state."""
        sound = data["sound"]
        self._write_block("ПЛК ПОДТВЕРДИЛ ЗАПИСЬ КОМАНДЫ MODBUS", [
            f"%MW0={data['word']}; %MW2..%MW6={sound}",
            "Оба запроса подтверждены. Фактическое состояние выходного реле не считывалось."
        ], self._format_reaction(data.get("reaction", {})), confirmed=True)

    def log_api_event(self, api_summary: str, api_details: List[Dict[str, Any]], reaction: Dict[str, Any]):
        """Запись изменения статуса в AlarmMap API и реакции системы."""
        header = "ИЗМЕНЕНИЕ СТАТУСА: ALARM-MAP API (alarmmap.online)"

        src_info = [
            f"Общий статус: {api_summary}",
            f"Количество активных тревог: {len(api_details)}"
        ]
        if api_details:
            src_info.append("Расшифровка активных тревог из API:")
            for idx, item in enumerate(api_details, 1):
                src_info.append(
                    f"  {idx}. [{item.get('type', '')}] {item.get('type_title', '')} | "
                    f"Уровень: {item.get('level', '')} ({item.get('level_title', '')}) | "
                    f"Старт: {item.get('start_local', '')} (длится {item.get('duration_str', '')}) | "
                    f"КАТОТТГ: {item.get('katottg', '')} ({item.get('target_name', '')})"
                )
        else:
            src_info.append("Активных угроз не зафиксировано (Отбой тревоги / Спокойно).")

        reaction_info = self._format_reaction(reaction)
        self._write_block(header, src_info, reaction_info)

    def log_reset_event(self, source: str, reaction: Dict[str, Any]):
        """Запись сброса тревоги оператором или с ПЛК."""
        header = "СБРОС ТРЕВОЖНОГО СОСТОЯНИЯ"
        src_info = [
            f"Инициатор сброса: {source}",
            "Действие: Сброс таймеров Telegram. Действующие тревоги API анализируются повторно."
        ]
        reaction_info = self._format_reaction(reaction)
        self._write_block(header, src_info, reaction_info)

    def log_plc_switch_event(self, switch_on: bool, reaction: Dict[str, Any]):
        """Запись переключения аппаратного тумблера анализа на ПЛК."""
        header = "ПЕРЕКЛЮЧЕНИЕ ТУМБЛЕРА АНАЛИЗА НА ПЛК"
        src_info = [
            f"Состояние тумблера (%MW1): {'ВКЛЮЧЕН (Анализ активен)' if switch_on else 'ВЫКЛЮЧЕН (Анализ приостановлен)'}"
        ]
        reaction_info = self._format_reaction(reaction)
        self._write_block(header, src_info, reaction_info)

    def _format_reaction(self, reaction: Dict[str, Any]) -> List[str]:
        lvl = reaction.get("level_code", 0)
        title = reaction.get("level_title", "Безопасно")
        desc = reaction.get("description", "")
        mw0 = reaction.get("modbus_word", 1)
        sound_name = reaction.get("sound_profile_name", "")
        sound_code = reaction.get("sound_code", 0)
        beeps = reaction.get("sound_beep_count", 0)
        dur = reaction.get("sound_duration_ms", 0)
        pause = reaction.get("sound_pause_ms", 0)
        interval = reaction.get("sound_interval_ms", 0)

        # Флаги угроз
        flags = []
        if reaction.get("has_rocket"): flags.append("🚀 РАКЕТА")
        if reaction.get("has_kab"): flags.append("💣 КАБ")
        if reaction.get("has_drone"):
            d_name = reaction.get("matched_drone_name", "")
            d_grp = reaction.get("drone_group", 0)
            flags.append(f"🛸 ДРОН ({d_name.upper() if d_name else 'БпЛА'}, Гр.{d_grp})")
        if reaction.get("is_muted"): flags.append("🌙 ТИХИЙ ЧАС")
        if reaction.get("analysis_disabled_by_plc"): flags.append("⛔ ТУМБЛЕР ПЛК ВЫКЛ")

        flags_str = ", ".join(flags) if flags else "нет активных угроз"

        return [
            f"• Уровень опасности: {lvl} ({title})",
            f"• Описание: {desc}",
            f"• Причина: {reaction.get('reason', '')}",
            f"• Активные угрозы: {flags_str}",
            f"• Слово передачи %MW0: 0x{mw0:04X} (DEC: {mw0})",
            f"• Профиль звука: \"{sound_name}\"",
            f"    Параметры: %MW2(Код)={sound_code}, %MW3(Гудков)={beeps} шт, %MW4(Длит)={dur} мс, %MW5(Пауза)={pause} мс, %MW6(Интервал)={interval} мс"
        ]
