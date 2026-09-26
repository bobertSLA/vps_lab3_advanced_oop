import re
import time
import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор для аудита функций ИБ-анализа.
    Замеряет время выполнения, логирует обнаружение угроз и перехватывает ошибки.
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            elapsed = time.perf_counter() - start_time
            print(f"[AUDIT] Ошибка в '{func.__name__}' (за {elapsed:.6f} сек): {exc}")
            return None
        elapsed = time.perf_counter() - start_time

        if result:
            print(f"[AUDIT] '{func.__name__}' обнаружил событие/угрозу: {result} "
                  f"(время выполнения: {elapsed:.6f} сек)")
        else:
            print(f"[AUDIT] '{func.__name__}' завершена без обнаружений "
                  f"(время выполнения: {elapsed:.6f} сек)")

        return result
    return wrapper


class SecurityEvent:
    """
    Класс события безопасности ИБ.
    """

    # Ключевые слова -> уровень severity (1..5), проверяются от самых
    # критичных к наименее критичным; первое совпадение побеждает.
    _SEVERITY_KEYWORDS: list[tuple[int, tuple[str, ...]]] = [
        (5, ("attack", "exploit", "breach", "compromise", "injection", "sqli", "malware", "ransomware")),
        (4, ("unauthorized", "intrusion", "brute", "root access")),
        (3, ("failed login", "failed password", "denied", "blocked")),
        (2, ("warning", "suspicious")),
    ]

    # Формат строки: "2026-09-13 12:00:00 [SSH] Failed login from 192.168.1.50"
    _SYSLOG_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\[(?P<event_type>[^\]]+)\]\s*"
        r"(?P<message>.*)$"
    )

    _IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, timestamp: str, source_ip: str, event_type: str, severity: int = 1) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("severity должен быть целым числом от 1 до 5")

        if value < 1 or value > 5:
            raise ValueError("Severity must be between 1 and 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        """Возвращает True, если уровень угрозы >= 4."""
        return self._severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Фабричный метод: создает объект из строки syslog.

        Ожидаемый формат:
            "2026-09-13 12:00:00 [SSH] Failed login from 192.168.1.50"

        - timestamp берется из начала строки ("2026-09-13 12:00:00").
        - event_type берется из содержимого квадратных скобок (например, "SSH").
        - IP-адрес ищется во всей строке; если не найден - используется "0.0.0.0".
        - severity вычисляется по ключевым словам в сообщении
          (см. _SEVERITY_KEYWORDS); если совпадений нет - severity = 1.

        Строки, не соответствующие формату, все равно обрабатываются:
        timestamp/event_type получают значение "unknown", а IP и severity
        по-прежнему извлекаются из текста строки.
        """
        if not raw_line or not raw_line.strip():
            raise ValueError("raw_line должна быть непустой строкой")

        line = raw_line.strip()
        match = cls._SYSLOG_PATTERN.match(line)

        if match:
            timestamp = match.group("timestamp")
            event_type = match.group("event_type")
            message = match.group("message")
        else:
            timestamp = "unknown"
            event_type = "unknown"
            message = line

        ip_match = cls._IP_PATTERN.search(line)
        source_ip = ip_match.group(0) if ip_match else "0.0.0.0"

        lowered = message.lower()
        severity = 1
        for level, keywords in cls._SEVERITY_KEYWORDS:
            if any(keyword in lowered for keyword in keywords):
                severity = level
                break

        return cls(timestamp=timestamp, source_ip=source_ip, event_type=event_type, severity=severity)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """
        Фабричный метод: создает объект из словаря.
        """
        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1),
        )

    def __repr__(self) -> str:
        return f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', severity={self.severity})"


class IPUtils:
    """
    Класс-утилита для работы с IP-адресами.
    """

    @staticmethod
    def is_private(ip: str) -> bool:
        """
        Проверяет, является ли IP частным (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x).
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(part) for part in parts]
        except ValueError:
            return False
        if not all(0 <= octet <= 255 for octet in octets):
            return False

        first, second, _, _ = octets
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        """
        Маскирует последний октет IP-адреса.
        Пример: '192.168.1.50' -> '192.168.1.***'
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        parts[-1] = "***"
        return ".".join(parts)


class BlacklistManager:
    """
    Менеджер заблокированных IP-адресов.
    """
    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"