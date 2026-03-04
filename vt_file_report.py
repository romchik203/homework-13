#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для получения отчёта о файле через VirusTotal API v3.
Сохраняет сырой JSON и формирует читаемый отчёт в отдельный файл.
"""

import sys
import json
import requests
from pathlib import Path
from datetime import datetime

# ----------------------------------------------------------------------
# Настройки
# ----------------------------------------------------------------------
BASE_URL = "https://www.virustotal.com/api/v3/"
SAVE_TO_FILE = True
OUTPUT_FILE = "virustotal_response.json"
REPORT_FILE = "virustotal_report.txt"   # Краткий читаемый отчёт
DEFAULT_HASH = "44d88612fea8a8f36de82e1278abb02f"  # MD5 EICAR (тестовый)


def build_readable_report(data):
    """Парсит ответ VirusTotal и формирует читаемый текстовый отчёт."""
    lines = []
    lines.append("=" * 70)
    lines.append("                    ОТЧЁТ VIRUSTOTAL ПО ФАЙЛУ")
    lines.append("=" * 70)
    lines.append("")

    try:
        attrs = data.get("data", {}).get("attributes", {})
    except (TypeError, AttributeError):
        return "\n".join(lines) + "\n(Не удалось извлечь данные из ответа.)\n"

    # ---- Основная информация о файле ----
    lines.append("▸ ИНФОРМАЦИЯ О ФАЙЛЕ")
    lines.append("-" * 50)
    lines.append("  Имя (основное):  {}".format(attrs.get("meaningful_name", "—")))
    lines.append("  Размер:          {} байт".format(attrs.get("size", "—")))
    lines.append("  Тип:             {}".format(attrs.get("type_description", attrs.get("magic", "—"))))
    lines.append("  Расширение:      {}".format(attrs.get("type_extension", "—")))
    if attrs.get("names"):
        names = attrs["names"][:10]
        lines.append("  Известные имена: {}".format(", ".join(names)))
        if len(attrs["names"]) > 10:
            lines.append("                   ... и ещё {} вариантов".format(len(attrs["names"]) - 10))
    lines.append("")

    # ---- Хеши ----
    lines.append("▸ ХЕШИ")
    lines.append("-" * 50)
    lines.append("  MD5:    {}".format(attrs.get("md5", "—")))
    lines.append("  SHA-1:  {}".format(attrs.get("sha1", "—")))
    lines.append("  SHA-256: {}".format(attrs.get("sha256", "—")))
    lines.append("")

    # ---- Статистика сканирования ----
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless + stats.get("timeout", 0) + stats.get("failure", 0) + stats.get("type-unsupported", 0)

    lines.append("▸ РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ (антивирусные движки)")
    lines.append("-" * 50)
    lines.append("  Всего движков:   {}".format(total))
    lines.append("  Обнаружено:      {} (вредоносное)".format(malicious))
    lines.append("  Подозрительно:   {}".format(suspicious))
    lines.append("  Без угрозы:      {} (undetected)".format(undetected))
    lines.append("  Безвредно:       {}".format(harmless))
    if total > 0:
        pct = round(100 * (malicious + suspicious) / total, 1)
        lines.append("  Итог:            {}% движков считают файл подозрительным/вредоносным".format(pct))
    lines.append("")

    # ---- Репутация и метка угрозы ----
    rep = attrs.get("reputation")
    if rep is not None:
        lines.append("▸ РЕПУТАЦИЯ И КЛАССИФИКАЦИЯ")
        lines.append("-" * 50)
        lines.append("  Репутация (VT):  {}".format(rep))
        pop = attrs.get("popular_threat_classification", {})
        label = pop.get("suggested_threat_label")
        if label:
            lines.append("  Метка угрозы:     {}".format(label))
        lines.append("")

    # ---- Движки, обнаружившие угрозу ----
    results = attrs.get("last_analysis_results", {})
    if results:
        malicious_engines = [
            (name, info.get("result") or info.get("category", ""))
            for name, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]
        if malicious_engines:
            lines.append("▸ ДВИЖКИ, ОБНАРУЖИВШИЕ УГРОЗУ")
            lines.append("-" * 50)
            for name, result in sorted(malicious_engines, key=lambda x: x[0]):
                res_str = (result or "").strip()
                if len(res_str) > 45:
                    res_str = res_str[:42] + "..."
                lines.append("  • {:25} → {}".format(name, res_str))
            lines.append("")

    # ---- Теги ----
    tags = attrs.get("tags", [])
    if tags:
        lines.append("▸ ТЕГИ")
        lines.append("-" * 50)
        lines.append("  {}".format(", ".join(tags)))
        lines.append("")

    # ---- Песочницы (sandbox) ----
    sandbox = attrs.get("sandbox_verdicts", {})
    if sandbox:
        lines.append("▸ ВЕРДИКТЫ ПЕСОЧНИЦ")
        lines.append("-" * 50)
        for name, verdict in sandbox.items():
            if isinstance(verdict, dict):
                cat = verdict.get("category", "—")
                lines.append("  • {}: {}".format(name, cat))
            else:
                lines.append("  • {}: {}".format(name, verdict))
        lines.append("")

    # ---- Даты ----
    last_ts = attrs.get("last_analysis_date")
    if last_ts:
        try:
            dt = datetime.utcfromtimestamp(last_ts)
            lines.append("▸ ДАТЫ")
            lines.append("-" * 50)
            lines.append("  Последний анализ: {} UTC".format(dt.strftime("%Y-%m-%d %H:%M:%S")))
            lines.append("")
        except (OSError, ValueError):
            pass

    lines.append("=" * 70)
    lines.append("Сырой JSON сохранён в: {}".format(OUTPUT_FILE))
    lines.append("=" * 70)
    return "\n".join(lines)

# ----------------------------------------------------------------------
# 1. Запуск программы — сразу запрашиваем API-ключ
# ----------------------------------------------------------------------
print("VirusTotal: отчёт о файле по хешу (API v3)\n")
try:
    api_key = input("Введите ваш VirusTotal API-ключ: ").strip()
except EOFError:
    api_key = ""
if not api_key:
    print("❌ Ошибка: API-ключ не указан.")
    sys.exit(1)

# ----------------------------------------------------------------------
# 2. Запрашиваем хеш файла (аргумент командной строки или ввод)
# ----------------------------------------------------------------------
if len(sys.argv) > 1:
    file_hash = sys.argv[1]
else:
    try:
        file_hash = input("Введите хеш файла (MD5/SHA-1/SHA-256) или Enter для тестового: ").strip()
    except EOFError:
        file_hash = ""
    if not file_hash:
        file_hash = DEFAULT_HASH
        print(f"⚠️  Используется тестовый хеш: {file_hash}")

# ----------------------------------------------------------------------
# 3. Формирование запроса и выполнение
# ----------------------------------------------------------------------
headers = {
    "x-apikey": api_key,
    "Accept": "application/json"
}
url = f"{BASE_URL}files/{file_hash}"

# ----------------------------------------------------------------------
# Выполнение запроса
# ----------------------------------------------------------------------
try:
    print(f"\n🔍 Запрашиваю информацию о файле с хешем {file_hash}...")
    response = requests.get(url, headers=headers)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"❌ Ошибка при выполнении запроса: {e}")
    if hasattr(e, "response") and e.response is not None and e.response.status_code == 404:
        print("   Возможно, файл с таким хешем не найден в базе VirusTotal.")
    sys.exit(1)

# ----------------------------------------------------------------------
# Обработка успешного ответа
# ----------------------------------------------------------------------
try:
    data = response.json()
except json.JSONDecodeError:
    print("❌ Ошибка декодирования JSON. Ответ сервера не является валидным JSON.")
    sys.exit(1)

print("\n✅ Запрос выполнен успешно. Полученные данные:\n")
print(json.dumps(data, indent=2, ensure_ascii=False))

# ----------------------------------------------------------------------
# Сохранение ответа в файл (опционально)
# ----------------------------------------------------------------------
if SAVE_TO_FILE:
    output_path = Path(OUTPUT_FILE)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n📁 Ответ также сохранён в файл: {output_path.absolute()}")

# ----------------------------------------------------------------------
# Парсинг и сохранение читаемого отчёта в отдельный файл
# ----------------------------------------------------------------------
report_text = build_readable_report(data)
report_path = Path(REPORT_FILE)
with open(report_path, "w", encoding="utf-8") as f:
    f.write(report_text)
print(f"📄 Краткий отчёт сохранён в файл: {report_path.absolute()}")
