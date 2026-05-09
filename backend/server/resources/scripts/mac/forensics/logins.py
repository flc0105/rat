#!/usr/bin/env python3
import re
import json
import shutil
import subprocess
import datetime as dt

MAX_RECORDS = 1000

WEEKDAYS = {
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
}

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

LAST_BIN = (
    shutil.which("last")
    or "/usr/bin/last"
)


def run_last():
    # 先尝试 -F：很多 BSD/macOS last 支持完整时间。
    # 如果不支持，再退回普通 last。
    attempts = [
        [LAST_BIN, "-F"],
        [LAST_BIN],
    ]

    for cmd in attempts:
        try:
            r = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                timeout=30,
            )
        except Exception:
            continue

        if r.returncode == 0 and r.stdout.strip():
            return r.stdout, " ".join(cmd)

    return "", ""


def clean(value):
    if value is None:
        return ""

    return re.sub(r"\s+", " ", str(value)).strip()


def find_date_index(tokens):
    for i, token in enumerate(tokens):
        if token in WEEKDAYS and i + 3 < len(tokens):
            if tokens[i + 1] in MONTHS:
                return i

    return -1


def parse_full_date(tokens, index):
    # -F 常见格式：
    # Sun May  3 13:20:11 2026
    if index + 5 >= len(tokens):
        return None, index

    chunk = tokens[index:index + 6]
    text = " ".join(chunk)

    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M %Y",
    ):
        try:
            value = dt.datetime.strptime(text, fmt)
            return value, index + 6
        except Exception:
            pass

    return None, index


def infer_year_date(tokens, index):
    # 普通 last 常见格式：
    # Sun May  3 13:20
    if index + 3 >= len(tokens):
        return None, index

    weekday = tokens[index]
    month = tokens[index + 1]
    day = tokens[index + 2]
    time_part = tokens[index + 3]

    now = dt.datetime.now()
    year = now.year

    candidates = []

    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M %Y"):
        text = f"{weekday} {month} {day} {time_part} {year}"
        try:
            value = dt.datetime.strptime(text, fmt)
            candidates.append(value)
        except Exception:
            pass

    if not candidates:
        return None, index

    value = candidates[0]

    # last 普通格式通常不带年份。
    # 如果解析出来的日期明显在未来，说明应该是上一年。
    if value > now + dt.timedelta(days=1):
        try:
            value = value.replace(year=year - 1)
        except Exception:
            pass

    return value, index + 4


def parse_login_date(tokens, index):
    value, next_index = parse_full_date(tokens, index)
    if value is not None:
        return value, next_index, "full"

    value, next_index = infer_year_date(tokens, index)
    if value is not None:
        return value, next_index, "short"

    return None, index, ""


def parse_logout_datetime(tokens, index, login_time, date_mode):
    if index >= len(tokens):
        return None, index, ""

    token = tokens[index]

    if token in {"still", "logged", "in"}:
        return None, index, "still_logged_in"

    if token in {"crash", "down"}:
        return None, index + 1, token

    # -F 模式：logout 后也可能是完整日期
    if token in WEEKDAYS:
        value, next_index = parse_full_date(tokens, index)
        if value is not None:
            return value, next_index, "completed"

        value, next_index = infer_year_date(tokens, index)
        if value is not None:
            return value, next_index, "completed"

    # 普通模式：logout 常常只有 HH:MM 或 HH:MM:SS
    if re.match(r"^\d{1,2}:\d{2}(:\d{2})?$", token):
        if login_time is None:
            return None, index + 1, "completed"

        parts = token.split(":")
        hour = int(parts[0])
        minute = int(parts[1])
        second = int(parts[2]) if len(parts) == 3 else 0

        logout_time = login_time.replace(
            hour=hour,
            minute=minute,
            second=second,
            microsecond=0,
        )

        # 如果 logout 时间小于 login 时间，说明跨天了。
        if logout_time < login_time:
            logout_time += dt.timedelta(days=1)

        return logout_time, index + 1, "completed"

    return None, index + 1, clean(token)


def iso(value):
    if value is None:
        return ""

    try:
        return value.astimezone().isoformat(timespec="seconds")
    except Exception:
        try:
            return value.isoformat(timespec="seconds")
        except Exception:
            return ""


def extract_duration(raw_line):
    m = re.search(r"\(([^)]+)\)", raw_line)
    if not m:
        return ""

    return m.group(1).strip()


def classify_event(user, status):
    if user == "reboot":
        return "boot"

    if user == "shutdown":
        return "shutdown"

    if status == "still_logged_in":
        return "login_active"

    if status in {"crash", "down"}:
        return "session_interrupted"

    return "login_session"


def parse_last_line(line, source_command):
    raw = line.rstrip("\n")

    if not raw.strip():
        return None

    if raw.startswith("wtmp begins"):
        return None

    tokens = raw.split()

    if len(tokens) < 5:
        return None

    date_index = find_date_index(tokens)
    if date_index < 0:
        return None

    before_date = tokens[:date_index]

    if not before_date:
        return None

    user = before_date[0]
    line_name = before_date[1] if len(before_date) >= 2 else ""
    host = " ".join(before_date[2:]) if len(before_date) >= 3 else ""

    login_time, next_index, date_mode = parse_login_date(tokens, date_index)
    if login_time is None:
        return None

    logout_time = None
    status = ""

    if next_index < len(tokens):
        if tokens[next_index] == "-":
            logout_time, next_index, status = parse_logout_datetime(
                tokens,
                next_index + 1,
                login_time,
                date_mode,
            )
        else:
            tail = " ".join(tokens[next_index:])
            if "still logged in" in tail:
                status = "still_logged_in"
            else:
                status = clean(tail)

    if not status:
        if user in {"reboot", "shutdown"}:
            status = user
        else:
            status = "completed" if logout_time else ""

    return {
        "event": classify_event(user, status),
        "user": user,
        "line": line_name,
        "host": host,
        "login_time": iso(login_time),
        "logout_time": iso(logout_time),
        "status": status,
        "duration": extract_duration(raw),
        "source": "last",
        "source_command": source_command,
        "raw": raw,
    }


def main():
    text, source_command = run_last()

    output = []

    for line in text.splitlines():
        item = parse_last_line(line, source_command)
        if item is None:
            continue

        output.append(item)

        if len(output) >= MAX_RECORDS:
            break

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()