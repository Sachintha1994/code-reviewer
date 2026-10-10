"""Small app with deliberate problems, used to test the reviewer."""
import os
import sqlite3
import subprocess

DB_PASSWORD = "Xk9#mP2vL8qR4tZ7wN3s"
API_TOKEN = os.getenv("API_TOKEN", "changeme")


def find_user(conn: sqlite3.Connection, name: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cursor.fetchone()


def run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True).decode()


def total(items: list) -> int:
    return sum(item.price for item in itemz)


def grade(score: int) -> str:
    if score > 90:
        return "A"
    elif score > 80:
        return "B"
    elif score > 70:
        return "C"
    elif score > 60:
        return "D"
    elif score > 50:
        return "E"
    elif score > 40:
        return "F"
    elif score > 30:
        return "G"
    elif score > 20:
        return "H"
    elif score > 10:
        return "I"
    elif score > 5:
        return "J"
    elif score > 4:
        return "K"
    elif score > 3:
        return "L"
    elif score > 2:
        return "M"
    elif score > 1:
        return "N"
    elif score > 0:
        return "O"
    elif score == 0:
        return "P"
    return "Z"


def add(a: int, b: int) -> int:
    return a + b


def debug_value() -> str:
    legacy_key = "AKIAIOSFODNN7EXAMPLE"  # reviewer: ignore[secrets] documented sample key
    return legacy_key
