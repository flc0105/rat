#!/usr/bin/env python3
import subprocess


def main():
    result = subprocess.run(['last'], capture_output=True, text=True)
    lines = result.stdout.split('\n')

    print(f"{'User':<12} {'TTY':<8} {'Login Time':<25} {'Logout Time':<15}")
    print("-" * 70)

    for line in lines[:20]:
        if not line.strip() or line.startswith('wtmp'):
            continue
        parts = line.split()
        if len(parts) >= 6:
            user = parts[0]
            tty = parts[1]
            login = ' '.join(parts[2:5])
            logout = parts[5] if len(parts) > 5 else ''
            print(f"{user:<12} {tty:<8} {login:<25} {logout:<15}")


main()
