import random
import time
import os
from datetime import datetime

os.makedirs("logs", exist_ok=True)
LOG_PATH = "logs/demo.log"

IPS = [
    "192.168.1.45", "10.0.0.23", "172.16.4.88",
    "203.0.113.12", "198.51.100.7", "45.55.200.1",
    "91.108.4.1",   "1.2.3.4",
]

USERS = ["root", "admin", "ubuntu", "deploy", "git", "oracle", "postgres"]

AUTH_TEMPLATES = [
    "Failed password for {user} from {ip} port {port} ssh2",
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Invalid user {user} from {ip} port {port}",
    "Accepted password for {user} from {ip} port {port} ssh2",
    "Accepted publickey for {user} from {ip} port {port} ssh2",
    "sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}",
]

APACHE_TEMPLATES = [
    '{ip} - - [{ts}] "GET /wp-admin HTTP/1.1" 401 512',
    '{ip} - - [{ts}] "GET /../../../etc/passwd HTTP/1.1" 400 0',
    '{ip} - - [{ts}] "GET /.env HTTP/1.1" 404 0',
    '{ip} - - [{ts}] "POST /login HTTP/1.1" 200 1024',
    '{ip} - - [{ts}] "GET /api/users HTTP/1.1" 200 4096',
    '{ip} - - [{ts}] "GET /index.php?id=1%27 HTTP/1.1" 500 0',
    '{ip} - - [{ts}] "GET /admin/config HTTP/1.1" 403 256',
]


def auth_line(aggressive: bool = False) -> str:
    now = datetime.now()
    # FIX: Use strftime("%b") instead of a manual MONTHS list
    prefix = f"{now.strftime('%b')} {now.day:2d} {now.strftime('%H:%M:%S')} myserver sshd[{random.randint(1000, 9999)}]"
    user = "root" if aggressive else random.choice(USERS)
    ip   = random.choice(IPS[:2] if aggressive else IPS)
    tpl  = random.choice(AUTH_TEMPLATES[:3] if aggressive else AUTH_TEMPLATES)
    msg  = tpl.format(user=user, ip=ip, port=random.randint(40000, 65000))
    return f"{prefix}: {msg}"


def apache_line() -> str:
    now    = datetime.now()
    ts_str = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip     = random.choice(IPS)
    tpl    = random.choice(APACHE_TEMPLATES)
    return tpl.format(ip=ip, ts=ts_str)


def main():
    print(f"[demo_log_gen] Writing to {LOG_PATH}. Press Ctrl+C to stop.")
    burst_countdown = 0
    # FIX: Wrap loop in try/except for clean Ctrl+C exit
    try:
        with open(LOG_PATH, "a") as f:
            while True:
                if burst_countdown > 0:
                    line = auth_line(aggressive=True)
                    burst_countdown -= 1
                elif random.random() < 0.03:
                    # FIX: Set countdown BEFORE writing so total burst length
                    # is exactly burst_countdown (not burst_countdown + 1)
                    burst_countdown = random.randint(15, 30) - 1
                    line = auth_line(aggressive=True)
                    print("[demo_log_gen] 🚨 Starting brute-force burst!")
                elif random.random() < 0.4:
                    line = apache_line()
                else:
                    line = auth_line()

                f.write(line + "\n")
                f.flush()
                print(line)
                time.sleep(random.uniform(0.3, 1.2))
    except KeyboardInterrupt:
        print("\n[demo_log_gen] Stopped.")


if __name__ == "__main__":
    main()