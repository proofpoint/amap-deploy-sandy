import json, socket, struct, sys, time
out = []
for p in json.loads(sys.argv[1]):
    k, a, port = p["kind"], p["addr"], p["port"]
    ok = False
    try:
        if k in ("tcp", "tcp6"):
            s = socket.socket(socket.AF_INET6 if k == "tcp6" else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4); s.connect((a, port)); ok = True; s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
            q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01" if k == "dns"
                 else b"\x1b" + b"\x00" * 47)
            s.sendto(q, (a, port)); ok = len(s.recvfrom(512)[0]) > 0; s.close()
    except OSError:
        ok = False
    out.append({**p, "ok": ok})
print(json.dumps(out))
