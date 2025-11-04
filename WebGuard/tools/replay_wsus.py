
#!/usr/bin/env python3
import json, base64, random, time, sys

def make_base64_blob(size_bytes=5000):
    raw = bytes([random.randint(0,255) for _ in range(size_bytes)])
    return base64.b64encode(raw).decode('ascii')

def make_event(pid=2000, suspicious=False, blob=None):
    if suspicious:
        payload = blob if blob is not None else make_base64_blob(8000)
        return {
            "pid": pid,
            "write_remote": 0,
            "mprotect_rwx": 0,
            "new_threads_unexpected": 0,
            "addr_entropy": 0.2,
            "unique_endpoints": 1,
            "module_loads_unusual": 0,
            "open_proc_vmwrite": 0,
            "ptrace_attempts": 0,
            "process_vm_writev": 0,
            "request_body": payload,
            "admin_api_flag": 1,
            "endpoint_rarity": 0.9
        }
    else:
        return {
            "pid": pid,
            "write_remote": 0,
            "mprotect_rwx": 0,
            "new_threads_unexpected": 0,
            "addr_entropy": 0.1,
            "unique_endpoints": 1,
            "module_loads_unusual": 0,
            "open_proc_vmwrite": 0,
            "ptrace_attempts": 0,
            "process_vm_writev": 0,
            "request_body": "normal=1&foo=bar",
            "admin_api_flag": 0,
            "endpoint_rarity": 0.1
        }

def simulate_valence_updates(num_episodes=8, out_file=None):
    valence = []
    traces = []
    for ep in range(num_episodes):
        suspicious = (ep % 3 == 0)
        ev = make_event(pid=2000, suspicious=suspicious)
        line = json.dumps(ev)
        if out_file:
            out_file.write(line + "\\n")
        else:
            print(line)
        req = ev["request_body"]
        has_blob = len(req) > 1000
        if has_blob and ev["admin_api_flag"] == 1:
            if len(traces) < 2:
                action = "log"
                reward = -0.5
            else:
                action = "isolate"
                reward = 1.0
            traces.append({"vec": "synthetic_blob_vector", "cum": reward, "valence": reward})
        else:
            action = "log"
            reward = 0.0
        valence.append({"episode": ep, "suspicious": suspicious, "action": action, "reward": reward})
        time.sleep(0.1)
    print("\\nSimulated valence updates:")
    for v in valence:
        print(v)

if __name__ == '__main__':
    out = None
    if len(sys.argv) > 1:
        out = open(sys.argv[1], "w")
    simulate_valence_updates(9, out)
