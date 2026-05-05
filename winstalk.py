import os
import winreg
import win32net
import win32service
import psutil
import glob
from threading import Thread

class winstalk:
    def __init__(self, output_file="winstalk_dump.txt"):
        self.output_file = output_file
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(f"{'='*80}\nwinstalk enumerator\n{'='*80}\n")
            f.write("guide:\n- [triage]: anomalies and risk vectors.\n")
            f.write("- [mapping]: process and network relations.\n")
            f.write("- [dump]: raw high-volume data.\n\n")

    def log(self, text):
        try:
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(str(text) + "\n")
        except: pass

    def run_triage(self):
        self.log("\n[section] === triage report ===")
        self.log("\n[analysis] checking non-standard paths...")
        suspicious = ['\\temp\\', '\\public\\', '\\appdata\\', '\\programdata\\']
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe = proc.info['exe']
                if exe and any(s in exe.lower() for s in suspicious):
                    self.log(f"alert: {proc.info['name']} (pid: {proc.info['pid']}) -> {exe}")
            except: continue

        self.log("\n[analysis] scanning unquoted service paths...")
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            for s in win32service.EnumServicesStatusEx(scm):
                try:
                    h = win32service.OpenService(scm, s['ServiceName'], win32service.SERVICE_QUERY_CONFIG)
                    path = win32service.QueryServiceConfig(h)[3]
                    if '"' not in path and ' ' in path and 'C:\\Windows' not in path:
                        self.log(f"vuln: {s['ServiceName']} -> {path}")
                    win32service.CloseServiceHandle(h)
                except: continue
        except: pass

    def run_proc_net_map(self):
        self.log("\n[section] === process network map ===")
        conns = psutil.net_connections(kind='inet')
        c_map = {}
        for c in conns:
            if c.pid not in c_map: c_map[c.pid] = []
            c_map[c.pid].append(c)

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pid = proc.info['pid']
                if pid in c_map:
                    self.log(f"\nproc: {proc.info['name']} (pid: {pid}) | user: {proc.info['username']}")
                    for c in c_map[pid]:
                        rem = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "listening"
                        self.log(f"  └─ {c.type} {c.laddr.ip}:{c.laddr.port} <-> {rem} [{c.status}]")
            except: continue

    def run_reg_rec(self, hive, path, depth=0, max_depth=3):
        if depth > max_depth: return
        try:
            with winreg.OpenKey(hive, path) as key:
                num_sub, num_val, _ = winreg.QueryInfoKey(key)
                for i in range(num_val):
                    name, val, _ = winreg.EnumValue(key, i)
                    self.log(f"reg_val: {path}\\{name} = {val}")
                for i in range(num_sub):
                    sub_name = winreg.EnumKey(key, i)
                    self.run_reg_rec(hive, os.path.join(path, sub_name), depth + 1)
        except: pass

    def run_mod_dump(self):
        self.log("\n[section] === module inventory ===")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.log(f"\ndll map: {proc.info['name']} (pid: {proc.info['pid']}):")
                for m in proc.memory_maps():
                    self.log(f"  path: {m.path}")
            except: continue

if __name__ == "__main__":
    ws = winstalk()
    ws.run_triage()
    ws.run_proc_net_map()
    
    ws.log("\n[section] === registry configuration dump ===")
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"software\microsoft\windows\currentversion\run"),
        (winreg.HKEY_LOCAL_MACHINE, r"system\currentcontrolset\services"),
        (winreg.HKEY_LOCAL_MACHINE, r"software\microsoft\windows nt\currentversion\winlogon"),
        (winreg.HKEY_CURRENT_USER, r"software")
    ]
    for h, p in hives:
        ws.run_reg_rec(h, p)
        
    ws.run_mod_dump()
    ws.log("\n[audit complete]")