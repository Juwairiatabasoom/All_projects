import scapy.all as scapy
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import platform
from collections import defaultdict
import socket

# ========== Configuration ==========
KNOWN_DEVICES = {
    "5c:3a:45:0a:bb:c3": "Laptop",
    "66:77:88:99:AA:BB": "Phone",
}
PORT_SCAN_THRESHOLD = 3
ARP_SPOOF_CHECK_INTERVAL = 5

# ========== Sound Alert ==========
try:
    if platform.system() == "Windows":
        import winsound
        def play_alert_sound():
            winsound.Beep(1000, 500)
    else:
        from playsound import playsound
        def play_alert_sound():
            playsound('/System/Library/Sounds/Ping.aiff')
except:
    def play_alert_sound():
        pass

# ========== Device ==========
class Device:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.name = KNOWN_DEVICES.get(mac.upper(), "Unknown Device")

# ========== Threat Detection ==========
class ThreatDetector:
    def __init__(self):
        self.previous_macs = set()
        self.arp_table = {}
        self.port_scan_data = defaultdict(list)

    def get_local_subnet(self):
        ip = scapy.get_if_addr(scapy.conf.iface)
        subnet = ip.rsplit('.', 1)[0] + '.1/24'
        return subnet

    def scan_network(self):
        devices = []
        subnet = self.get_local_subnet()
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_broadcast, timeout=2, verbose=False)[0]

        for sent, received in answered:
            devices.append(Device(received.psrc, received.hwsrc))
        return devices

    def detect_new_devices(self, devices):
        current_macs = {d.mac for d in devices}
        new_macs = current_macs - self.previous_macs
        threats = [d for d in devices if d.mac in new_macs and d.mac.upper() not in KNOWN_DEVICES]
        self.previous_macs = current_macs
        return threats

    def detect_arp_spoof(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            src_ip = packet[scapy.ARP].psrc
            src_mac = packet[scapy.ARP].hwsrc
            if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                return f"ARP Spoofing Detected! IP {src_ip} changed MAC from {self.arp_table[src_ip]} to {src_mac}"
            self.arp_table[src_ip] = src_mac
        return None

    def detect_port_scan(self, packet):
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.TCP].dport
            current_time = time.time()
            self.port_scan_data[src_ip].append((dst_port, current_time))
            self.port_scan_data[src_ip] = [
                (port, t) for port, t in self.port_scan_data[src_ip] if current_time - t < 10
            ]
            unique_ports = set(port for port, t in self.port_scan_data[src_ip])
            if len(unique_ports) > PORT_SCAN_THRESHOLD:
                return f"Port Scanning Detected from {src_ip}"
        return None

# ========== GUI App ==========
class WiFiThreatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Threat Notifier")
        self.detector = ThreatDetector()

        self.tree = ttk.Treeview(root, columns=('Name', 'IP', 'MAC'), show='headings')
        self.tree.heading('Name', text='Device Name')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.pack(padx=10, pady=10, fill='x')

        self.status = tk.Label(root, text="Status: Ready", fg="green")
        self.status.pack(pady=5)

        self.rescan_button = tk.Button(root, text="Manual Rescan", command=self.scan_network_safe)
        self.rescan_button.pack(pady=5)

        self.start_background_scanning()
        self.start_packet_sniffing()

    def scan_network_safe(self):
        def task():
            devices = self.detector.scan_network()
            threats = self.detector.detect_new_devices(devices)

            def update_gui():
                self.tree.delete(*self.tree.get_children())
                for dev in devices:
                    self.tree.insert('', 'end', values=(dev.name, dev.ip, dev.mac))
                if threats:
                    self.status.config(text="Unauthorized device detected!", fg="red")
                    for threat in threats:
                        play_alert_sound()
                        messagebox.showwarning("Unknown Device Detected", f"Device IP: {threat.ip}\nMAC: {threat.mac}")
                else:
                    self.status.config(text="No threats detected", fg="green")
            self.root.after(0, update_gui)

        threading.Thread(target=task, daemon=True).start()

    def start_background_scanning(self):
        def background_task():
            while True:
                self.scan_network_safe()
                time.sleep(15)
        threading.Thread(target=background_task, daemon=True).start()

    def start_packet_sniffing(self):
        def packet_handler(pkt):
            arp_alert = self.detector.detect_arp_spoof(pkt)
            scan_alert = self.detector.detect_port_scan(pkt)

            if arp_alert:
                play_alert_sound()
                self.root.after(0, lambda: messagebox.showerror("ARP Spoofing", arp_alert))
                self.root.after(0, lambda: self.status.config(text="ARP Spoofing Detected!", fg="red"))

            if scan_alert:
                play_alert_sound()
                self.root.after(0, lambda: messagebox.showerror("Port Scan Detected", scan_alert))
                self.root.after(0, lambda: self.status.config(text="Port Scanning Detected!", fg="red"))

        threading.Thread(target=lambda: scapy.sniff(prn=packet_handler, store=0), daemon=True).start()

# ========== Run App ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiThreatApp(root)
    root.mainloop()
