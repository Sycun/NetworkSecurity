from scapy.all import sniff, DNSQR
from collections import defaultdict
import re

suspect_domains = [
    r".*.xyz$",
    r".*.top$",
    r".*.pw$",
    r"dns.exfil.com"
]

class DNSMonitor:
    def __init__(self, output_signal):
        self.running = False
        self.output_signal = output_signal

    def dns_handler(self, packet):
        if packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode().rstrip('.')
            src_ip = packet[IP].src
            
            # 检测可疑域名模式
            for pattern in suspect_domains:
                if re.match(pattern, domain):
                    self.output_signal.emit(f'[!] 可疑DNS查询: {src_ip} -> {domain}')
            
            # 检测长随机子域名
            if len(domain.split('.')) > 3 and re.search(r"[a-z0-9]{16}", domain):
                self.output_signal.emit(f'[!] 潜在DNS隐蔽通道: {src_ip} -> {domain}')

    def start_monitoring(self):
        self.running = True
        sniff(prn=self.dns_handler, filter="udp port 53", store=0, stop_filter=lambda x: not self.running)

    def stop_monitoring(self):
        self.running = False

if __name__ == "__main__":
    print("启动DNS查询监控器...")
    print("警告：本工具仅限授权使用，监控网络流量需遵守当地法律法规\n")
    monitor = DNSMonitor(print)
    monitor.start_monitoring()