from scapy.all import sniff, ARP
import time

arp_table = {}

def arp_monitor(packet):
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        
        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"[!] ARP欺骗警报: IP {ip} MAC地址变更 ({arp_table[ip]} -> {mac})")
        else:
            arp_table[ip] = mac

def start_monitoring(interface, threshold, interval):
    print(f"启动ARP监控: 网卡{interface} 阈值{threshold}包/秒 间隔{interval}秒")
    try:
        sniff(prn=arp_monitor, filter="arp", iface=interface, store=0)
        return True
    except Exception as e:
        print(f"监控失败: {str(e)}")
        return False

if __name__ == "__main__":
    print("启动ARP欺骗检测器...")
    sniff(prn=arp_monitor, filter="arp", store=0)