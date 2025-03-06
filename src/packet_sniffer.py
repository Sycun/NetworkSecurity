from scapy.all import sniff, Ether, IP, TCP
from scapy.layers import http

def packet_handler(packet):
    import re
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"[+] IP数据包: {src_ip} -> {dst_ip} 协议:{proto}")
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"   TCP端口: {sport} -> {dport}")

        if packet.haslayer(http.HTTPRequest):
            host = packet[http.HTTPRequest].Host.decode()
            path = packet[http.HTTPRequest].Path.decode()
            method = packet[http.HTTPRequest].Method.decode()
            print(f"   HTTP请求: {method} {host}{path}")
            
            if packet.haslayer('Raw'):
                load = packet['Raw'].load.decode()
                cookies = re.search(r'Cookie:.*', load)
                auth = re.search(r'Authorization:.*', load)
                if cookies:
                    print(f"   [!] 发现Cookies: {cookies.group(0)}")
                if auth:
                    print(f"   [!] 发现认证信息: {auth.group(0)}")

        elif packet.haslayer(http.HTTPResponse):
            print(f"   HTTP响应码: {packet[http.HTTPResponse].Status}")
            server_header = re.search(r'Server:.*', str(packet))
            if server_header:
                print(f"   Web服务器信息: {server_header.group(0)}")

if __name__ == "__main__":
    print("启动网络流量嗅探...")
    sniff(prn=packet_handler, store=0, count=50)