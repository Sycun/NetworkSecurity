from scapy.all import sniff
from scapy.layers.tls.all import TLSClientHello
import warnings

def tls_handler(packet):
    if packet.haslayer(TLSClientHello):
        try:
            version = packet[TLSClientHello].version
            ciphers = packet[TLSClientHello].ciphers
            
            print(f"检测到TLS连接: 版本{version_name(version)}")
            
            # 检测不安全协议版本
            if version in [0x0300, 0x0301, 0x0302]:
                print(f"[!] 发现不安全协议版本: {version_name(version)}")
            
            # 检测弱加密套件
            weak_ciphers = [0x0005, 0x0004, 0x000A, 0x002F, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
            if any(c in weak_ciphers for c in ciphers):
                print(f"[!] 发现弱加密套件: {ciphers}")
                
        except Exception as e:
            warnings.warn(f"解析错误: {str(e)}")

def version_name(code):
    versions = {
        0x0300: 'SSLv3',
        0x0301: 'TLSv1.0',
        0x0302: 'TLSv1.1',
        0x0303: 'TLSv1.2',
        0x0304: 'TLSv1.3'
    }
    return versions.get(code, f'未知版本 0x{code:04x}')

if __name__ == "__main__":
    print("启动加密流量分析器...")
    sniff(prn=tls_handler, filter="tcp port 443", store=0)