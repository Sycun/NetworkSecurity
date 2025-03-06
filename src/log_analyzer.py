import re
from collections import defaultdict

def analyze_log(log_file):
    error_codes = defaultdict(int)
    ip_activity = defaultdict(int)
    suspicious_paths = set()

    with open(log_file) as f:
        for line in f:
            # 解析常见日志格式
            match = re.search(r'(\d+.\d+.\d+.\d+).*\[(.*)\].*"(\w+)\s([^\s]+).*"\s(\d+)', line)
            if match:
                ip, timestamp, method, path, status = match.groups()
                
                # 统计状态码
                error_codes[status] += 1
                
                # 记录IP活动
                ip_activity[ip] += 1
                
                # 检测可疑路径
                if re.search(r'(phpmyadmin|wp-admin|.env|.git)', path):
                    suspicious_paths.add(f"{ip} 访问可疑路径: {path}")
                
                # 检测异常User-Agent
                if 'curl' not in line and 'Mozilla' not in line:
                    print(f"[!] 可疑User-Agent: {line.split('"')[-2]}")

    print("\n=== 统计结果 ===")
    print(f"异常状态码分布: {dict(error_codes)}")
    
    if suspicious_paths:
        print("\n=== 可疑路径告警 ===")
        for alert in suspicious_paths:
            print(alert)
    
    print("\n=== IP活动统计 ===")
    for ip, count in ip_activity.items():
        if count > 100:  # 单个IP异常高频访问
            print(f"可疑IP {ip} 请求次数: {count}")

if __name__ == "__main__":
    file = input("输入日志文件路径: ")
    analyze_log(file)
    print("\n日志分析完成")