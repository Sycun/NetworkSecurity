import requests
from concurrent.futures import ThreadPoolExecutor

common_dirs = [
    'admin', 'wp-admin', 'backup', 'config.php', 
    '.env', '.git/HEAD', 'phpmyadmin', 'test',
    'login', 'secret', 'api', 'debug'
]

def check_directory(url, directory):
    try:
        full_url = f"{url.rstrip('/')}/{directory}"
        response = requests.get(full_url, timeout=5)
        if response.status_code == 200:
            print(f"发现有效路径: {full_url} (状态码:200)")
        elif response.status_code == 403:
            print(f"发现禁止访问路径: {full_url} (状态码:403)")
    except Exception as e:
        pass

if __name__ == "__main__":
    target = input("输入目标URL(例:http://example.com): ")
    print("\n开始目录爆破扫描...")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for dir in common_dirs:
            futures.append(executor.submit(check_directory, target, dir))
        for future in futures:
            future.result()
    print("\n基础目录扫描完成")