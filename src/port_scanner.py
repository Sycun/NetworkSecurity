import socket
import multiprocessing
from multiprocessing import Queue
import platform

def port_scan(target, port, result_queue):
    sock_type = socket.SOCK_STREAM
    if platform.system() == 'Linux':
        sock_type = socket.SOCK_STREAM | socket.SOCK_NONBLOCK
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"端口 {port} 开放")
        sock.close()
    except Exception as e:
        pass

def worker(queue):
    while True:
        port = queue.get()
        port_scan(target, port)
        queue.task_done()

def main(目标IP: str, 端口范围: str, 扫描类型: str, 超时时间: str):
    target = 目标IP
    start_port, end_port = map(int, 端口范围.split('-'))
    
    queue = multiprocessing.Queue()
    for _ in range(50):
        t = multiprocessing.Process(target=worker, args=(queue,))
        t.daemon = True
        t.start()
    
    for port in range(start_port, end_port+1):
        queue.put(port)
    
    queue.join()

if __name__ == "__main__":
    main(目标IP=input("输入目标IP: "),
         端口范围=input("端口范围: "),
         扫描类型=input("扫描类型: "),
         超时时间=input("超时时间: "))