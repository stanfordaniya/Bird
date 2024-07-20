import socket
import threading
from queue import Queue

stop_scan = threading.Event()

def resolve_server_name(server_name):
    try:
        return socket.gethostbyname(server_name)
    except socket.gaierror:
        print(f"Could not resolve {server_name}")
        return None

def port_scanner(ip, port_range, update_function, timeout):
    def scan_port(ip, port, timeout):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return f"Port {port} is open"
        else:
            return f"Port {port} is closed"

    q = Queue()
    for port in range(port_range[0], port_range[1] + 1):
        if stop_scan.is_set():
            update_function("Scan stopped by user")
            return
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            if stop_scan.is_set():
                return
            result = scan_port(ip, port, timeout)
            update_function(result)
            q.task_done()

    threads = []
    for _ in range(10):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def common_ports_scanner(ip, update_function, timeout):
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080
    ]
    port_scanner(ip, (common_ports[0], common_ports[-1]), update_function, timeout)

def stop_scanning():
    stop_scan.set()

def reset_stop_event():
    stop_scan.clear()
