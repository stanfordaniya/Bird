import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import argparse
from port_scanner import (
    port_scanner,
    common_ports_scanner,
    resolve_server_name,
    stop_scanning,
    reset_stop_event,
)
from network_sniffer import start_sniffer, stop_sniffer_function
from password_cracker import crack_password, stop_cracking
from keylogger import start_keylogger as kl_start_keylogger, stop_keylogger as kl_stop_keylogger

# Function to start the port scanner tool
def start_port_scanner():
    server_name = entry_server_name.get()
    ip = resolve_server_name(server_name)
    if not ip:
        messagebox.showerror("Error", f"Could not resolve {server_name}")
        return

    scan_type = scan_option.get()
    timeout = int(entry_timeout.get())
    reset_stop_event()
    
    if scan_type == "Range":
        port_start = entry_port_start.get()
        port_end = entry_port_end.get()
        if not port_start or not port_end:
            messagebox.showerror("Error", "Port range is required for Range scan")
            return
        try:
            port_range = (int(port_start), int(port_end))
            thread = threading.Thread(target=port_scanner, args=(ip, port_range, update_port_scanner_output, timeout))
            thread.start()
        except ValueError:
            messagebox.showerror("Error", "Port fields must be integers")
    elif scan_type == "Common Ports":
        thread = threading.Thread(target=common_ports_scanner, args=(ip, update_port_scanner_output, timeout))
        thread.start()
    elif scan_type == "All Ports":
        port_range = (1, 65535)
        thread = threading.Thread(target=port_scanner, args=(ip, port_range, update_port_scanner_output, timeout))
        thread.start()

# Function to update port scanner output
def update_port_scanner_output(message):
    txt_output.insert(tk.END, message + '\n')
    txt_output.see(tk.END)

# Function to stop the port scanner tool
def stop_port_scanner():
    stop_scanning()

# Function to start the network sniffer tool
def start_network_sniffer():
    filter_str = entry_filter.get()
    thread = threading.Thread(target=start_sniffer, args=(filter_str, update_sniffer_output))
    thread.start()

def stop_network_sniffer():
    stop_sniffer_function()

def update_sniffer_output(message):
    txt_sniffer_output.insert(tk.END, message + '\n')
    txt_sniffer_output.see(tk.END)

# Function to start the password cracker tool
def start_password_cracker():
    hash_to_crack = entry_hash.get()
    dictionary_file = entry_dict.get()

    if not hash_to_crack or not dictionary_file:
        messagebox.showerror("Error", "All fields are required for Password Cracker")
        return

    crack_password(hash_to_crack, dictionary_file, update_password_cracker_output)

def stop_password_cracker():
    stop_cracking()

def update_password_cracker_output(message):
    txt_password_output.insert(tk.END, message + '\n')
    txt_password_output.see(tk.END)

# Function to start the keylogger tool
def start_keylogger():
    kl_start_keylogger()

# Function to stop the keylogger tool
def stop_keylogger():
    kl_stop_keylogger()

# Function to deploy the keylogger
def deploy_keylogger():
    target_directory = entry_target_directory.get()
    if not target_directory:
        messagebox.showerror("Error", "Target directory is required for deployment")
        return
    
    try:
        shutil.copy("keylogger.py", target_directory)
        messagebox.showinfo("Success", "Keylogger deployed successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to deploy keylogger: {e}")

# Function to quit the application
def quit_app():
    root.quit()

# Terminal interface (command line)
def terminal_interface():
    parser = argparse.ArgumentParser(description='Bird Cyber Security Tool Application')
    subparsers = parser.add_subparsers(dest='command')

    # Port Scanner Arguments
    port_scanner_parser = subparsers.add_parser('port_scanner', help='Run the port scanner')
    port_scanner_parser.add_argument('server', help='Server name or IP')
    port_scanner_parser.add_argument('--scan-type', choices=['common', 'range', 'all'], default='common', help='Type of scan')
    port_scanner_parser.add_argument('--start-port', type=int, help='Start port for range scan')
    port_scanner_parser.add_argument('--end-port', type=int, help='End port for range scan')
    port_scanner_parser.add_argument('--timeout', type=int, default=1, help='Timeout for port scan in seconds')
    port_scanner_parser.add_argument('--stop', action='store_true', help='Stop the port scanner')

    # Network Sniffer Arguments
    sniffer_parser = subparsers.add_parser('sniffer', help='Run the network sniffer')
    sniffer_parser.add_argument('--filter', help='Custom filter for the sniffer')
    sniffer_parser.add_argument('--stop', action='store_true', help='Stop the network sniffer')

    # Password Cracker Arguments
    cracker_parser = subparsers.add_parser('password_cracker', help='Run the password cracker')
    cracker_parser.add_argument('hash', help='Hash to crack')
    cracker_parser.add_argument('dictionary', help='Path to dictionary file')
    cracker_parser.add_argument('--stop', action='store_true', help='Stop the password cracker')

    # Keylogger Arguments
    keylogger_parser = subparsers.add_parser('keylogger', help='Run the keylogger')
    keylogger_parser.add_argument('--start', action='store_true', help='Start the keylogger')
    keylogger_parser.add_argument('--stop', action='store_true', help='Stop the keylogger')

    args = parser.parse_args()

    if args.command == 'port_scanner':
        if args.stop:
            stop_scanning()
        else:
            ip = resolve_server_name(args.server)
            if not ip:
                print(f"Could not resolve {args.server}")
                return

            reset_stop_event()

            if args.scan_type == 'range':
                if not args.start_port or not args.end_port:
                    print("Start port and end port are required for range scan")
                    return
                port_scanner(ip, (args.start_port, args.end_port), print, args.timeout)
            elif args.scan_type == 'common':
                common_ports_scanner(ip, print, args.timeout)
            elif args.scan_type == 'all':
                port_scanner(ip, (1, 65535), print, args.timeout)
    elif args.command == 'sniffer':
        if args.stop:
            stop_sniffer_function()
        else:
            start_sniffer(args.filter, print)
    elif args.command == 'password_cracker':
        if args.stop:
            stop_cracking()
        else:
            crack_password(args.hash, args.dictionary, print)
    elif args.command == 'keylogger':
        if args.start:
            kl_start_keylogger()
        elif args.stop:
            kl_stop_keylogger()

# Creating the main window
root = tk.Tk()
root.title("Bird Cybersecurity Tool")

# Create the notebook (tabs container)
notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

# Port Scanner Tab
frame_ps = ttk.Frame(notebook, padding=10)
notebook.add(frame_ps, text="Port Scanner")

tk.Label(frame_ps, text="Server Name or IP:").pack()
entry_server_name = tk.Entry(frame_ps)
entry_server_name.pack()

# Scan Type Options
scan_option = tk.StringVar(value="Common Ports")
tk.Radiobutton(frame_ps, text="Common Ports", variable=scan_option, value="Common Ports").pack()
tk.Radiobutton(frame_ps, text="Range", variable=scan_option, value="Range").pack()
tk.Radiobutton(frame_ps, text="All Ports", variable=scan_option, value="All Ports").pack()

# Port Range Fields (shown only if Range is selected)
tk.Label(frame_ps, text="Port Start:").pack()
entry_port_start = tk.Entry(frame_ps)
entry_port_start.pack()
tk.Label(frame_ps, text="Port End:").pack()
entry_port_end = tk.Entry(frame_ps)
entry_port_end.pack()
tk.Label(frame_ps, text="Timeout (seconds):").pack()
entry_timeout = tk.Entry(frame_ps)
entry_timeout.pack()
entry_timeout.insert(0, "1")  # Setting the default value to 1 second

tk.Button(frame_ps, text="Start Port Scanner", command=start_port_scanner).pack()
tk.Button(frame_ps, text="Stop Port Scanner", command=stop_port_scanner).pack()

# Output Text Box for Port Scanner
txt_output = tk.Text(frame_ps, height=10, width=50)
txt_output.pack()

# Network Sniffer Tab
frame_ns = ttk.Frame(notebook, padding=10)
notebook.add(frame_ns, text="Network Sniffer")

tk.Label(frame_ns, text="Filter:").pack()
entry_filter = tk.Entry(frame_ns)
entry_filter.pack()
tk.Button(frame_ns, text="Start Network Sniffer", command=start_network_sniffer).pack()
tk.Button(frame_ns, text="Stop Network Sniffer", command=stop_network_sniffer).pack()

# Output Text Box for Network Sniffer
txt_sniffer_output = tk.Text(frame_ns, height=10, width=50)
txt_sniffer_output.pack()

# Password Cracker Tab
frame_pc = ttk.Frame(notebook, padding=10)
notebook.add(frame_pc, text="Password Cracker")

tk.Label(frame_pc, text="Hash:").pack()
entry_hash = tk.Entry(frame_pc)
entry_hash.pack()
tk.Label(frame_pc, text="Dictionary File:").pack()
entry_dict = tk.Entry(frame_pc)
entry_dict.pack()
tk.Button(frame_pc, text="Start Password Cracker", command=start_password_cracker).pack()
tk.Button(frame_pc, text="Stop Password Cracker", command=stop_password_cracker).pack()

# Output Text Box for Password Cracker
txt_password_output = tk.Text(frame_pc, height=10, width=50)
txt_password_output.pack()

# Keylogger Tab
frame_kl = ttk.Frame(notebook, padding=10)
notebook.add(frame_kl, text="Keylogger")

tk.Button(frame_kl, text="Start Keylogger", command=start_keylogger).pack()
tk.Button(frame_kl, text="Stop Keylogger", command=stop_keylogger).pack()

# Deploy Keylogger Tab
frame_deploy = ttk.Frame(notebook, padding=10)
notebook.add(frame_deploy, text="Deploy Keylogger")

tk.Label(frame_deploy, text="Target Directory:").pack()
entry_target_directory = tk.Entry(frame_deploy)
entry_target_directory.pack()
tk.Button(frame_deploy, text="Deploy Keylogger", command=deploy_keylogger).pack()

# Quit Button
frame_quit = ttk.Frame(notebook, padding=10)
notebook.add(frame_quit, text="Quit")

tk.Button(frame_quit, text="Quit", command=quit_app).pack()

# Check if the script is run with arguments or GUI mode
if __name__ == "__main__":
    if len(os.sys.argv) > 1:
        terminal_interface()
    else:
        root.mainloop()
