from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import threading

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Guardian Firewall")
        self.root.geometry("1000x600")
        self.root.minsize(600, 400)  # Minimum window size
        self.rules = self.load_rules()
        self.sniffing = False
        self.sniff_thread = None
        self.network_interface = "eth0"  # Replace with your interface (e.g., wlan0)
        self.log_entries = []  # Store log entries for selection

        # Configure style for dark theme
        style = ttk.Style()
        style.configure("TButton", padding=4, font=("Helvetica", 9, "bold"), background="#3c3f41", foreground="white")
        style.configure("TLabel", font=("Helvetica", 9), background="#2b2b2b", foreground="white")
        style.configure("Treeview", font=("Helvetica", 9), rowheight=20, background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e")
        style.configure("Treeview.Heading", font=("Helvetica", 9, "bold"), background="#3c3f41", foreground="white")
        style.configure("TCombobox", font=("Helvetica", 9), background="#1e1e1e", foreground="black", padding=(5, 5, 5, 5))
        style.configure("TEntry", font=("Helvetica", 9), background="#1e1e1e", foreground="black", padding=(5, 5, 5, 5))
        style.map("TCombobox", fieldbackground=[("readonly", "#1e1e1e")], selectbackground=[("readonly", "#1e1e1e")], selectforeground=[("readonly", "black")])
        style.configure("Status.TFrame", background="#1a3c34")  # Dark teal for status bar

        # Create canvas and scrollbar
        self.canvas = tk.Canvas(self.root, bg="#2b2b2b", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Main frame inside canvas
        self.main_frame = ttk.Frame(self.canvas)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")
        self.main_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.root.bind_all("<MouseWheel>", self.on_mouse_wheel)  # Windows
        self.root.bind_all("<Button-4>", self.on_mouse_wheel)  # Linux scroll up
        self.root.bind_all("<Button-5>", self.on_mouse_wheel)  # Linux scroll down
        self.root.configure(bg="#2b2b2b")

        # Header with logo
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=1)
        header_label = ttk.Label(header_frame, text="🛡️ Guardian Firewall", font=("Arial Black", 14, "bold"), background="#2b2b2b", foreground="#ff6200")
        header_label.pack()

        # Status bar
        self.status_var = tk.StringVar(value="Firewall Status: Idle")
        status_frame = ttk.Frame(self.main_frame, style="Status.TFrame")
        status_frame.pack(fill=tk.X, pady=1)
        status_label = ttk.Label(status_frame, textvariable=self.status_var, background="#1a3c34", foreground="white", font=("Helvetica", 10))
        status_label.pack(side=tk.LEFT)
        self.status_indicator = tk.Canvas(status_frame, width=15, height=15, bg="#1a3c34", highlightthickness=0)
        self.status_indicator.create_oval(3, 3, 12, 12, fill="red")
        self.status_indicator.pack(side=tk.LEFT, padx=5)

        # Main content frame
        content_frame = ttk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=1)
        content_frame.configure(style="TFrame")

        # Left panel: Packet log
        log_frame = ttk.LabelFrame(content_frame, text="Live Packet Log", padding=5)
        log_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        self.log_text = tk.Text(log_frame, height=3, width=50, bg="#1e1e1e", fg="white", font=("Courier", 9), wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        self.log_text.bind("<Button-1>", self.show_log_details)

        # Right panel: Rule management
        rule_frame = ttk.LabelFrame(content_frame, text="Rule Management", padding=5)
        rule_frame.grid(row=0, column=1, sticky="nsew", padx=5)

        # Rule table with scrollbar
        tree_frame = ttk.Frame(rule_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=("Action", "Src IP", "Dst IP", "Port", "Protocol"), show="headings")
        self.tree.heading("Action", text="Action")
        self.tree.heading("Src IP", text="Source IP")
        self.tree.heading("Dst IP", text="Dest IP")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.column("Action", width=60)
        self.tree.column("Src IP", width=100)
        self.tree.column("Dst IP", width=100)
        self.tree.column("Port", width=50)
        self.tree.column("Protocol", width=70)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.load_rule_to_inputs)
        self.update_rule_table()

        # Rule input fields (reduced sizes, left-aligned with gaps)
        input_frame = ttk.Frame(rule_frame)
        input_frame.pack(pady=2, fill=tk.X)
        ttk.Label(input_frame, text="Source IP:", width=8, anchor="e").grid(row=0, column=0, padx=2, pady=2, sticky="e")
        self.src_ip_entry = ttk.Entry(input_frame, width=12, justify="left")
        self.src_ip_entry.grid(row=0, column=1, padx=2, pady=4)
        ttk.Label(input_frame, text="Dest IP:", width=8, anchor="e").grid(row=1, column=0, padx=2, pady=2, sticky="e")
        self.dst_ip_entry = ttk.Entry(input_frame, width=12, justify="left")
        self.dst_ip_entry.grid(row=1, column=1, padx=2)
        ttk.Label(input_frame, text="Port:", width=8, anchor="e").grid(row=0, column=2, padx=2, pady=2,  sticky="e")
        self.port_combo = ttk.Combobox(input_frame, values=["", "21", "22", "25", "53", "80", "110", "143", "443", "3389", "5060"], width=6, state="normal", justify="left")
        self.port_combo.grid(row=0, column=3, padx=2,pady=1)
        ttk.Label(input_frame, text="Protocol:", width=8, anchor="e").grid(row=1, column=2, padx=2,pady=2, sticky="e")
        self.protocol_entry = ttk.Combobox(input_frame, values=["TCP", "UDP", "ICMP"], width=6, state="normal", justify="left")
        self.protocol_entry.grid(row=1, column=3, padx=2,pady=1)
        ttk.Label(input_frame, text="Action:", width=8, anchor="e").grid(row=2, column=2, padx=2,pady=2, sticky="e")
        self.action_entry = ttk.Combobox(input_frame, values=["Allow", "Block"], width=6, state="normal", justify="left")
        self.action_entry.grid(row=2, column=3, padx=2,pady=1)

        # Buttons (ordered and aligned)
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=3, column=0, columnspan=4, pady=2)
        ttk.Button(button_frame, text="Add Rule", command=self.add_rule, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Change Rule", command=self.change_rule, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Delete Rule", command=self.delete_rule, width=12).pack(side=tk.LEFT, padx=2)

        # Log details frame
        details_frame = ttk.LabelFrame(self.main_frame, text="Log Details", padding=5)
        details_frame.pack(fill=tk.X, pady=1)
        self.details_text = tk.Text(details_frame, height=4, bg="#1e1e1e", fg="white", font=("Courier", 9), wrap=tk.WORD)
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_text.yview)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_text.config(yscrollcommand=details_scrollbar.set)

        # Bottom panel: Controls
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, pady=1)
        self.toggle_button = ttk.Button(control_frame, text="Start Sniffing", command=self.toggle_sniffing, width=14)
        self.toggle_button.pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Clear iptables", command=self.clear_iptables, width=14).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="View Log", command=self.view_log, width=14).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Refresh Log", command=self.refresh_log, width=14).pack(side=tk.LEFT, padx=2)

        # Configure grid weights for responsiveness
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=0)  # Header
        self.main_frame.rowconfigure(1, weight=0)  # Status
        self.main_frame.rowconfigure(2, weight=1)  # Content
        self.main_frame.rowconfigure(3, weight=0)  # Details
        self.main_frame.rowconfigure(4, weight=0)  # Controls

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_frame, width=self.canvas.winfo_width())

    def on_mouse_wheel(self, event):
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def load_rules(self, file_path="rules.json"):
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            with open(file_path, "w") as file:
                json.dump([], file)
            return []

    def save_rules(self):
        try:
            with open("rules.json", "w") as file:
                json.dump(self.rules, file, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules: {e}")

    def update_rule_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for rule in self.rules:
            self.tree.insert("", tk.END, values=(
                rule["action"].capitalize(),
                rule["src_ip"] or "Any",
                rule["dst_ip"] or "Any",
                rule["port"] or "Any",
                rule["protocol"] or "Any"
            ))

    def log_packet(self, packet, action):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        port = None
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        log_entry = f"[{timestamp}] {action} - Src: {src_ip}, Dst: {dst_ip}, Proto: {proto}, Port: {port}"
        self.log_entries.append((log_entry, packet.summary()))
        self.log_text.tag_configure("block", foreground="red")
        self.log_text.tag_configure("default", foreground="white")
        tag = "block" if action == "BLOCK" else "default"
        self.log_text.insert(tk.END, f"{log_entry}\n", tag)
        self.log_text.see(tk.END)
        self.root.update()
        try:
            with open("log.txt", "a") as log_file:
                log_file.write(f"{log_entry}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write to log file: {e}")

    def apply_iptables_rule(self, rule):
        action = "DROP" if rule["action"].lower() == "block" else "ACCEPT"
        cmd = ["iptables", "-A", "INPUT"]
        if rule["src_ip"]:
            cmd.extend(["-s", rule["src_ip"]])
        if rule["dst_ip"]:
            cmd.extend(["-d", rule["dst_ip"]])
        if rule["protocol"]:
            cmd.extend(["-p", rule["protocol"].lower()])
        if rule["port"] and rule["protocol"] != "ICMP":
            cmd.extend(["--dport", str(rule["port"])])
        cmd.extend(["-j", action])
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to apply iptables rule: {' '.join(cmd)}\nError: {e.stderr}"
            messagebox.showerror("Error", error_msg)
            raise

    def reapply_all_rules(self):
        try:
            subprocess.run(["iptables", "-F"], check=True, capture_output=True, text=True)
            for rule in self.rules:
                self.apply_iptables_rule(rule)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to reapply iptables rules: {e.stderr}")

    def clear_iptables(self):
        try:
            subprocess.run(["iptables", "-F"], check=True, capture_output=True, text=True)
            messagebox.showinfo("Success", "iptables rules cleared!")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to clear iptables rules: {e.stderr}")

    def view_log(self):
        try:
            with open("log.txt", "r") as log_file:
                logs = log_file.readlines()
            log_window = tk.Toplevel(self.root)
            log_window.title("Log File")
            log_window.geometry("600x400")
            log_window.configure(bg="#2b2b2b")
            text = tk.Text(log_window, bg="#1e1e1e", fg="white", font=("Courier", 9), wrap=tk.WORD)
            text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar = ttk.Scrollbar(log_window, orient=tk.VERTICAL, command=text.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text.config(yscrollcommand=scrollbar.set)
            text.tag_configure("block", foreground="red")
            text.tag_configure("default", foreground="white")
            for log in logs:
                if log.strip():
                    action = log.split(" ")[1]
                    tag = "block" if "BLOCK" in action else "default"
                    text.insert(tk.END, log, tag)
            if not logs:
                text.insert(tk.END, "No logs available.")
        except FileNotFoundError:
            messagebox.showerror("Error", "Log file not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read log file: {e}")

    def refresh_log(self):
        try:
            self.log_text.delete(1.0, tk.END)
            self.log_entries = []
            with open("log.txt", "r") as log_file:
                logs = log_file.readlines()
            for log in logs:
                if log.strip():
                    action = log.split(" ")[1]
                    tag = "block" if "BLOCK" in action else "default"
                    self.log_text.insert(tk.END, log, tag)
            self.log_text.see(tk.END)
            self.root.update()
        except FileNotFoundError:
            messagebox.showerror("Error", "Log file not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh log: {e}")

    def show_log_details(self, event):
        self.details_text.delete(1.0, tk.END)
        region = self.log_text.tag_nextrange("block", 1.0) or self.log_text.tag_nextrange("default", 1.0)
        if not region:
            return
        index = self.log_text.index(f"{region[0]} linestart")
        line_num = int(index.split(".")[0])
        if line_num <= len(self.log_entries):
            log_entry, packet_summary = self.log_entries[line_num - 1]
            details = f"Log Entry: {log_entry}\nPacket Details: {packet_summary}"
            self.details_text.insert(tk.END, details)
            self.details_text.see(tk.END)

    def load_rule_to_inputs(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        index = self.tree.index(selected[0])
        rule = self.rules[index]
        self.src_ip_entry.delete(0, tk.END)
        self.src_ip_entry.insert(0, rule["src_ip"] or "")
        self.dst_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.insert(0, rule["dst_ip"] or "")
        self.port_combo.delete(0, tk.END)
        self.port_combo.insert(0, str(rule["port"]) if rule["port"] else "")
        self.protocol_entry.set(rule["protocol"] or "")
        self.action_entry.set(rule["action"] or "")

    def match_packet(self, packet, rule):
        if IP not in packet:
            return False
        pkt_src = packet[IP].src
        pkt_dst = packet[IP].dst
        pkt_proto = packet[IP].proto
        pkt_port = None
        if TCP in packet:
            pkt_port = packet[TCP].dport
        elif UDP in packet:
            pkt_port = packet[UDP].dport

        if rule["src_ip"] and rule["src_ip"] != pkt_src:
            return False
        if rule["dst_ip"] and rule["dst_ip"] != pkt_dst:
            return False
        if rule["protocol"] and rule["protocol"].upper() != ("TCP" if pkt_proto == 6 else "UDP" if pkt_proto == 17 else "ICMP" if pkt_proto == 1 else None):
            return False
        if rule["port"] and pkt_port and rule["port"] != pkt_port:
            return False
        return True

    def packet_callback(self, packet):
        print(f"Packet captured: {packet.summary()}")
        action = "NO_RULE"
        for rule in self.rules:
            if self.match_packet(packet, rule):
                action = rule["action"].upper()
                break
        self.log_packet(packet, action)

    def sniff_packets(self):
        while self.sniffing:
            try:
                sniff(prn=self.packet_callback, count=1, store=0, filter="ip", iface=self.network_interface, timeout=2)
                self.root.update()
            except Exception as e:
                print(f"Sniffing error: {e}")
                self.log_text.insert(tk.END, f"Sniffing error: {e}\n", "default")
                self.log_text.see(tk.END)
                self.root.update()

    def toggle_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.status_var.set("Firewall Status: Sniffing")
            self.status_indicator.delete("all")
            self.status_indicator.create_oval(3, 3, 12, 12, fill="green")
            self.toggle_button.configure(text="Stop Sniffing")
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()
        else:
            self.sniffing = False
            self.status_var.set("Firewall Status: Idle")
            self.status_indicator.delete("all")
            self.status_indicator.create_oval(3, 3, 12, 12, fill="red")
            self.toggle_button.configure(text="Start Sniffing")

    def add_rule(self):
        rule = {
            "action": self.action_entry.get().lower(),
            "src_ip": self.src_ip_entry.get() or None,
            "dst_ip": self.dst_ip_entry.get() or None,
            "port": int(self.port_combo.get()) if self.port_combo.get().isdigit() else None,
            "protocol": self.protocol_entry.get().upper() or None
        }
        if rule["action"] not in ["allow", "block"]:
            messagebox.showerror("Error", "Action must be 'allow' or 'block'!")
            return
        if rule["port"] and (rule["port"] < 0 or rule["port"] > 65535):
            messagebox.showerror("Error", "Port must be between 0 and 65535!")
            return
        self.rules.append(rule)
        self.save_rules()
        self.apply_iptables_rule(rule)
        self.update_rule_table()
        messagebox.showinfo("Success", "Rule added successfully!")
        self.clear_input_fields()

    def change_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a rule to change!")
            return
        index = self.tree.index(selected[0])
        rule = {
            "action": self.action_entry.get().lower(),
            "src_ip": self.src_ip_entry.get() or None,
            "dst_ip": self.dst_ip_entry.get() or None,
            "port": int(self.port_combo.get()) if self.port_combo.get().isdigit() else None,
            "protocol": self.protocol_entry.get().upper() or None
        }
        if rule["action"] not in ["allow", "block"]:
            messagebox.showerror("Error", "Action must be 'allow' or 'block'!")
            return
        if rule["port"] and (rule["port"] < 0 or rule["port"] > 65535):
            messagebox.showerror("Error", "Port must be between 0 and 65535!")
            return
        self.rules[index] = rule
        self.save_rules()
        self.reapply_all_rules()
        self.update_rule_table()
        messagebox.showinfo("Success", "Rule changed successfully!")
        self.clear_input_fields()

    def delete_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a rule to delete!")
            return
        index = self.tree.index(selected[0])
        self.rules.pop(index)
        self.save_rules()
        self.reapply_all_rules()
        self.update_rule_table()
        messagebox.showinfo("Success", "Rule deleted successfully!")
        self.clear_input_fields()

    def clear_input_fields(self):
        self.src_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.delete(0, tk.END)
        self.port_combo.delete(0, tk.END)
        self.port_combo.set("")
        self.protocol_entry.set("")
        self.action_entry.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
