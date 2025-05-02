import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import json

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

class IDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System - Live Feed")
        self.root.geometry("800x500")

        # Title Label
        title = tk.Label(root, text="Live Network Feature Capture", font=("Arial", 18, "bold"))
        title.pack(pady=10)

        # Scrollable Text Area
        self.output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(expand=True, fill='both', padx=20, pady=10)
        self.output_box.configure(state='disabled')  # Make read-only

        # Start listening for data
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((SERVER_IP, SERVER_PORT))
        server_sock.listen(1)
        conn, addr = server_sock.accept()

        with conn:
            buffer = ""
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                buffer += data.decode()
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self.display_data(line)

    def display_data(self, data_line):
        try:
            parsed = json.loads(data_line)
            pretty_json = json.dumps(parsed, indent=2)
        except json.JSONDecodeError:
            pretty_json = data_line

        self.output_box.configure(state='normal')
        self.output_box.insert(tk.END, pretty_json + "\n\n")
        self.output_box.see(tk.END)  # Auto-scroll
        self.output_box.configure(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_UI(root)
    root.mainloop()

