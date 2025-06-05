# detector.py 
# Sistem deteksi SSH Brute Force dengan kombinasi GUI dasar menggunakan lib Tkinter.

import tkinter as tk
# Untuk bikin tampilan jendela, tombol, tulisan (GUI). Kita panggil 'tk'.

from tkinter import scrolledtext, messagebox
# scrolledtext: Kotak tulisan yang bisa digulir.
# messagebox: Kotak pesan pop-up (info, error, peringatan).

import tkinter.ttk as ttk
# Sama seperti 'tk' yang atas, tapi untuk elemen GUI yang tampilannya lebih baru. dipanggil panggil 'ttk'.

import threading
# Biar program bisa kerjakan banyak hal sekaligus (misal, pantau log sambil GUI tetap jalan).

import time
# Untuk urusan waktu (misal, dikasi jeda).

import re
# Untuk cari pola tulisan di dalam teks (misal, cari IP di log).

from collections import defaultdict
# Kamus (dictionary) pintar yang otomatis kasih nilai awal kalau belum ada.

import os
# Untuk kerja dengan file dan folder di komputer (misal, cek file ada atau tidak).

import queue
# Untuk bikin "antrian" pesan aman antar bagian program yang jalan bareng.

# --- Konfigurasi Utama (Sama seperti di server_ssh_detector.py) ---
# Di Ubuntu VM, ini seharusnya sudah benar
LOG_FILE_PATH_DEFAULT = "/var/log/auth.log" # Sesuaikan jika perlu untuk demo
FAILED_LOGIN_THRESHOLD_DEFAULT = 5
TIME_WINDOW_SECONDS_DEFAULT = 300

# --- Variabel Global untuk Kontrol Thread dan GUI ---
monitoring_thread = None
stop_monitoring_flag = threading.Event() # Event untuk memberi sinyal stop ke thread
log_queue = queue.Queue() # Antrian untuk mengirim pesan dari thread backend ke GUI

# --- Logika Deteksi Inti
failed_attempts_log = defaultdict(list)
current_log_file_path = LOG_FILE_PATH_DEFAULT
current_failed_login_threshold = FAILED_LOGIN_THRESHOLD_DEFAULT
current_time_window_seconds = TIME_WINDOW_SECONDS_DEFAULT

def analyze_log_line(log_line):
    """Menganalisis satu baris log untuk menemukan upaya login SSH yang gagal dan mengambil IP penyerang."""
    patterns = [
        re.compile(r"Failed password for (invalid user )?\S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"),
        re.compile(r"Invalid user \S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"),
        re.compile(r"User \S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) not allowed because not listed in AllowUsers"),
        re.compile(r"Connection closed by authenticating user \S+ (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]"),
        re.compile(r"Received disconnect from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+:11: Bye Bye \[preauth\]")
    ]
    for pattern in patterns:
        match = pattern.search(log_line)
        if match:
            ip_address = match.group("ip_address")
            return ip_address
    return None

def check_and_update_failed_attempts(ip_address):
    """
    Memeriksa apakah IP telah melampaui ambang batas serangan brute force.
    Mengembalikan pesan alert jika terdeteksi, jika tidak None.
    """
    global failed_attempts_log, current_failed_login_threshold, current_time_window_seconds
    current_time = time.time()

    valid_attempts_timestamps = [ts for ts in failed_attempts_log[ip_address] if current_time - ts < current_time_window_seconds]
    failed_attempts_log[ip_address] = valid_attempts_timestamps
    failed_attempts_log[ip_address].append(current_time)

    current_failed_count = len(failed_attempts_log[ip_address])
    if current_failed_count >= current_failed_login_threshold:
        alert_message = (
            f"🚨 PERINGATAN: Potensi serangan SSH Brute Force terdeteksi!\n"
            f"    🌐 IP Penyerang: {ip_address}\n"
            f"    🕒 Jumlah Percobaan Gagal: {current_failed_count} dalam {current_time_window_seconds // 60} menit terakhir.\n"
            # f"    📜 Detail Waktu Percobaan (timestamp): {failed_attempts_log[ip_address]}\n" # Mungkin terlalu verbose untuk GUI utama
            f"----------------------------------------"
        )
        failed_attempts_log[ip_address] = [] # Reset setelah peringatan
        return alert_message
    return None

def monitor_log_file_thread_func():
    """Fungsi yang akan dijalankan di thread terpisah untuk memantau log."""
    global failed_attempts_log, stop_monitoring_flag, current_log_file_path, log_queue

    failed_attempts_log = defaultdict(list)
    stop_monitoring_flag.clear()

    log_queue.put(f"[*] Memulai pemantauan log SSH: {current_log_file_path}")
    log_queue.put(f"[*] Kriteria Deteksi: {current_failed_login_threshold}x gagal dalam {current_time_window_seconds // 60} menit.")

    # Hapus logika pembuatan file dummy jika tidak diinginkan dari permintaan awal
    if not os.path.exists(current_log_file_path):
        log_queue.put(f"❌ ERROR: File log tidak ditemukan di '{current_log_file_path}'")
        return

    try:
        with open(current_log_file_path, "r") as file:
            file.seek(0, 2)
            while not stop_monitoring_flag.is_set():
                new_line = file.readline()
                if not new_line:
                    time.sleep(0.1)
                    continue
                
                # Untuk mengurangi keramaian, baris log mentah tidak dikirim ke GUI kecuali diinginkan
                # log_queue.put(f"LOG: {new_line.strip()}") 

                attacking_ip = analyze_log_line(new_line)
                if attacking_ip:
                    alert = check_and_update_failed_attempts(attacking_ip)
                    if alert:
                        log_queue.put(alert)
            log_queue.put("[*] Pemantauan dihentikan.")
    except FileNotFoundError:
        log_queue.put(f"❌ ERROR: File log tidak ditemukan saat mencoba membuka: '{current_log_file_path}'")
    except PermissionError:
        log_queue.put(f"❌ ERROR: Izin ditolak membaca '{current_log_file_path}'. Pertimbangkan hak akses.")
    except Exception as e:
        log_queue.put(f"❌ ERROR: Terjadi kesalahan tak terduga di thread: {e}")


# --- Fungsi-fungsi untuk GUI (Backend tidak diubah) ---
def start_monitoring():
    global monitoring_thread, stop_monitoring_flag

    #if monitoring_thread and monitoring_thread.is_alive():
        #messagebox.showwarning("Peringatan", "Pemantauan sudah berjalan!", parent=root)
        #return

    monitoring_thread = threading.Thread(target=monitor_log_file_thread_func, daemon=True)
    monitoring_thread.start()
    status_label.config(text="Status: Berjalan", foreground="#4CAF50") # Hijau cerah
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

def stop_monitoring():
    global stop_monitoring_flag
    if monitoring_thread and monitoring_thread.is_alive():
        stop_monitoring_flag.set()
        status_label.config(text="Status: Dihentikan", foreground="#F44336") # Merah cerah
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
    else:
        # Jika belum pernah berjalan, pastikan state tombol konsisten
        status_label.config(text="Status: Dihentikan", foreground="#F44336")
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        #if not monitoring_thread: # Hanya tampilkan jika memang belum pernah dimulai
             #messagebox.showinfo("Info", "Pemantauan belum dimulai.", parent=root)


def check_log_queue():
    """Memeriksa antrian log dari thread backend dan update GUI."""
    try:
        while True:
            message = log_queue.get_nowait()
            log_text_area.config(state=tk.NORMAL) # Aktifkan untuk insert
            
            # Terapkan tag berdasarkan isi pesan
            if "PERINGATAN:" in message:
                log_text_area.insert(tk.END, message + "\n", "alert")
            elif "ERROR:" in message:
                log_text_area.insert(tk.END, message + "\n", "error")
            elif "[*]" in message:
                 log_text_area.insert(tk.END, message + "\n", "info")
            else:
                log_text_area.insert(tk.END, message + "\n") # Pesan biasa tanpa tag khusus

            log_text_area.config(state=tk.DISABLED) # Nonaktifkan lagi
            log_text_area.see(tk.END)
    except queue.Empty:
        pass
    finally:
        root.after(100, check_log_queue)

def on_closing():
    """Fungsi yang dijalankan saat jendela GUI ditutup."""
    # if messagebox.askokcancel("Keluar", "Apakah Anda yakin ingin keluar?", parent=root):
        # Coba hentikan thread jika berjalan dengan lebih sabar
    if monitoring_thread and monitoring_thread.is_alive():
        stop_monitoring_flag.set()
        # Tidak menggunakan join() secara agresif di sini untuk menghindari GUI freeze
        # daemon=True pada thread seharusnya membantu penutupan.
    root.destroy()

# --- Setup GUI Utama ---
root = tk.Tk()
root.title("🛡 SSH Brute Force Detector")
root.geometry("750x550") # Sedikit penyesuaian ukuran
root.configure(bg="#263238") # Warna latar belakang utama (Blue Grey Darken-3)

# Style untuk ttk widgets
style = ttk.Style()
style.theme_use('clam') # 'clam', 'alt', 'default', 'classic' (clam seringkali terlihat baik)

# Kustomisasi style tombol umum
style.configure("TButton",
                font=("Helvetica", 10, "bold"), # Font yang lebih umum tersedia
                padding=(10, 5), # (padding horizontal, padding vertikal)
                relief="flat",
                borderwidth=0)
style.map("TButton",
          background=[('active', '#455A64'), ('!disabled', '#546E7A')], # Blue Grey Darken-1, Blue Grey Darken-2
          foreground=[('!disabled', 'white')],
          relief=[('pressed', 'sunken')])

# Style spesifik untuk tombol Start (Aksen)
style.configure("Accent.TButton", foreground="white", background="#4CAF50") # Hijau
style.map("Accent.TButton", background=[('active', '#388E3C')]) # Hijau lebih gelap

# Style spesifik untuk tombol Stop (Bahaya)
style.configure("Danger.TButton", foreground="white", background="#F44336") # Merah
style.map("Danger.TButton", background=[('active', '#D32F2F')]) # Merah lebih gelap


# --- Frame Utama untuk Konten ---
main_content_frame = tk.Frame(root, bg="#263238", padx=20, pady=20)
main_content_frame.pack(fill=tk.BOTH, expand=True)

# Judul Aplikasi
title_label = tk.Label(main_content_frame, text="Detektor Serangan SSH Brute Force",
                       font=("Helvetica", 18, "bold"), fg="white", bg="#263238", pady=10)
title_label.pack(fill=tk.X)


# Frame untuk tombol dan status
control_frame = ttk.Frame(main_content_frame, style="TFrame", padding=(0, 10, 0, 15)) # (kiri, atas, kanan, bawah)
style.configure("TFrame", background="#263238") # Pastikan background TFrame sesuai
control_frame.pack(fill=tk.X)

start_button = ttk.Button(control_frame, text="Mulai Pemantauan", command=start_monitoring, style="Accent.TButton")
start_button.pack(side=tk.LEFT, padx=(0,10)) # Padding kanan 10

stop_button = ttk.Button(control_frame, text="Hentikan Pemantauan", command=stop_monitoring, style="Danger.TButton", state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=(0,10))

status_label = tk.Label(control_frame, text="Status: Dihentikan", font=("Helvetica", 10, "italic"),
                        fg="#F44336", bg="#37474F", # Blue Grey Darken-2 untuk background status
                        padx=10, pady=6, relief="groove", borderwidth=1)
status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)


# Area teks untuk menampilkan log dan peringatan
log_area_frame = tk.Frame(main_content_frame, bg="#1C252A", relief="sunken", bd=1) # Warna lebih gelap untuk frame log
log_area_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5)) # Padding bawah sedikit

log_text_area = scrolledtext.ScrolledText(log_area_frame, wrap=tk.WORD,
                                          state=tk.DISABLED, # Awalnya disabled
                                          height=18, # Sesuaikan tinggi jika perlu
                                          bg="#1C252A", # Dark background untuk area teks
                                          fg="#CFD8DC", # Light foreground (Blue Grey Lighten-4)
                                          font=("Courier New", 10), # Font monospace
                                          relief="flat", # Hilangkan border default ScrolledText
                                          padx=10, pady=10,
                                          borderwidth=0)
log_text_area.pack(fill=tk.BOTH, expand=True)

# Definisikan tag untuk pewarnaan teks di ScrolledText
log_text_area.tag_config("alert", foreground="#EF9A9A", font=("Courier New", 10, "bold")) # Merah muda untuk alert
log_text_area.tag_config("error", foreground="#FFCC80", font=("Courier New", 10, "bold")) # Oranye muda untuk error
log_text_area.tag_config("info", foreground="#80CBC4", font=("Courier New", 10))       # Teal muda untuk info

# Menangani penutupan jendela
root.protocol("WM_DELETE_WINDOW", on_closing)

# Panggil stop_monitoring di awal untuk set state tombol & label yang benar
stop_monitoring()

# Mulai memeriksa antrian log secara periodik
root.after(100, check_log_queue)

# Jalankan loop utama Tkinter
root.mainloop()
