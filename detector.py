# server_ssh_detector.py
# Sistem untuk mendeteksi serangan SSH Brute Force dengan menganalisis log.

import time
import re
from collections import defaultdict
import os # Untuk memeriksa keberadaan file

# --- Konfigurasi Utama (SESUAIKAN INI!) ---
# Path ke file log SSH. Ini SANGAT PENTING dan berbeda antar sistem operasi!
# Contoh umum:
# - Linux (OpenSSH): "/var/log/auth.log" atau "/var/log/secure"
# - macOS (OpenSSH): "/var/log/system.log" (perlu filter tambahan untuk pesan sshd)
# - Windows (jika menggunakan OpenSSH Server): Cek dokumentasi OpenSSH untuk lokasinya.
LOG_FILE_PATH = "/var/log/system.log"

# Ambang batas (threshold) untuk deteksi
FAILED_LOGIN_THRESHOLD = 5  # Jumlah maksimum upaya login gagal sebelum dianggap brute force
TIME_WINDOW_SECONDS = 300   # Jendela waktu dalam detik untuk menghitung kegagalan (misal, 5 menit = 300 detik)

# --- Penyimpanan Data Dinamis ---
# Dictionary untuk menyimpan catatan upaya login gagal:
# Format: { "ip_address": [timestamp1, timestamp2, ...], ... }
failed_attempts_log = defaultdict(list)

# --- Fungsi Inti ---

def analyze_log_line(log_line):
    """
    Menganalisis satu baris log untuk menemukan upaya login SSH yang gagal dan mengambil IP penyerang.
    PENTING: Pola regex ini MUNGKIN PERLU DISESUAIKAN dengan format log SSH di sistem Anda!
    """
    # Contoh pola regex untuk log sshd di Linux (misal, dari /var/log/auth.log):
    # 1. Gagal password untuk user yang valid:
    #    "Failed password for testuser from 192.168.1.100 port 12345 ssh2"
    # 2. Gagal password untuk user yang tidak valid:
    #    "Failed password for invalid user aneh from 192.168.1.101 port 54321 ssh2"
    # 3. User tidak ada:
    #    "Invalid user BadUser from 192.168.1.102 port 11223"
    # 4. Pesan lain yang mungkin mengindikasikan kegagalan otentikasi (bisa lebih kompleks)
    #    "Connection closed by authenticating user <user> <ip> port <port> [preauth]"

    # Regex yang mencoba menangkap beberapa pola umum kegagalan:
    # Ini mencari "Failed password for ... from <IP>" atau "Invalid user ... from <IP>"
    # \s+ cocok dengan satu atau lebih spasi
    # \S+ cocok dengan satu atau lebih karakter non-spasi
    # (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) menangkap alamat IP
    patterns = [
        re.compile(r"Failed password for (invalid user )?\S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"),
        re.compile(r"Invalid user \S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"),
        re.compile(r"User \S+ from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) not allowed because not listed in AllowUsers"),
        re.compile(r"Connection closed by authenticating user \S+ (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]"), # Indikasi kuat kegagalan berulang
        re.compile(r"Received disconnect from (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+:11: Bye Bye \[preauth\]") # Juga indikasi
    ]

    for pattern in patterns:
        match = pattern.search(log_line)
        if match:
            ip_address = match.group("ip_address")
            # print(f"DEBUG: Ditemukan upaya gagal dari IP: {ip_address} di baris: {log_line.strip()}") # Untuk debugging regex
            return ip_address
    return None # Tidak ditemukan pola kegagalan yang cocok

def check_and_update_failed_attempts(ip_address):
    """
    Memeriksa apakah IP telah melampaui ambang batas serangan brute force.
    Juga membersihkan catatan lama dan menambahkan upaya baru.
    """
    current_time = time.time()

    # 1. Bersihkan timestamp yang sudah kedaluwarsa (di luar TIME_WINDOW_SECONDS)
    valid_attempts_timestamps = []
    for ts in failed_attempts_log[ip_address]:
        if current_time - ts < TIME_WINDOW_SECONDS:
            valid_attempts_timestamps.append(ts)
    failed_attempts_log[ip_address] = valid_attempts_timestamps

    # 2. Tambahkan timestamp upaya gagal saat ini
    failed_attempts_log[ip_address].append(current_time)

    # 3. Periksa apakah jumlah upaya gagal saat ini melebihi ambang batas
    current_failed_count = len(failed_attempts_log[ip_address])
    if current_failed_count >= FAILED_LOGIN_THRESHOLD:
        print(f"🚨 \033[91mPERINGATAN: Potensi serangan SSH Brute Force terdeteksi!\033[0m") # \033[91m adalah kode warna merah
        print(f"    зло IP Penyerang: {ip_address}")
        print(f"   🕒 Jumlah Percobaan Gagal: {current_failed_count} dalam {TIME_WINDOW_SECONDS // 60} menit terakhir.")
        print(f"   📜 Detail Waktu Percobaan (timestamp): {failed_attempts_log[ip_address]}")
        print("-" * 40)
        # Setelah terdeteksi, kita bisa mereset hitungan untuk IP ini agar tidak memberi peringatan terus menerus
        # untuk serangan yang sama, atau implementasikan mekanisme cooldown.
        # Untuk kesederhanaan, kita reset setelah peringatan.
        failed_attempts_log[ip_address] = []
        return True # Serangan terdeteksi
    return False # Belum ada serangan terdeteksi

def monitor_log_file(file_path):
    """
    Membaca baris baru dari file log secara terus menerus (mirip 'tail -f').
    """
    print(f"[*] Memulai pemantauan log SSH: {file_path}")
    print(f"[*] Kriteria Deteksi: {FAILED_LOGIN_THRESHOLD}x gagal login dari 1 IP dalam {TIME_WINDOW_SECONDS // 60} menit.")
    print("-" * 40)

    # Pastikan file log ada sebelum memulai
    if not os.path.exists(file_path):
        print(f"❌ \033[91mERROR: File log tidak ditemukan di '{file_path}'\033[0m")
        print(f"   Pastikan path sudah benar dan server SSH Anda menghasilkan log di sana.")
        print(f"   Anda mungkin perlu menyesuaikan variabel 'LOG_FILE_PATH' di atas.")
        return # Keluar dari fungsi jika file tidak ada

    try:
        with open(file_path, "r") as file:
            # Pindah ke akhir file untuk membaca hanya baris baru
            file.seek(0, 2)
            while True:
                new_line = file.readline()
                if not new_line:
                    time.sleep(0.1)  # Tunggu sebentar jika tidak ada baris baru
                    continue

                # Proses baris baru yang didapat
                attacking_ip = analyze_log_line(new_line)
                if attacking_ip:
                    check_and_update_failed_attempts(attacking_ip)

    except FileNotFoundError:
        # Ini seharusnya sudah ditangani oleh pemeriksaan os.path.exists, tapi sebagai jaga-jaga
        print(f"❌ \033[91mERROR: File log tidak ditemukan saat mencoba membuka: '{file_path}'\033[0m")
    except PermissionError:
        print(f"❌ \033[91mERROR: Izin ditolak untuk membaca file log '{file_path}'.\033[0m")
        print(f"   Coba jalankan skrip ini dengan hak akses root/administrator (misalnya, pakai 'sudo').")
    except KeyboardInterrupt:
        print("\n[*] Pemantauan dihentikan oleh pengguna.")
    except Exception as e:
        print(f"❌ \033[91mERROR: Terjadi kesalahan tak terduga: {e}\033[0m")

# --- Blok Eksekusi Utama ---
if __name__ == "__main__":
    monitor_log_file(LOG_FILE_PATH)