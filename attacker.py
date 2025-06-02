# attacker_simulation.py
# Skrip untuk mensimulasikan serangan SSH Brute Force untuk keperluan pengujian.

import subprocess
import time

# --- Konfigurasi Serangan (SESUAIKAN JIKA PERLU) ---
TARGET_IP = "127.0.0.1"  # Alamat IP server SSH yang akan diserang (biasanya localhost untuk tes)
# Gunakan username yang ADA di sistem target untuk simulasi 'Failed password'
# atau username yang TIDAK ADA untuk simulasi 'Invalid user'.
TARGET_USER = "gandisuastika" # Ganti dengan username yang tidak ada, atau user valid dengan password salah
NUM_ATTEMPTS = 7         # Jumlah upaya login yang akan dilakukan
DELAY_BETWEEN_ATTEMPTS_SECONDS = 0.5 # Jeda waktu antar upaya login (dalam detik)

print(f"--- Simulasi Serangan SSH Brute Force Dimulai ---")
print(f"🎯 Target: {TARGET_USER}@{TARGET_IP}")
print(f"💥 Jumlah Percobaan: {NUM_ATTEMPTS}")
print(f"⏳ Jeda Antar Percobaan: {DELAY_BETWEEN_ATTEMPTS_SECONDS} detik")
print("-" * 40)

# Perintah SSH dasar. Opsi ditambahkan untuk membuatnya non-interaktif dan cepat gagal.
# "-o StrictHostKeyChecking=no": Menonaktifkan pemeriksaan kunci host (berguna untuk tes lokal)
# "-o UserKnownHostsFile=/dev/null": Tidak menggunakan file known_hosts
# "-o PasswordAuthentication=yes": Coba paksa otentikasi password (meskipun mungkin di-override server)
# "-o NumberOfPasswordPrompts=1": Hanya izinkan 1 kali prompt password (agar cepat gagal jika salah)
# "-o ConnectTimeout=5": Batas waktu koneksi
# "exit": Perintah dummy yang dijalankan jika login (secara ajaib) berhasil, agar koneksi segera ditutup.
ssh_command_template = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PasswordAuthentication=yes", # Eksplisit minta auth password
    "-o", "PreferredAuthentications=password", # Prioritaskan password
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=5",
    f"{TARGET_USER}@{TARGET_IP}",
    "exit" # Perintah sederhana untuk dijalankan jika login (seharusnya tidak akan)
]

for i in range(1, NUM_ATTEMPTS + 1):
    print(f"[*] Melakukan percobaan ke-{i}/{NUM_ATTEMPTS}...")
    try:
        # Kita menggunakan subprocess.run()
        # 'capture_output=True' untuk menangkap stdout/stderr (tidak ditampilkan langsung)
        # 'text=True' untuk output sebagai string
        # 'timeout' untuk mencegah proses menggantung
        # 'check=False' karena kita EKSPEK perintah ssh ini gagal (itu tujuan simulasi)
        process_result = subprocess.run(
            ssh_command_template,
            capture_output=True,
            text=True,
            timeout=10, # Timeout untuk keseluruhan proses ssh
            check=False
        )

        # print(f"    Stdout: {process_result.stdout.strip()}")
        # print(f"    Stderr: {process_result.stderr.strip()}")
        if "Permission denied" in process_result.stderr or \
           "incorrect password" in process_result.stderr.lower() or \
           process_result.returncode != 0 : # Kode return non-nol biasanya indikasi error/gagal
            print(f"    ✔️ Percobaan ke-{i} gagal seperti yang diharapkan.")
        else:
            print(f"    ⚠️ Percobaan ke-{i} sepertinya tidak gagal sesuai harapan (atau berhasil?). Cek log.")

    except subprocess.TimeoutExpired:
        print(f"    ❌ Percobaan ke-{i} timeout.")
    except Exception as e:
        print(f"    ❌ Error tak terduga saat percobaan ke-{i}: {e}")

    time.sleep(DELAY_BETWEEN_ATTEMPTS_SECONDS)

print("-" * 40)
print(f"--- Simulasi Serangan Selesai ---")