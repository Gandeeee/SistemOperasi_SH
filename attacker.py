# attacker.py
# Skrip untuk mensimulasikan serangan SSH Brute Force secara otomatis

import subprocess
# Untuk menjalankan perintah atau program lain dari dalam kode Python kita
# (misalnya, menjalankan perintah 'ssh' untuk simulasi serangan).

import time
# Untuk semua hal yang berhubungan dengan waktu
# (misalnya, memberi jeda `time.sleep()` antar percobaan serangan).

# --- Konfigurasi Serangan (SESUAIKAN JIKA PERLU) ---
# Atur ke "127.0.0.1" jika menjalankan ini di VM yang sama dengan detektor.
# Jika detektor di VM lain, ganti dengan IP VM detektor tersebut.
TARGET_IP = "127.0.0.1"

# untuk simulasi 'Failed password', atau username yang TIDAK ADA
# untuk simulasi 'Invalid user'.
TARGET_USER = "gandhisuastika"  # Contoh: "userlinuxsaya" atau "user_tidak_ada"

NUM_ATTEMPTS = 20         # Jumlah upaya login yang akan dilakukan
DELAY_BETWEEN_ATTEMPTS_SECONDS = 0.5 # Jeda waktu antar upaya login (dalam detik)

# ----------------------------------------------------------------------------
print(f"--- Simulasi Serangan SSH Brute Force Otomatis Dimulai ---")
print(f"🎯 Target Server: {TARGET_IP}")
print(f"👤 Target User  : {TARGET_USER}")
print(f"💥 Jumlah Percobaan: {NUM_ATTEMPTS}")
print(f"⏳ Jeda Antar Percobaan: {DELAY_BETWEEN_ATTEMPTS_SECONDS} detik")
print("-" * 50)

# Perintah SSH dasar. Opsi ditambahkan untuk membuatnya non-interaktif dan cepat gagal.
# -o BatchMode=yes: Mode non-interaktif, jangan pernah meminta password atau konfirmasi.
# -o ConnectTimeout=5: Batas waktu koneksi.
# -o StrictHostKeyChecking=no: Menonaktifkan pemeriksaan kunci host (berguna untuk tes).
# -o UserKnownHostsFile=/dev/null: Tidak menggunakan file known_hosts.
# "exit": Perintah dummy yang dijalankan jika login (secara ajaib) berhasil,
#         agar koneksi segera ditutup.
# Menggunakan BatchMode=yes adalah cara yang lebih kuat untuk memastikan non-interaktivitas.
ssh_command_template = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    f"{TARGET_USER}@{TARGET_IP}",
    "exit" # Perintah sederhana untuk dijalankan jika login (seharusnya tidak akan)
]

successful_failures = 0
for i in range(1, NUM_ATTEMPTS + 1):
    print(f"[*] Melakukan percobaan ke-{i} dari {NUM_ATTEMPTS} ke {TARGET_USER}@{TARGET_IP}...")
    try:
        # Jalankan perintah ssh.
        # 'capture_output=True' untuk menangkap stdout/stderr (tidak ditampilkan langsung).
        # 'text=True' untuk output sebagai string.
        # 'timeout' untuk mencegah proses menggantung terlalu lama.
        # 'check=False' karena kita EKSPEK perintah ssh ini gagal (itu tujuan simulasi).
        process_result = subprocess.run(
            ssh_command_template,
            capture_output=True,
            text=True,
            timeout=10, # Timeout untuk keseluruhan proses ssh
            check=False # Jangan error jika ssh gagal (itu yang kita mau)
        )

        # Analisis sederhana berdasarkan kode return atau output error
        # Kode return non-nol dari ssh biasanya indikasi error/gagal.
        if process_result.returncode != 0:
            print(f"    ✔️ Percobaan ke-{i} gagal seperti yang diharapkan (return code: {process_result.returncode}).")
            successful_failures += 1
        else:
            # Ini seharusnya tidak terjadi jika TARGET_USER atau otentikasi memang salah
            print(f"    ⚠️ Percobaan ke-{i} sepertinya TIDAK GAGAL (return code: 0). Ini tidak diharapkan.")
            if process_result.stdout:
                print(f"      Output SSH: {process_result.stdout.strip()}")


    except subprocess.TimeoutExpired:
        print(f"    ❌ Percobaan ke-{i} timeout setelah 10 detik.")
    except Exception as e:
        print(f"    ❌ Error tak terduga saat percobaan ke-{i}: {e}")

    # Jeda sebelum percobaan berikutnya
    if i < NUM_ATTEMPTS: # Tidak perlu jeda setelah percobaan terakhir
        time.sleep(DELAY_BETWEEN_ATTEMPTS_SECONDS)

print("-" * 50)
print(f"--- Simulasi Serangan Selesai ---")
print(f"Total percobaan yang (diharapkan) gagal: {successful_failures} dari {NUM_ATTEMPTS}")
