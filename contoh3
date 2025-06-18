#!/bin/bash

# ==============================================================================
# DEFINISI WARNA (ANSI ESCAPE CODES)
# ==============================================================================
# Di bagian ini, saya mendefinisikan semua variabel yang akan saya gunakan untuk 
# memberikan warna dan gaya pada output teks di terminal linu

# --- Gaya Teks ---
# Deklarasi ini berisi kode untuk memberikan format khusus pada teks, tanpa mengubah warnanya
BOLD='\e[1m'         # Variabel untuk membuat teks menjadi tebal (bold)
DIM='\e[2m'          # Variabel untuk membuat teks menjadi redup (dim/faint)
UNDERLINE='\e[4m'    # Variabel untuk memberikan garis bawah pada teks

# --- Warna Teks Standar ---
# Deklarasi Ini adalah 8 warna dasar yang umumnya didukung oleh semua terminal
BLACK='\e[30m'       # Kode untuk warna teks hitam
RED='\e[31m'         # Kode untuk warna teks merah
GREEN='\e[32m'       # Kode untuk warna teks hijau
YELLOW='\e[33m'      # Kode untuk warna teks kuning
BLUE='\e[34m'        # Kode untuk warna teks biru
MAGENTA='\e[35m'     # Kode untuk warna teks magenta (ungu)
CYAN='\e[36m'        # Kode untuk warna teks cyan (biru muda)
WHITE='\e[37m'       # Kode untuk warna teks putih

# Kode ini merupakan delrasi kode warna kustom (jingga/oranye) yang saya ambil dari palet 256 warna
# agar tampilannya lebih unik dibandingkan warna standar
ORANGE='\e[38;5;208m' 

# --- Warna Teks Cerah ---
# Ini adalah versi warna standar yang lebih cerah atau "high-intensity"
BRIGHT_RED='\e[91m'      # Kode untuk warna teks merah cerah
BRIGHT_GREEN='\e[92m'    # Kode untuk warna teks hijau cerah
BRIGHT_YELLOW='\e[93m'   # Kode untuk warna teks kuning cerah
BRIGHT_BLUE='\e[94m'     # Kode untuk warna teks biru cerah
BRIGHT_MAGENTA='\e[95m'  # Kode untuk warna teks magenta cerah
BRIGHT_CYAN='\e[96m'     # Kode untuk warna teks cyan cerah

# --- Reset ---
# variabel ini sangat penting, di sini digunakan untuk mengembalikan gaya dan 
# warna teks ke pengaturan default terminal setelah saya selesai mewarnai bagian tertentu
# Ini mencegah "color bleed" atau warna yang menyebar ke baris berikutnya yang tidak diinginkan
NC='\e[0m' # No Color - kembali ke default

# ==============================================================================
# FUNGSI-FUNGSI PEMBANTU
# ==============================================================================

# FUNGSI: tampilkan_judul
# TUJUAN: Mencetak judul dengan gaya ciamik di terminal
# ARGUMEN: $1 -> Teks yang ingin dijadikan judul
# Fungsi untuk menampilkan judul
tampilkan_judul() {
    # Langkah pertama, apakah perintah 'figlet' ada di sistem
    # Redirect output &> /dev/null ini untuk menyembunyikan pesan jika 'figlet' tidak ada
    if command -v figlet &> /dev/null; then
        # Jika 'figlet' ditemukan, saya akan menggunakannya untuk output yang lebih baik
        # Mengatur warna teks menjadi Cyan Cerah sebelum mencetak judul
        printf "${BRIGHT_CYAN}"
        # Memanggil figlet untuk mengubah teks dari argumen pertama ($1) menjadi seni ASCII dengan font slant
        figlet -f slant "$1"
        # Setelah selesai, warna segera dikembalikan ke default agar tidak mempengaruhi teks lain
        printf "${NC}"
    else
        # Ini case blok alternatif jika 'figlet' tidak terinstal di sistem linux
        # skrip tetap berfungsi dan menampilkan judul yang rapi meskipun tanpa figle
        # Menyimpan teks judul dari argumen ke variabel lokal agar mudah dikelola
        local judul_teks="$1"
        # Menghitung panjang karakter dari teks judul untuk membuat bingkai yang pas
        local panjang_judul=${#judul_teks}
        # Membuat baris pembatas ('######') secara dinamis yang panjangnya disesuaikan dengan panjang judul
        local garis_batas=$(printf "#%.0s" $(seq 1 $((panjang_judul + 4))) | tr '0' '#')
        # Mencetak baris pembatas atas, dengan warna, dan diawali baris baru untuk spasi
        printf "\n${BRIGHT_CYAN}%s${NC}\n" "$garis_batas"
        # Mencetak teks judul yang diapit oleh karakter '#' dan spasi
        printf "${BRIGHT_CYAN}# %s #${NC}\n" "$judul_teks"
        # Mencetak baris pembatas bawah, lalu diikuti dua baris baru untuk memberi jarak ke konten selanjutnya
        printf "${BRIGHT_CYAN}%s${NC}\n\n" "$garis_batas"
    fi
}

# ==============================================================================
# FUNGSI-FUNGSI MENU UTAMA
# ==============================================================================

# FUNGSI: sapa_pengguna
# TUJUAN: Menampilkan layar sapaan pembuka yang ramah kepada pengguna
#         Isinya berupa ucapan selamat sesuai waktu dan rangkuman info dasar
# Fungsi untuk menampilkan sapaan dan waktu
sapa_pengguna() {
    # Membersihkan layar terminal terlebih dahulu agar tampilan bersih
    clear
    # Memanggil fungsi pembantu untuk mencetak judul utama halaman ini
    tampilkan_judul "Greeting User"
    
    # --- Mengumpulkan Informasi ---
    # Mengambil nama user yang sedang login saat ini dari sistem
    local NAMA_USER=$(id -un)
    # Mendapatkan jam saat ini dalam format 24 jam (misal: 22 untuk jam 10 malam)
    local JAM=$(date +%H)
    # Mendeklarasikan variabel kosong untuk menampung sapaan yang sesuai
    local SAPAAN
    # Logika kondisional untuk menentukan sapaan yang tepat berdasarkan jam
    # Jika jam antara 4 pagi sampai sebelum jam 11 siang, sapaannya adalah "Selamat Pagi"
    if [[ "$JAM" -ge 4 && "$JAM" -lt 11 ]]; then
        SAPAAN="Selamat Pagi"
    # Jika jam antara 11 siang sampai sebelum jam 3 sore
    elif [[ "$JAM" -ge 11 && "$JAM" -lt 15 ]]; then
        SAPAAN="Selamat Siang"
    # Jika jam antara 3 sore sampai sebelum jam 7 malam
    elif [[ "$JAM" -ge 15 && "$JAM" -lt 19 ]]; then
        SAPAAN="Selamat Sore"
    # Untuk sisa waktu lainnya, berarti "Selamat Malam"
    else
        SAPAAN="Selamat Malam"
    fi

    # --- Merangkai dan menyimpan semua informasi ke dalam variabel lokal ---
    # Merangkai kalimat sapaan lengkap dengan nama user dan sapaan yang sesuai waktu
    local SALAM_PEMBUKA="Halo ${BOLD}${ORANGE}$NAMA_USER${NC}, $SAPAAN!"
    # Mengambil tanggal sistem lengkap (Nama Hari, Tanggal, Bulan, Tahun)
    local TANGGAL_LENGKAP=$(date +"%A, %d %B %Y")
    # Mengambil waktu sistem lengkap (Jam:Menit:Detik ZonaWaktu)
    local WAKTU_SEKARANG=$(date +"%T %Z")
    # Mendapatkan informasi hari keberapa dalam setahun (1-366)
    local HARI_KE=$(date +%j)
    # Mendapatkan informasi minggu keberapa dalam setahun (1-53)
    local MINGGU_KE=$(date +%V)
    # Untuk saat ini, lokasi saya atur secara manual (hardcoded)
    local LOKASI="Surabaya, Jawa Timur"

    # --- Menampilkan Output dalam Format Tabel ---
    # Setelah semua data terkumpul, saya akan menampilkannya dalam format tabel yang rapi
    
    echo ""
    # Mencetak salam pembuka yang sudah dirangkai tadi, -e untuk mengaktifkan warna
    echo -e "$SALAM_PEMBUKA" 
    echo ""

    # Membuat variabel untuk garis horizontal tabel agar bisa digunakan berulang kali
    local table_line="${DIM}+---------------------------+---------------------------------------+${NC}"
    
    # Mencetak garis tabel untuk memulai
    echo -e "$table_line"
    # Mencetak baris header untuk tabel dengan teks tebal dan berwarna
    printf "| ${BOLD}${YELLOW}%-25s${NC} | ${BOLD}${YELLOW}%-37s${NC} |\n" "INFORMASI" "DETAIL"
    # Mencetak garis pemisah antara header dan isi tabel
    echo -e "$table_line"
    # Mencetak setiap baris data di dalam tabel, kolom detail diberi warna agar menonjol
    printf "| %-25s | ${CYAN}%-37s${NC} |\n" "Tanggal Hari Ini" "$TANGGAL_LENGKAP"
    printf "| %-25s | ${CYAN}%-37s${NC} |\n" "Waktu Saat Ini" "$WAKTU_SEKARANG"
    printf "| %-25s | ${CYAN}%-37s${NC} |\n" "Info Kalender" "Hari ke-$HARI_KE (Minggu ke-$MINGGU_KE)"
    printf "| %-25s | ${CYAN}%-37s${NC} |\n" "Perkiraan Lokasi Anda" "$LOKASI"
    # Mencetak garis penutup tabel
    echo -e "$table_line"
    
    # Memberi jarak di bagian bawah
    echo ""
}

# FUNGSI: informasi_jaringan
# TUJUAN: Menampilkan rangkuman lengkap mengenai status dan konfigurasi jaringan
#         Mulai dari koneksi internet, detail interface, hingga IP publik dan lokal
# Fungsi untuk menampilkan informasi jaringan
informasi_jaringan() {
    # Membersihkan layar dan menampilkan judul untuk bagian ini
    clear
    tampilkan_judul "Info Jaringan"
    # Mencetak garis pembatas atas
    echo -e "${DIM}=====================================================================${NC}"
    
    # Bagian 1: Melakukan pengecekan koneksi internet secara cepat
    # Mencetak label status
    printf "%-30s: " "Status Koneksi Internet"
    # Melakukan ping ke server DNS Google atau Cloudflare sebagai target
    # -c 1 untuk mengirim satu paket saja, -W 1 untuk timeout 1 detik agar tidak lama menunggu
    # Tanda '||' berarti jika ping pertama gagal, coba ping kedua
    # '&> /dev/null' digunakan untuk menyembunyikan semua output dari perintah ping
    if ping -c 1 -W 1 8.8.8.8 &> /dev/null || ping -c 1 -W 1 1.1.1.1 &> /dev/null; then
        # Jika salah satu ping berhasil, tampilkan status terhubung
        echo -e "${BRIGHT_GREEN}✔ Terhubung${NC}"
    else
        # Jika keduanya gagal, tampilkan status putus
        echo -e "${BRIGHT_RED}❌ Putus / Tidak Terhubung${NC}"
    fi
    echo ""

    # Bagian 2: Menampilkan status detail untuk setiap koneksi seperti Wi-Fi atau LAN
    # Mencetak sub-judul untuk bagian ini
    echo -e "${YELLOW}--- Status Koneksi LAN / Wi-Fi ---${NC}"
    # Memeriksa apakah perintah 'nmcli' (NetworkManager) ada di sistem
    if command -v nmcli &> /dev/null; then
        # Jika ada, saya akan gunakan untuk menampilkan tabel status koneksi
        local table_line="${DIM}+-----------------+------------+---------------+--------------------------+${NC}"
        echo -e "$table_line"
        printf "| ${BOLD}%-15s${NC} | ${BOLD}%-10s${NC} | ${BOLD}%-13s${NC} | ${BOLD}%-24s${NC} |\n" "DEVICE" "TYPE" "STATE" "CONNECTION"
        echo -e "$table_line"
        # Mengambil data dari nmcli, membuang baris 'loopback', dan memprosesnya baris per baris
        nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev status | grep -v 'loopback' | while IFS=: read -r device type state connection; do
            # Jika nama koneksi kosong, ganti dengan '--'
            if [[ -z "$connection" ]]; then connection="--"; fi
            # Logika untuk memberi warna pada status koneksi
            local state_color="$NC"
            if [[ "$state" == "connected" ]]; then state_color="${GREEN}"; elif [[ "$state" == "disconnected" ]]; then state_color="${RED}"; fi
            # Mencetak baris data ke dalam tabel
            printf "| ${CYAN}%-15s${NC} | %-10s | ${state_color}%-13s${NC} | ${BRIGHT_GREEN}%-24s${NC} |\n" "$device" "$type" "$state" "$connection"
        done
        echo -e "$table_line"
    else
        # Jika 'nmcli' tidak ada, tampilkan pesan informasi
        echo -e "${RED}Perintah 'nmcli' tidak ditemukan. Fitur ini memerlukan NetworkManager.${NC}"
    fi
    echo ""

    # Bagian 3: Mengambil dan menampilkan data konfigurasi umum dan info IP Publik
    # Mengambil alamat Gateway dari routing table
    local GATEWAY=$(ip route | grep '^default' | awk '{print $3}')
    # Membaca semua server DNS dari file /etc/resolv.conf
    readarray -t DNS_SERVERS < <(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}')
    # Mengambil alamat IP Publik dari layanan eksternal
    local PUBLIC_IP
    if command -v curl &> /dev/null; then PUBLIC_IP=$(curl -s --max-time 5 api.ipify.org); fi
    # Menyiapkan variabel untuk informasi lokasi geografis dari IP Publik
    local CITY="N/A" REGION="N/A" COUNTRY="N/A" ORG="N/A"
    # Jika IP Publik berhasil didapatkan, lanjutkan mengambil info lokasi
    if [[ -n "$PUBLIC_IP" ]]; then
        # Mengambil data lokasi dalam format JSON dari ipinfo.io
        # Token API bisa ditambahkan untuk request yang lebih banyak
        LOCATION_INFO_JSON=$(curl -s --max-time 7 "ipinfo.io/$PUBLIC_IP?token=YOUR_IPINFO_TOKEN")
        # Mem-parsing data JSON dengan grep untuk mendapatkan info spesifik
        CITY=$(echo "$LOCATION_INFO_JSON" | grep -oP '"city":\s*"\K[^"]*')
        REGION=$(echo "$LOCATION_INFO_JSON" | grep -oP '"region":\s*"\K[^"]*')
        COUNTRY=$(echo "$LOCATION_INFO_JSON" | grep -oP '"country":\s*"\K[^"]*')
        ORG=$(echo "$LOCATION_INFO_JSON" | grep -oP '"org":\s*"\K[^"]*')
    fi

    # Menampilkan data yang sudah terkumpul di atas ke dalam tabel
    echo -e "${YELLOW}--- Konfigurasi Umum & IP Publik ---${NC}"
    local config_line="${DIM}+-------------------------+------------------------------------------+${NC}"
    echo -e "$config_line"
    printf "| ${BOLD}%-23s${NC} | ${BOLD}%-40s${NC} |\n" "INFORMASI" "DETAIL"
    echo -e "$config_line"
    # Menggunakan ":-Tidak Ditemukan" sebagai nilai default jika variabel GATEWAY kosong
    printf "| %-23s | ${CYAN}%-40s${NC} |\n" "Gateway Utama" "${GATEWAY:-Tidak Ditemukan}"
    # Looping untuk menampilkan semua server DNS yang ditemukan
    local i=1
    for dns in "${DNS_SERVERS[@]}"; do
        printf "| %-23s | ${CYAN}%-40s${NC} |\n" "DNS Server $i" "$dns"
        i=$((i+1))
    done
    printf "| %-23s | ${BRIGHT_GREEN}%-40s${NC} |\n" "IP Publik" "${PUBLIC_IP:-Tidak Terhubung}"
    printf "| %-23s | ${CYAN}%-40s${NC} |\n" "Kota / Negara" "${CITY:-N/A} / ${COUNTRY:-N/A}"
    printf "| %-23s | ${CYAN}%-40s${NC} |\n" "Wilayah" "${REGION:-N/A}"
    printf "| %-23s | ${CYAN}%-40s${NC} |\n" "Provider/Organisasi" "${ORG:-N/A}"
    echo -e "$config_line"
    echo ""

    # Bagian 4: Menampilkan tabel berisi semua alamat IP lokal (IPv4)
    echo -e "${YELLOW}--- Alamat IP Lokal (IPv4) ---${NC}"
    local ip_table_line="${DIM}+-----------------+------------------+${NC}"
    echo -e "$ip_table_line"
    printf "| ${BOLD}%-15s${NC} | ${BOLD}%-16s${NC} |\n" "INTERFACE" "ALAMAT IP"
    echo -e "$ip_table_line"
    # Mengambil daftar alamat IP, lalu memprosesnya satu per satu
    ip -4 addr show scope global | awk '/inet / {print $NF, $2}' | while read -r interface ip_cidr; do
        # Menghilangkan bagian CIDR (contoh: /24) dari alamat IP
        local ip_clean=$(echo "$ip_cidr" | sed 's|/.*||')
        # Mencetak interface dan alamat IP bersih ke dalam tabel
        printf "| ${CYAN}%-15s${NC} | ${GREEN}%-16s${NC} |\n" "$interface" "$ip_clean"
    done
    echo -e "$ip_table_line"
    
    # Mencetak garis pembatas bawah
    echo -e "${DIM}=====================================================================${NC}"
    echo ""
}

# FUNGSI: daftar_direktori
# TUJUAN: Menampilkan isi dari direktori saat ini dalam format tabel yang detail
#         Mirip seperti perintah 'ls -l', tapi dengan tampilan yang lebih rapi dan berwarna
# Fungsi untuk menampilkan isi direktori saat ini (VERSI TABEL SIMETRIS)
daftar_direktori() {
    # Membersihkan layar dan menampilkan judul untuk bagian ini
    clear
    tampilkan_judul "Daftar Direktori"
    # Mencetak sub-judul yang menunjukkan path direktori yang sedang ditampilkan
    echo -e "${YELLOW}--- Isi Direktori Saat Ini: ${BRIGHT_YELLOW}$(pwd)${YELLOW} ---${NC}"
    echo ""

    # Pengecekan awal: apakah direktori ini kosong atau tidak
    # Logika ini mencari satu file/direktori, jika tidak ada, berarti kosong
    if ! [ -n "$(find . -maxdepth 1 -mindepth 1 -print -quit)" ]; then
        # Jika direktori kosong, tampilkan pesan dan keluar dari fungsi lebih awal
        echo -e "  ${DIM}(Direktori ini kosong)${NC}"
        echo ""
        echo -e "${DIM}=====================================================================${NC}"
        echo ""
        return
    fi
    
    # Mendefinisikan variabel untuk garis horizontal tabel
    local table_line="${DIM}+------------+----------+----------+---------+------------------+-------------------------------+"
    
    # Mencetak garis atas tabel
    echo -e "$table_line${NC}"
    # Mencetak header untuk setiap kolom tabel dengan format tebal
    printf "| ${BOLD}%-10s${NC} | ${BOLD}%-8s${NC} | ${BOLD}%-8s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-16s${NC} | ${BOLD}%-29s${NC} |\n" "Hak Akses" "Pemilik" "Grup" "Ukuran" "Modifikasi" "Nama File/Direktori"
    # Mencetak garis pemisah di bawah header
    echo -e "$table_line${NC}"

    # Memulai perulangan (loop) untuk setiap item di direktori ini
    # '* .*' digunakan untuk mencakup semua file, termasuk file tersembunyi (hidden files)
    for item in * .*; do
        # Melewatkan item direktori '.' (saat ini) dan '..' (induk) agar tidak tampil di daftar
        if [[ "$item" == "." || "$item" == ".." ]]; then continue; fi
        # Memastikan item tersebut benar-benar ada sebelum diproses
        if [ -e "$item" ]; then
            # Mengumpulkan semua informasi (metadata) dari setiap item menggunakan 'stat'
            local perms=$(stat -c "%A" "$item")      # Hak akses file (rwx)
            local size=$(stat -c "%s" "$item")       # Ukuran file dalam bytes
            local owner=$(stat -c "%U" "$item")      # Nama pemilik file
            local group=$(stat -c "%G" "$item")      # Nama grup pemilik
            local mod_time=$(stat -c "%Y" "$item")   # Waktu modifikasi terakhir (dalam detik epoch)

            # Mengonversi ukuran file dari bytes menjadi format yang mudah dibaca (KB, MB, dll)
            local human_size=$(numfmt --to=iec-i --suffix=B --format="%.1f" "$size")
            # Mengonversi waktu modifikasi dari format epoch menjadi tanggal dan jam yang mudah dibaca
            local human_date=$(date -d "@$mod_time" "+%Y-%m-%d %H:%M")
            
            # Logika untuk memberikan warna pada nama item berdasarkan tipenya
            local item_color="$NC" # Warna default (tidak ada warna)
            if [ -d "$item" ]; then
                item_color="${BRIGHT_BLUE}" # Jika item adalah direktori, warnai biru
            elif [ -x "$item" ]; then
                item_color="${BRIGHT_GREEN}" # Jika item bisa dieksekusi (executable), warnai hijau
            fi
            
            # Mencetak satu baris lengkap ke dalam tabel dengan semua data yang sudah diformat dan diwarnai
            # '%.8s' dan '%.29s' digunakan untuk memotong teks jika terlalu panjang agar tabel tetap rapi
            printf "| ${GREEN}%-10s${NC} | %-8.8s | %-8.8s | ${ORANGE}%-7s${NC} | ${MAGENTA}%-16s${NC} | ${item_color}%-29.29s${NC} |\n" "$perms" "$owner" "$group" "$human_size" "$human_date" "$item"
        fi
    done
    
    # Mencetak garis bawah tabel setelah semua item ditampilkan
    echo -e "$table_line${NC}"
    echo ""
    # Mencetak garis pembatas akhir halaman
    echo -e "${DIM}=====================================================================${NC}"
    echo ""
}

# FUNGSI: informasi_user
# TUJUAN: Menampilkan semua informasi relevan tentang pengguna yang sedang aktif
#         Informasi mencakup data dasar, sesi login, dan riwayat login
# Fungsi untuk menampilkan informasi pengguna
informasi_user() {
    # Membersihkan layar dan menampilkan judul untuk bagian ini
    clear
    tampilkan_judul "Info User"
    echo -e "${DIM}=====================================================================${NC}"
    
    # --- Tahap 1: Mengumpulkan semua data pengguna terlebih dahulu ---
    # Dengan mengumpulkan data di awal, kode untuk menampilkannya menjadi lebih bersih
    
    local CURRENT_USER=$(id -un)            # Mengambil nama pengguna saat ini
    local UID=$(id -u "$CURRENT_USER")      # Mengambil User ID (UID) dari pengguna
    local GID=$(id -g "$CURRENT_USER")      # Mengambil Group ID (GID) utama dari pengguna
    local PRIMARY_GROUP=$(id -gn "$CURRENT_USER") # Mengambil nama grup utama pengguna
    # Mengambil daftar grup lain dimana pengguna menjadi anggota, lalu memotong bagian yang tidak perlu
    local OTHER_GROUPS=$(groups "$CURRENT_USER" | cut -d' ' -f4-)
    local SHELL_PATH="$SHELL"               # Mengambil path shell login default dari variabel lingkungan
    local DISK_USAGE="N/A"                  # Menyiapkan variabel untuk penggunaan disk, defaultnya "N/A"
    # Memeriksa apakah direktori home ada, jika ada, hitung penggunaannya
    # 'du -sh' untuk mendapatkan total ukuran dalam format human-readable
    if [ -d "$HOME" ]; then read -r DISK_USAGE _ < <(du -sh "$HOME"); fi

    # --- Tahap 2: Menampilkan data umum dalam tabel pertama ---
    
    echo -e "${YELLOW}--- Informasi Umum & Disk ---${NC}"
    local main_table_line="${DIM}+---------------------------+------------------------------------------+${NC}"
    echo -e "$main_table_line"
    printf "| ${BOLD}%-25s${NC} | ${BOLD}%-40s${NC} |\n" "INFORMASI PENGGUNA" "DETAIL"
    echo -e "$main_table_line"
    # Mencetak semua data yang sudah dikumpulkan tadi ke dalam tabel
    printf "| %-25s | ${BRIGHT_GREEN}%-40s${NC} |\n" "Nama User Saat Ini" "$CURRENT_USER"
    printf "| %-25s | ${CYAN}%-40s${NC} |\n" "User ID (UID)" "$UID"
    printf "| %-25s | ${CYAN}%-40s${NC} |\n" "Grup Utama" "$PRIMARY_GROUP (GID: $GID)"
    # Hanya menampilkan baris "Grup Lain" jika pengguna memang punya grup lain
    if [ -n "$OTHER_GROUPS" ]; then printf "| %-25s | %-40.40s |\n" "Anggota Grup Lain" "$OTHER_GROUPS"; fi
    printf "| %-25s | ${YELLOW}%-40s${NC} |\n" "Direktori Home" "$HOME"
    printf "| %-25s | %-40s |\n" "Shell Login" "$SHELL_PATH"
    printf "| %-25s | ${ORANGE}%-40s${NC} |\n" "Penggunaan Disk Home" "$DISK_USAGE"
    echo -e "$main_table_line"
    echo ""

    # --- Tahap 3: Menampilkan tabel sesi login yang sedang aktif ---
    
    echo -e "${YELLOW}--- Sesi Login Aktif (dari 'w') ---${NC}"
    # Memeriksa apakah perintah 'w' ada DAN ada sesi login aktif untuk pengguna saat ini
    if command -v w &> /dev/null && [[ -n $(w -h "$CURRENT_USER") ]]; then
        # Jika ya, cetak tabelnya
        local session_table_line="${DIM}+-----------+------------+---------+-------------------------------+"
        echo -e "$session_table_line${NC}"
        printf "| ${BOLD}%-9s${NC} | ${BOLD}%-10s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-29s${NC} |\n" "TTY" "DARI" "LOGIN" "PROSES"
        echo -e "$session_table_line${NC}"
        # Mengambil output 'w', filter hanya untuk user saat ini, lalu proses per baris
        w | grep "^$CURRENT_USER" | while read -r user tty from login_at idle jcpu pcpu what; do
            # Mencetak detail setiap sesi ke dalam baris tabel
            printf "| ${GREEN}%-9s${NC} | ${CYAN}%-10s${NC} | %-7s | %-29.29s |\n" "$tty" "$from" "$login_at" "$what"
        done
        echo -e "$session_table_line${NC}"
    else
        # Jika tidak ada sesi aktif atau perintah 'w' tidak ada, tampilkan pesan
        echo -e "  ${DIM}(Tidak ada sesi login aktif atau perintah 'w' tidak ditemukan)${NC}"
    fi
    echo ""

    # --- Tahap 4: Menampilkan tabel riwayat 5 login terakhir ---

    echo -e "${YELLOW}--- 5 Riwayat Login Terakhir (dari 'last') ---${NC}"
    # Memeriksa apakah perintah 'last' ada DAN ada riwayat login untuk pengguna ini
    # 'head -n -2' digunakan untuk membuang 2 baris terakhir dari output 'last' yang biasanya berisi info reboot
    if command -v last &> /dev/null && [[ -n $(last -n 5 "$CURRENT_USER" | head -n -2) ]]; then
        # Jika ya, cetak tabel riwayatnya
        local hist_table_line="${DIM}+-----------------------+-----------+----------------------+"
        echo -e "$hist_table_line${NC}"
        printf "| ${BOLD}%-21s${NC} | ${BOLD}%-9s${NC} | ${BOLD}%-20s${NC} |\n" "WAKTU LOGIN" "TTY" "DARI"
        echo -e "$hist_table_line${NC}"
        # Mengambil 5 riwayat terakhir, lalu memprosesnya baris per baris
        last -n 5 "$CURRENT_USER" | head -n -2 | while read -r _ tty from day mon date time rest; do
            # Menyusun ulang format waktu dari output 'last' agar lebih rapi
            local login_time=$(printf "%s %s %s %s" "$day" "$mon" "$date" "$time")
            # Mencetak detail setiap riwayat ke dalam baris tabel
            printf "| ${MAGENTA}%-21.21s${NC} | ${GREEN}%-9s${NC} | ${CYAN}%-20.20s${NC} |\n" "$login_time" "$tty" "$from"
        done
        echo -e "$hist_table_line${NC}"
    else
        # Jika tidak ada riwayat atau perintah 'last' tidak ada, tampilkan pesan
        echo -e "  ${DIM}(Tidak ada riwayat login atau perintah 'last' tidak ditemukan)${NC}"
    fi
    
    # Mencetak garis pembatas akhir halaman
    echo -e "${DIM}=====================================================================${NC}"
    echo ""
}


# FUNGSI: informasi_sistem
# TUJUAN: Menampilkan ringkasan teknis dari sistem operasi secara menyeluruh
#         Mencakup info OS, CPU, memori, dan penggunaan disk dalam format tabel
# Fungsi untuk menampilkan detail Sistem Operasi
informasi_sistem() {
    # Membersihkan layar dan menampilkan judul untuk bagian ini
    clear
    tampilkan_judul "Detail OS"
    # Mencetak garis pembatas atas untuk seluruh halaman
    echo -e "${DIM}=============================================================================${NC}"

    # --- Tahap 1: Mengumpulkan semua data sistem terlebih dahulu ---
    # Saya kumpulkan semua datanya di sini agar bagian tampilan nanti lebih bersih

    # Menyiapkan variabel untuk nama dan versi OS dengan nilai default "N/A"
    local os_name="N/A"; local os_version="N/A"
    # Cara paling umum untuk mendapatkan info distro, dengan membaca file /etc/os-release
    if [ -f /etc/os-release ]; then . /etc/os-release; os_name=$NAME; os_version=$VERSION; fi
    # Mengambil versi kernel dan arsitektur sistem menggunakan perintah 'uname'
    local kernel_version=$(uname -r); local arch=$(uname -m)
    # Menyiapkan variabel untuk statistik CPU
    local cpu_user="N/A"; local cpu_system="N/A"; local cpu_idle="N/A"
    # Memeriksa apakah perintah 'top' tersedia untuk mengambil info CPU
    if command -v top &> /dev/null; then
        # Menjalankan 'top' dalam mode batch untuk satu snapshot, lalu ambil baris CPU
        local cpu_info=$(top -b -n 1 | grep '%Cpu(s)')
        # Mem-parsing baris info CPU dengan 'awk' untuk mendapatkan nilai spesifik
        cpu_user=$(echo "$cpu_info" | awk '{print $2}'); cpu_system=$(echo "$cpu_info" | awk '{print $4}'); cpu_idle=$(echo "$cpu_info" | awk '{print $8}')
    fi

    # --- Tahap 2: Menampilkan tabel Info Umum dan CPU ---

    echo -e "${YELLOW}--- Info Umum Sistem & CPU ---${NC}"
    local table_line_1="${DIM}+-------------------------+------------------------------------------+${NC}"
    echo -e "$table_line_1"
    printf "| ${BOLD}%-23s${NC} | ${BOLD}%-40s${NC} |\n" "INFORMASI" "DETAIL"
    echo -e "$table_line_1"
    # Mencetak data OS, kernel, dan arsitektur yang sudah dikumpulkan
    printf "| %-23s | ${BRIGHT_BLUE}%-40s${NC} |\n" "Nama OS" "$os_name"
    printf "| %-23s | %-40s |\n" "Versi" "$os_version"
    printf "| %-23s | ${CYAN}%-40s${NC} |\n" "Versi Kernel" "$kernel_version"
    printf "| %-23s | %-40s |\n" "Arsitektur" "$arch"
    
    # PERBAIKAN: Menggabungkan nilai CPU dengan '%' sebelum dicetak
    # Ini memastikan kolom tabel tetap sejajar meskipun ada kode warna
    local cpu_user_val="${cpu_user}%"
    local cpu_system_val="${cpu_system}%"
    local cpu_idle_val="${cpu_idle}%"
    # Mencetak statistik penggunaan CPU
    printf "| %-23s | ${GREEN}%-40s${NC} |\n" "CPU - Penggunaan User" "$cpu_user_val"
    printf "| %-23s | ${ORANGE}%-40s${NC} |\n" "CPU - Penggunaan System" "$cpu_system_val"
    printf "| %-23s | %-40s |\n" "CPU - Idle" "$cpu_idle_val"
    echo -e "$table_line_1"
    echo ""

    # --- Tahap 3: Menampilkan tabel Penggunaan Memori ---

    echo -e "${YELLOW}--- Penggunaan Memori ---${NC}"
    # Memeriksa ketersediaan perintah 'free'
    if command -v free &> /dev/null; then
        local mem_line="${DIM}+-------+---------+---------+---------+------------+-----------+${NC}"
        echo -e "$mem_line"
        printf "| ${BOLD}%-5s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-10s${NC} | ${BOLD}%-9s${NC} |\n" "Tipe" "Total" "Digunakan" "Bebas" "Shared" "Available"
        echo -e "$mem_line"
        # Mengambil info memori utama, lalu memformatnya langsung dengan awk agar pas di tabel
        free -h | grep -E "^Mem" | awk '{printf "| %-5s | %-7s | %-7s | %-7s | %-10s | %-9s |\n", $1, $2, $3, $4, $5, $7}'
        # PERBAIKAN: Format string untuk Swap disamakan dengan header agar simetris
        free -h | grep -E "^Swap" | awk '{printf "| %-5s | %-7s | %-7s | %-7s | %-10s | %-9s |\n", $1, $2, $3, $4, "--", "--"}'
        echo -e "$mem_line"
    else
        # Pesan jika 'free' tidak ditemukan
        echo -e "  ${RED}Perintah 'free' tidak ditemukan${NC}"
    fi
    echo ""

    # --- Tahap 4: Menampilkan tabel Penggunaan Disk ---

    echo -e "${YELLOW}--- Penggunaan Disk ---${NC}"
    # Memeriksa ketersediaan perintah 'df'
    if command -v df &> /dev/null; then
        local disk_line="${DIM}+-------------------------+---------+---------+---------+------+--------------------------------+${NC}"
        echo -e "$disk_line"
        printf "| ${BOLD}%-23s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-7s${NC} | ${BOLD}%-4s${NC} | ${BOLD}%-30s${NC} |\n" "Filesystem" "Ukuran" "Digunakan" "Tersedia" "Guna%" "Di-mount di"
        echo -e "$disk_line"
        # Menjalankan 'df -h', mengecualikan beberapa filesystem sementara, dan membuang header-nya
        df -h -x squashfs -x tmpfs -x devtmpfs | tail -n +2 | while read -r fs size used avail usepct mount; do
            # Menghapus tanda '%' untuk perbandingan numerik
            local use_val=${usepct//%/}
            # Menentukan warna berdasarkan persentase penggunaan
            local use_color="$GREEN" # Warna default hijau
            if (( use_val >= 85 )); then use_color="$BRIGHT_RED"; elif (( use_val >= 60 )); then use_color="$YELLOW"; fi
            
            # PERBAIKAN: Padding dan pewarnaan ditangani secara manual untuk menjaga kesejajaran
            local padded_usepct=$(printf "%-4s" "$usepct")
            local padded_mount=$(printf "%-30.30s" "$mount")
            
            # Mencetak baris data disk dengan warna yang sesuai dan padding yang benar
            printf "| %-23s | %-7s | %-7s | %-7s | ${use_color}%s${NC} | ${CYAN}%s${NC} |\n" "$fs" "$size" "$used" "$avail" "$padded_usepct" "$padded_mount"
        done
        echo -e "$disk_line"
    else
        # Pesan jika 'df' tidak ditemukan
        echo -e "  ${RED}Perintah 'df' tidak ditemukan${NC}"
    fi
    
    # Mencetak garis pembatas akhir halaman
    echo -e "${DIM}=============================================================================${NC}"
    echo ""
}

# FUNGSI: informasi_waktu_sistem
# TUJUAN: Menampilkan informasi waktu penting terkait sistem
#         Mencakup waktu boot terakhir, durasi uptime, dan perkiraan waktu instalasi OS
# Fungsi untuk menampilkan waktu sistem (VERSI TABEL SIMETRIS)
informasi_waktu_sistem() {
    # Membersihkan layar dan menampilkan judul untuk bagian ini
    clear
    tampilkan_judul "Waktu Sistem"
    
    # --- Tahap 1: Mengumpulkan data uptime ---
    
    # Menyiapkan variabel untuk waktu boot dan durasi uptime dengan nilai default
    local waktu_boot="N/A"; local durasi_up="N/A"
    # Memeriksa apakah perintah 'uptime' tersedia
    if command -v uptime &> /dev/null; then
        # Jika ada, ambil data uptime
        waktu_boot=$(uptime -s)                # 'uptime -s' untuk mendapatkan tanggal dan waktu boot
        durasi_up=$(uptime -p | sed 's/up //') # 'uptime -p' untuk format cantik, lalu hapus kata 'up '
    fi

    # --- Tahap 2: Mencari perkiraan waktu instalasi OS (ini bagian yang rumit) ---
    # Saya akan mencoba beberapa metode untuk mendapatkan data ini

    local install_date="N/A"; local install_source="Tidak dapat ditentukan"
    # Menyiapkan variabel untuk 'sudo' jika skrip tidak dijalankan sebagai root
    local sudo_cmd=""; if [[ $EUID -ne 0 ]]; then sudo_cmd="sudo"; fi

    # Metode A: Memeriksa tanggal modifikasi file log installer
    # Ini adalah cara yang cukup akurat di banyak distro
    local files_to_check=("/var/log/installer/syslog" "/var/log/installer/cloud-init.log" "/var/log/anaconda/ks.cfg" "/var/log/pacman.log")
    # Melakukan perulangan untuk setiap file log yang umum
    for file in "${files_to_check[@]}"; do
        # Jika file ditemukan
        if [ -f "$file" ]; then
            # Ambil tanggal modifikasi file menggunakan 'stat'
            # Saya gunakan '$sudo_cmd' karena file ini mungkin butuh akses root
            local stat_output; stat_output=$($sudo_cmd stat -c "%y" "$file" 2>/dev/null)
            # Jika berhasil mendapatkan tanggalnya
            if [ -n "$stat_output" ]; then
                # Simpan tanggal dan sumber datanya, lalu hentikan perulangan karena sudah ketemu
                install_date=$(echo "$stat_output" | awk '{print $1, $2}'); install_source="$file"; break; fi
        fi
    done

    # Metode B: Fallback jika Metode A gagal
    # Metode ini memeriksa waktu pembuatan partisi root
    if [[ "$install_date" == "N/A" ]] && command -v tune2fs &>/dev/null; then
        # Mengambil nama device dari partisi root (/)
        local root_device=$(df / | tail -n 1 | awk '{print $1}')
        # Menggunakan 'tune2fs' untuk melihat metadata filesystem
        local fs_creation; fs_creation=$($sudo_cmd tune2fs -l "$root_device" 2>/dev/null | grep 'Filesystem created:')
        # Jika informasi waktu pembuatan ditemukan
        if [ -n "$fs_creation" ]; then
            # Ambil tanggalnya, bersihkan, dan simpan
            install_date=$(echo "$fs_creation" | sed 's/Filesystem created://g' | awk '{$1=$1};1')
            install_source="Waktu pembuatan partisi ($root_device)"
        fi
    fi

    # --- Tahap 3: Menampilkan semua data yang sudah dikumpulkan ---
    
    echo ""
    # Menampilkan peringatan jika skrip tidak dijalankan sebagai root
    if [[ $EUID -ne 0 && "$install_date" != "N/A" && "$install_source" != "Tidak dapat ditentukan" ]]; then
        echo -e "${DIM}Info waktu instalasi mungkin memerlukan hak akses root (sudo)${NC}"
        echo ""
    fi

    # Mendefinisikan variabel untuk garis tabel agar konsisten
    local table_line="${DIM}+---------------------------+------------------------------------------+${NC}"
    local separator_line="${DIM}|---------------------------+------------------------------------------|${NC}"

    # Mulai mencetak tabel
    echo -e "$table_line"
    printf "| ${BOLD}${YELLOW}%-25s${NC} | ${BOLD}${YELLOW}%-40s${NC} |\n" "INFORMASI WAKTU" "DETAIL"
    echo -e "$table_line"
    # Menampilkan data uptime
    printf "| %-25s | ${CYAN}%-40s${NC} |\n" "Waktu Boot Terakhir" "$waktu_boot"
    printf "| %-25s | ${GREEN}%-40s${NC} |\n" "Telah Berjalan Selama" "$durasi_up"
    # Mencetak garis pemisah
    echo -e "$separator_line"
    # Menampilkan perkiraan waktu instalasi dan sumber datanya
    printf "| %-25s | ${MAGENTA}%-40s${NC} |\n" "Perkiraan Waktu Instal" "$install_date"
    printf "| %-25s | ${DIM}%-40s${NC} |\n" "Sumber Data Instalasi" "$install_source"
    echo -e "$table_line"
    echo ""
    # Mencetak garis pembatas akhir halaman
    echo -e "${DIM}=====================================================================${NC}"
    echo ""
}

# ==============================================================================
# PROGRAM UTAMA (MENU)
# ==============================================================================
# Ini adalah jantung dari skrip saya, sebuah loop tak terbatas yang akan terus
# menampilkan menu utama sampai pengguna memilih untuk keluar

# Membersihkan layar sekali di awal sebelum loop utama dimulai
clear
# Memulai loop utama yang akan berjalan selamanya
while true; do
    # Di setiap awal perulangan, layar dibersihkan agar menu selalu tampil rapi
    clear
    # Menampilkan judul utama dari menu
    tampilkan_judul "Menu Biasa Aja"

    # --- Bagian untuk Menggambar Tampilan Menu ---
    # Di sini saya mendefinisikan fungsi-fungsi lokal khusus untuk menggambar menu
    # agar kode utama tetap bersih dan mudah dibaca

    # Menetapkan lebar konten di dalam menu (dalam satuan karakter)
    menu_content_width=37

    # Fungsi lokal untuk menggambar garis horizontal dengan karakter box-drawing
    # Argumen: $1: karakter sudut kiri, $2: karakter garis, $3: karakter sudut kanan
    print_line() {
        printf "${DIM}$1"
        # Mencetak karakter garis tengah sebanyak lebar konten yang ditetapkan
        printf "$2%.0s" $(seq 1 $menu_content_width) | tr '0' "$2"
        printf "$3${NC}\n"
    }

    # Fungsi lokal untuk mencetak satu baris opsi menu
    print_menu_option() {
        # Memisahkan nomor dan teks dari argumen (misal: "1. Greeting User")
        local number=$(echo "$1" | awk '{print $1}')
        local text=$(echo "$1" | cut -d' ' -f2-)
        # Merangkai teks lengkap dengan warna dan spasi untuk indentasi
        local full_text="  ${YELLOW}${number}${NC} ${text}"
        
        # Mencetak garis vertikal kiri
        printf "${DIM}│${NC}"
        # PERBAIKAN: Menggunakan 'echo -e' untuk menginterpretasikan kode warna
        echo -ne "$full_text"
        
        # Menghitung panjang teks yang terlihat (tanpa kode warna) untuk padding
        # Ini penting agar posisi garis vertikal kanan selalu rata
        local visible_length=$((2 + ${#number} + 1 + ${#text}))
        
        # Menghitung sisa spasi (padding) yang dibutuhkan
        local padding=$(($menu_content_width - visible_length))
        # Memastikan padding tidak bernilai negatif jika teks terlalu panjang
        if (( padding < 0 )); then padding=0; fi
        # Mencetak spasi kosong sesuai hasil kalkulasi padding
        printf "%${padding}s" " "
        # Mencetak garis vertikal kanan dan baris baru
        printf "${DIM}│${NC}\n"
    }
    
    # Memanggil fungsi-fungsi di atas untuk benar-benar menggambar menu di layar
    print_line "┌" "─" "┐" # Garis atas
    print_menu_option "1. Greeting User"
    print_menu_option "2. Info Daftar Direktori"
    print_menu_option "3. Info Jaringan"
    print_menu_option "4. Info OS"
    print_menu_option "5. Waktu Install OS"
    print_menu_option "6. Info User"
    print_line "├" "─" "┤" # Garis pemisah sebelum opsi keluar
    print_menu_option "7. Exit Program"
    print_line "└" "─" "┘" # Garis bawah
    echo ""

    # --- Bagian untuk Memproses Input Pengguna ---

    # Menampilkan prompt dan membaca input dari pengguna, lalu menyimpannya di variabel 'pilihan'
    read -p "$(echo -e "${BRIGHT_YELLOW}Pilih opsi [1-7]: ${NC}")" pilihan

    # Menggunakan 'case' untuk menentukan tindakan berdasarkan input 'pilihan'
    case $pilihan in
        # Jika pilihan adalah 1, panggil fungsi sapa_pengguna
        1) sapa_pengguna; ;;
        2) daftar_direktori; ;;
        3) informasi_jaringan; ;;
        4) informasi_sistem; ;;
        5) informasi_waktu_sistem; ;;
        6) informasi_user; ;;
        # Jika pilihan adalah 7, jalankan urutan keluar dari program
        7)
            clear
            tampilkan_judul "XIE XIE YA!" # Pesan perpisahan
            sleep 2                       # Jeda 2 detik
            clear
            exit 0                        # Keluar dari skrip dengan status sukses
            ;;
        # Jika pilihan adalah karakter lain (input tidak valid)
        *)
            clear
            tampilkan_judul "Input Salah!"
            # Menampilkan pesan error dengan figlet jika ada, atau teks biasa jika tidak
            if command -v figlet &> /dev/null; then
                echo -e "${BRIGHT_RED}"
                figlet -w 80 "Pilihan '$pilihan' Gak Ada Bang!"
                echo -e "${NC}"
            else
                echo -e "${BRIGHT_RED}Pilihan '$pilihan' tidak valid! Silakan coba lagi${NC}"
            fi
            ;;
    esac
    
    # --- Bagian Jeda (Pause) ---
    # Ini digunakan agar pengguna bisa melihat output sebelum kembali ke menu

    # Jika pilihan adalah 1-6 (menu yang menampilkan informasi)
    if [[ "$pilihan" =~ ^[1-6]$ ]]; then
        echo ""
        # Tunggu pengguna menekan tombol apa saja untuk melanjutkan
        read -n 1 -s -r -p "$(echo -e "${DIM}Tekan tombol apa saja untuk kembali${NC}")"
    # Jika input tidak valid (bukan 1-6 dan juga bukan 7)
    elif [[ "$pilihan" != "7" ]]; then
        echo ""
        # Tunggu pengguna menekan tombol apa saja untuk lanjut setelah melihat pesan error
        read -n 1 -s -r -p "$(echo -e "${DIM}Tekan tombol apa saja untuk lanjut${NC}")"
    fi
done
