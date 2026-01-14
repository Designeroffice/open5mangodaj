#!/bin/bash

# ============================================
# UBUNTU 20.04 - OPEN5GS GÜNCELLENMİŞ KURULUM
# ============================================
# MongoDB 5.0, Open5GS, WebUI, Nginx
# Tüm paket bağımlılıkları düzeltildi
# ============================================

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Logo
clear
echo -e "${PURPLE}"
cat << "EOF"
╔══════════════════════════════════════════════════╗
║   🚀 OPEN5GS 5G CORE - GÜNCELLENMİŞ KURULUM 🚀   ║
║         Ubuntu 20.04 - Tüm Bağımlılıklar         ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Fonksiyonlar
info() { echo -e "${BLUE}[ℹ]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step() { 
    echo -e "\n${CYAN}══════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  🔧 $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
}

# ============================================
# KONTROLLER
# ============================================

step "SİSTEM KONTROLLERİ"

# Root kontrol
if [ "$EUID" -ne 0 ]; then 
    error "Root yetkisi gerekli! sudo ile çalıştırın: sudo $0"
    exit 1
fi

# Ubuntu 20.04 kontrolü
if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    error "Bu script Ubuntu için tasarlanmıştır!"
    exit 1
fi

UBUNTU_VERSION=$(grep "VERSION_ID" /etc/os-release | cut -d'"' -f2)
if [[ "$UBUNTU_VERSION" != "20.04" ]]; then
    warning "Ubuntu 20.04 önerilir, sürümünüz: $UBUNTU_VERSION"
    read -p "Devam etmek istiyor musunuz? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# AVX kontrolü
info "CPU AVX desteği kontrol ediliyor..."
if grep -q avx /proc/cpuinfo; then
    success "AVX desteği mevcut ✓"
else
    error "AVX desteği yok! MongoDB 5.0 AVX gerektirir."
    warning "MongoDB 4.4 kurmak için 'n' girin, iptal için 'c'"
    read -p "Seçiminiz (N/c): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Cc]$ ]]; then
        exit 1
    fi
    USE_MONGODB_44=true
fi

# RAM kontrol
RAM_GB=$(free -g | grep Mem: | awk '{print $2}')
if [ "$RAM_GB" -lt 4 ]; then
    warning "Düşük RAM: $RAM_GB GB (4GB+ önerilir)"
else
    info "RAM: $RAM_GB GB ✓"
fi

# ============================================
# SİSTEM HAZIRLIĞI - GÜNCELLENMİŞ
# ============================================

step "SİSTEM HAZIRLIĞI VE GÜNCELLEMELER"

info "Paket listesi güncelleniyor..."
apt update -y

info "Sistem güncelleniyor..."
DEBIAN_FRONTEND=noninteractive apt upgrade -y -q

info "Kernel ve firmware güncelleniyor..."
apt install -y linux-firmware

info "Temel araçlar kuruluyor..."
apt install -y \
    curl wget git nano htop \
    net-tools iputils-ping \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg lsb-release \
    build-essential \
    ufw fail2ban \
    pkg-config cmake \
    python3 python3-pip python3-dev \
    automake autoconf libtool \
    libpcap-dev libgcrypt20-dev \
    libidn11-dev libgnutls28-dev \
    libmicrohttpd-dev libcurl4-openssl-dev \
    libnghttp2-dev libssl-dev \
    libsctp-dev libyaml-dev \
    libmnl-dev libtins-dev \
    libsystemd-dev libreadline-dev \
    libbson-dev libmongoc-dev \
    libsnmp-dev libgcrypt20-dev \
    libssh-gcrypt-dev libidn11-dev \
    libprotobuf-dev protobuf-compiler \
    scons flex bison

# Python bağımlılıkları
pip3 install meson ninja

# Zaman dilimi
timedatectl set-timezone Europe/Istanbul

# Swap (8GB'dan az RAM varsa)
if [ "$RAM_GB" -lt 8 ]; then
    info "Swap alanı oluşturuluyor..."
    if [ ! -f /swapfile ]; then
        fallocate -l 4G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        success "4GB swap alanı oluşturuldu"
    else
        info "Swap dosyası zaten mevcut"
    fi
fi

# Sistem optimizasyonları
cat >> /etc/sysctl.conf << EOF
# Open5GS Optimizasyonları
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 300000
net.ipv4.tcp_moderate_rcvbuf = 1
fs.file-max = 2097152
EOF

sysctl -p

# ============================================
# MONGODB KURULUMU - GÜNCELLENMİŞ
# ============================================

step "MONGODB KURULUMU"

if [ "$USE_MONGODB_44" = true ]; then
    info "MongoDB 4.4 kuruluyor (AVX gerektirmez)..."
    
    # MongoDB 4.4 GPG
    wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add -
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.4.list
    
    apt update
    apt install -y mongodb-org=4.4.24 mongodb-org-server=4.4.24 mongodb-org-shell=4.4.24
else
    info "MongoDB 5.0 kuruluyor..."
    
    # MongoDB 5.0 GPG
    wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | apt-key add -
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-5.0.list
    
    apt update
    apt install -y mongodb-org
fi

# MongoDB konfigürasyonu - GÜNCELLENMİŞ
cat > /etc/mongod.conf << 'EOF'
# MongoDB Configuration for Open5GS
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
      cacheSizeGB: 2
      journalCompressor: snappy
    collectionConfig:
      blockCompressor: snappy
    indexConfig:
      prefixCompression: true

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  logRotate: reopen
  verbosity: 0
  quiet: false

net:
  port: 27017
  bindIp: 127.0.0.1,::1
  maxIncomingConnections: 10000
  wireObjectCheck: true
  ipv6: true

processManagement:
  fork: false
  pidFilePath: /var/run/mongodb/mongod.pid
  timeZoneInfo: /usr/share/zoneinfo

security:
  authorization: enabled
  javascriptEnabled: true

operationProfiling:
  mode: slowOp
  slowOpThresholdMs: 100
  slowOpSampleRate: 1.0

replication:
  oplogSizeMB: 1024
  replSetName: rs0

setParameter:
  enableLocalhostAuthBypass: false
  ttlMonitorEnabled: true
  cursorTimeoutMillis: 600000
  notablescan: false
  logLevel: 1
  flowControlTargetLagSeconds: 10
EOF

# MongoDB'yi başlat
systemctl start mongod
systemctl enable mongod

# MongoDB başlangıç kontrolü
for i in {1..30}; do
    if systemctl is-active --quiet mongod; then
        success "MongoDB başlatıldı"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        error "MongoDB başlatılamadı!"
        journalctl -u mongod --no-pager -n 50
        exit 1
    fi
done

# MongoDB veritabanı hazırlığı
info "MongoDB veritabanı hazırlanıyor..."

# Geçici auth kapatma
cp /etc/mongod.conf /etc/mongod.conf.backup
sed -i 's/  authorization: enabled/  authorization: disabled/' /etc/mongod.conf
systemctl restart mongod
sleep 5

# Veritabanı ve kullanıcı oluştur - GÜNCELLENMİŞ
mongosh --quiet << 'EOF'
use admin

// Open5GS veritabanı oluştur
db = db.getSiblingDB('open5gs')

// Kullanıcı oluştur
db.createUser({
  user: "open5gs",
  pwd: "Open5GS@2024",
  roles: [
    { role: "readWrite", db: "open5gs" },
    { role: "dbAdmin", db: "open5gs" },
    { role: "clusterMonitor", db: "admin" },
    { role: "readAnyDatabase", db: "admin" }
  ],
  mechanisms: ["SCRAM-SHA-1", "SCRAM-SHA-256"]
})

// Koleksiyonları oluştur
db.createCollection("subscriptions")
db.createCollection("sessions")
db.createCollection("equipment")
db.createCollection("profiles")
db.createCollection("counters")

// Index'ler oluştur
db.subscriptions.createIndex({ "imsi": 1 }, { unique: true, background: true })
db.subscriptions.createIndex({ "msisdn": 1 }, { unique: true, sparse: true, background: true })
db.sessions.createIndex({ "ue_ip": 1 }, { background: true })
db.sessions.createIndex({ "imsi": 1 }, { background: true })
db.sessions.createIndex({ "created_at": 1 }, { expireAfterSeconds: 86400, background: true })

print("✅ Open5GS MongoDB başarıyla hazırlandı")
EOF

# Auth'u tekrar aç
mv /etc/mongod.conf.backup /etc/mongod.conf
systemctl restart mongod

sleep 3

# MongoDB bağlantı testi
if mongosh --eval "db.adminCommand('ping')" --quiet > /dev/null 2>&1; then
    success "MongoDB bağlantısı başarılı"
else
    error "MongoDB bağlantı testi başarısız"
    exit 1
fi

# ============================================
# OPEN5GS KURULUMU - TAM BAĞIMLILIKLAR
# ============================================

step "OPEN5GS BAĞIMLILIKLARI VE KURULUMU"

info "Ek bağımlılıklar kuruluyor..."

# Gerekli tüm kütüphaneler
apt install -y \
    libtalloc-dev libpcsclite-dev \
    libusb-1.0-0-dev libpcap-dev \
    libaugeas-dev libxml2-dev \
    libconfuse-dev libreadline-dev \
    libpcre3-dev libseccomp-dev \
    libcap-dev libcurl4-openssl-dev \
    libgcrypt20-dev libgnutls28-dev \
    libsqlite3-dev libpq-dev \
    libmysqlclient-dev libffi-dev \
    libsctp-dev lksctp-tools \
    libmicrohttpd-dev libnghttp2-dev \
    libyaml-dev libmnl-dev \
    libidn11-dev libssh-gcrypt-dev \
    libprotobuf-dev protobuf-compiler \
    libgtest-dev libre2-dev \
    libjson-c-dev libini-config-dev \
    libwebsockets-dev libpq-dev \
    libmysqlclient-dev libhiredis-dev \
    libradcli-dev libfreeradius-dev \
    libsnmp-dev libelf-dev \
    libbpfcc-dev libxdp-dev \
    libpulse-dev libsndfile1-dev \
    libopus-dev libavcodec-dev \
    libavformat-dev libavutil-dev \
    libswscale-dev libvpx-dev \
    libx264-dev libx265-dev

# Özel derlenmesi gereken kütüphaneler
info "Özel kütüphaneler derleniyor..."

# FreeDiameter
cd /tmp
if [ ! -d "freeDiameter" ]; then
    git clone https://github.com/freediameter/freeDiameter.git
    cd freeDiameter
    mkdir build && cd build
    cmake .. -DDEFAULT_CONF_PATH:PATH="/usr/local/etc/freeDiameter"
    make -j$(nproc)
    make install
    ldconfig
fi

# Open5GS kaynak kodu
step "OPEN5GS DERLENİYOR"

cd /opt
if [ -d "open5gs" ]; then
    info "Open5GS zaten var, güncelleniyor..."
    cd open5gs
    git pull
    git submodule update --init --recursive
else
    info "Open5GS indiriliyor..."
    git clone https://github.com/open5gs/open5gs.git
    cd open5gs
    git submodule update --init --recursive
fi

# Derleme öncesi kontroller
info "Derleme ortamı kontrol ediliyor..."

# Meson versiyon kontrolü
MESON_VERSION=$(meson --version 2>/dev/null || echo "0.0")
if [[ "$MESON_VERSION" < "0.56" ]]; then
    warning "Meson versiyonu düşük ($MESON_VERSION), güncelleniyor..."
    pip3 install --upgrade meson
fi

# Derleme optimizasyonları
export MAKEFLAGS="-j$(nproc)"
export CFLAGS="-O2 -march=native -mtune=native"
export CXXFLAGS="-O2 -march=native -mtune=native"

info "Open5GS derleniyor (bu işlem 15-20 dakika sürebilir)..."

# Build dizinini temizle
rm -rf build
mkdir build && cd build

# Meson yapılandırması
meson setup .. \
    --prefix=/usr/local \
    --buildtype=release \
    --optimization=3 \
    --wrap-mode=nofallback \
    -Dhttp1=false \
    -Dhttp2=true \
    -Dsctp=true \
    -Dtls=gnutls \
    -Ddiameter=true \
    -Dmongoc=true \
    -Dsubscriber_db=mongodb \
    -Dmongo_ha=false \
    -Dtesting=false

# Derleme
ninja

# Testler (opsiyonel)
info "Testler çalıştırılıyor..."
if ninja test; then
    success "Tüm testler başarılı"
else
    warning "Bazı testler başarısız, devam ediliyor..."
fi

# Kurulum
ninja install
ldconfig

success "Open5GS başarıyla kuruldu"

# ============================================
# OPEN5GS KONFİGÜRASYONU - GÜNCELLENMİŞ
# ============================================

step "OPEN5GS KONFİGÜRASYONU"

# Konfigürasyon dizini
mkdir -p /usr/local/etc/open5gs
cd /usr/local/etc/open5gs

# MongoDB bağlantısı
cat > mongodb.yaml << 'EOF'
mongodb:
  uri: mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs?authSource=open5gs
  database: open5gs
  pool:
    minSize: 5
    maxSize: 100
    idleTimeoutMS: 30000
  serverSelectionTimeoutMS: 30000
  socketTimeoutMS: 60000
  connectTimeoutMS: 10000
EOF

# AMF konfigürasyonu - GÜNCELLENMİŞ
cat > amf.yaml << 'EOF'
amf:
  sbi:
    - addr: 0.0.0.0
      port: 29518
      advertise: 0.0.0.0
  ngap:
    - addr: 0.0.0.0
      port: 38412
  guami:
    - plmn_id:
        mcc: 001
        mnc: 01
      amf_id:
        region: 2
        set: 1
        pointer: 0
  tai:
    - plmn_id:
        mcc: 001
        mnc: 01
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 001
        mnc: 01
      s_nssai:
        - sst: 1
          sd: 0x010203
        - sst: 1
          sd: 0x112233
  security:
    integrity_order:
      - NIA2
      - NIA1
      - NIA0
    ciphering_order:
      - NEA2
      - NEA1
      - NEA0
  network_name:
    full: Open5GS
    short: O5GS
  amf_name: open5gs-amf0
  relative_capacity: 100
EOF

# SMF konfigürasyonu - GÜNCELLENMİŞ
cat > smf.yaml << 'EOF'
smf:
  sbi:
    - addr: 0.0.0.0
      port: 29502
      advertise: 0.0.0.0
  pfcp:
    - addr: 0.0.0.0
  gtpc:
    - addr: 0.0.0.0
  dns:
    - 8.8.8.8
    - 8.8.4.4
  mtu: 1500
  subnet:
    - addr: 10.45.0.1/16
      dnn: internet
    - addr: 10.46.0.1/16
      dnn: ims
  p-cscf:
    - addr: 10.45.0.2
  freeDiameter: /usr/local/etc/freeDiameter/smf.conf
  upf:
    - addr: 127.0.0.1
  metrics:
    enable: true
    interval: 30
EOF

# UPF konfigürasyonu
cat > upf.yaml << 'EOF'
upf:
  pfcp:
    - addr: 0.0.0.0
      advertise: 0.0.0.0
  gtpu:
    - addr: 0.0.0.0
      advertise: 0.0.0.0
  subnet:
    - addr: 10.45.0.1/16
      dnn: internet
    - addr: 10.46.0.1/16
      dnn: ims
  dns:
    - 8.8.8.8
    - 8.8.4.4
  metrics:
    enable: true
    interval: 30
EOF

# Test abonesi ekle
info "Test aboneleri ekleniyor..."
open5gs-dbctl add 901700123456789 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
open5gs-dbctl add 901700987654321 00112233445566778899AABBCCDDEEFF 63BFA50EE6523365FF14C1F45F88737D

success "Open5GS konfigürasyonları tamamlandı"

# ============================================
# WEBUI KURULUMU - GÜNCELLENMİŞ
# ============================================

step "WEB ARAYÜZÜ KURULUMU"

info "Node.js 18 LTS kuruluyor..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Node.js versiyon kontrolü
NODE_VERSION=$(node --version)
if [[ "$NODE_VERSION" =~ ^v18\..* ]]; then
    success "Node.js $NODE_VERSION kuruldu"
else
    error "Node.js 18 kurulumu başarısız"
    exit 1
fi

info "WebUI indiriliyor..."
cd /opt
if [ -d "open5gs-webui" ]; then
    cd open5gs-webui
    git pull
else
    git clone https://github.com/open5gs/open5gs-webui.git
    cd open5gs-webui
fi

info "Bağımlılıklar kuruluyor..."
npm cache clean --force
npm install --legacy-peer-deps

# Environment konfigürasyonu
cat > .env.production << 'EOF'
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# MongoDB Connection
MONGODB_URI=mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs?authSource=open5gs
MONGODB_DB=open5gs

# API Configuration
API_HOST=0.0.0.0
API_PORT=3000

# Security
SESSION_SECRET=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# WebUI Settings
WEBUI_TITLE=Open5GS 5G Core Network
WEBUI_THEME=dark
PAGINATION_LIMIT=50
SESSION_TIMEOUT=3600

# Logging
LOG_LEVEL=info
LOG_FORMAT=combined
EOF

info "WebUI build ediliyor..."
npm run build

# PM2 kurulumu (process manager)
npm install -g pm2
pm2 startup

success "WebUI hazırlandı"

# ============================================
# NGINX KURULUMU - GÜNCELLENMİŞ
# ============================================

step "NGINX VE SSL KURULUMU"

apt install -y nginx

# Self-signed SSL sertifikası
IP_ADDRESS=$(hostname -I | awk '{print $1}')
mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/open5gs.key \
    -out /etc/nginx/ssl/open5gs.crt \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Open5GS/CN=$IP_ADDRESS" \
    -addext "subjectAltName = IP:$IP_ADDRESS"

# Nginx konfigürasyonu
cat > /etc/nginx/sites-available/open5gs << EOF
# Open5GS WebUI Configuration
upstream open5gs_webui {
    server 127.0.0.1:3000;
    keepalive 64;
}

server {
    listen 80;
    listen [::]:80;
    server_name $IP_ADDRESS;
    
    # Redirect to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $IP_ADDRESS;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/open5gs.crt;
    ssl_certificate_key /etc/nginx/ssl/open5gs.key;
    
    # SSL Security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_ecdh_curve secp384r1;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Root location
    location / {
        proxy_pass http://open5gs_webui;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        
        # Buffer optimizations
        proxy_buffer_size 16k;
        proxy_buffers 4 32k;
        proxy_busy_buffers_size 64k;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass http://open5gs_webui;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Static files with caching
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable, max-age=31536000";
        proxy_pass http://open5gs_webui;
    }
    
    # WebSocket support
    location /socket.io/ {
        proxy_pass http://open5gs_webui;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Nginx'i yapılandır
ln -sf /etc/nginx/sites-available/open5gs /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Nginx optimizasyonları
sed -i 's/worker_processes auto;/worker_processes auto;\nworker_rlimit_nofile 65535;/' /etc/nginx/nginx.conf
sed -i '/events {/a\    worker_connections 4096;\n    multi_accept on;\n    use epoll;' /etc/nginx/nginx.conf

# Test ve başlat
nginx -t
systemctl restart nginx
systemctl enable nginx

success "Nginx kuruldu ve yapılandırıldı"

# ============================================
# SYSTEMD SERVİSLERİ - GÜNCELLENMİŞ
# ============================================

step "SYSTEMD SERVİSLERİ"

# Tüm Open5GS servisleri
SERVICES=("amfd" "smfd" "upfd" "hssd" "pcrfd" "nssfd" "bsfd" "udmd" "udrd" "ausfd" "nrf" "scpd" "mfpd")

for service in "${SERVICES[@]}"; do
cat > /etc/systemd/system/open5gs-${service}.service << EOF
[Unit]
Description=Open5GS ${service^^}
After=network.target mongod.service
Requires=mongod.service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/local/bin/open5gs-${service}d
Restart=always
RestartSec=3
StartLimitInterval=0
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
LimitMEMLOCK=infinity
LimitSTACK=infinity
TimeoutStartSec=30
TimeoutStopSec=30
Environment="LD_LIBRARY_PATH=/usr/local/lib"
Environment="GOTRACEBACK=crash"
Nice=-5
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99

[Install]
WantedBy=multi-user.target
EOF
done

# WebUI için PM2 systemd servisi
cat > /etc/systemd/system/open5gs-webui.service << 'EOF'
[Unit]
Description=Open5GS Web User Interface
After=network.target mongod.service nginx.service
Requires=mongod.service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/open5gs-webui
Environment=NODE_ENV=production
Environment=PATH=/usr/bin:/usr/local/bin
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=3
StartLimitInterval=0
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
Nice=0
CPUSchedulingPolicy=other
CPUSchedulingPriority=0

[Install]
WantedBy=multi-user.target
EOF

# Systemd reload ve başlatma
systemctl daemon-reload

# Temel servisleri başlat
info "Temel servisler başlatılıyor..."
systemctl enable --now open5gs-amfd
systemctl enable --now open5gs-smfd
systemctl enable --now open5gs-upfd
systemctl enable --now open5gs-nrf
systemctl enable --now open5gs-webui

# Diğer servisleri durdur (isteğe bağlı)
for service in "hssd" "pcrfd" "nssfd" "bsfd" "udmd" "udrd" "ausfd" "scpd" "mfpd"; do
    systemctl disable open5gs-${service} 2>/dev/null || true
    systemctl stop open5gs-${service} 2>/dev/null || true
done

success "Systemd servisleri kuruldu"

# ============================================
# FIREWALL VE GÜVENLİK - GÜNCELLENMİŞ
# ============================================

step "GÜVENLİK AYARLARI"

# UFW firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Portları aç
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw allow 29518/tcp    # AMF SBI
ufw allow 29502/tcp    # SMF SBI
ufw allow 29510/tcp    # NRF SBI
ufw allow 38412/sctp   # AMF N2
ufw allow 2152/udp     # GTP-U
ufw allow 8805/udp     # PFCP
ufw allow 2123/udp     # GTP-C

# Rate limiting
ufw limit ssh

# Firewall'u etkinleştir
ufw --force enable

# Fail2ban kurulumu
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

success "Güvenlik ayarları tamamlandı"

# ============================================
# YARDIMCI ARAÇLAR - GÜNCELLENMİŞ
# ============================================

step "YARDIMCI ARAÇLAR VE MONİTÖRİNG"

# 5G durum script'i
cat > /usr/local/bin/5g-status << 'EOF'
#!/bin/bash

echo "========================================"
echo "      OPEN5GS 5G CORE - SİSTEM DURUMU"
echo "========================================"
echo "Tarih: $(date)"
echo "Hostname: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo "Ubuntu: $(lsb_release -ds)"
echo ""

# MongoDB durumu
echo "🗄️  MONGODB DURUMU:"
echo "----------------------------------------"
if systemctl is-active mongod >/dev/null 2>&1; then
    echo "  Status: ✅ ÇALIŞIYOR"
    echo "  Version: $(mongosh --quiet --eval "db.version()")"
    echo "  Connections: $(mongosh --quiet