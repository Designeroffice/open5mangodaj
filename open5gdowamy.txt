info "Open5GS derleniyor (bu işlem 10-15 dakika sürebilir)..."
meson build --prefix=/usr/local --buildtype=release
ninja -C build

info "Open5GS kuruluyor..."
ninja -C build install
ldconfig

success "Open5GS kuruldu"

# ============================================
# OPEN5GS KONFİGÜRASYONU
# ============================================

step "OPEN5GS KONFİGÜRASYONU"

info "Open5GS konfigürasyon dosyaları oluşturuluyor..."

# Konfigürasyon dizini
mkdir -p /usr/local/etc/open5gs
cd /usr/local/etc/open5gs

# MongoDB bağlantı bilgisi
cat > mongodb.yaml << 'EOF'
mongodb:
  uri: mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs
  database: open5gs
EOF

# AMF konfigürasyonu
cat > amf.yaml << 'EOF'
amf:
  sbi:
    - addr: 0.0.0.0
      port: 29518
  ngap:
    - addr: 0.0.0.0
  guami:
    - plmn_id:
        mcc: 001
        mnc: 01
      amf_id:
        region: 2
        set: 1
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
  amf_name: open5gs-amf
EOF

# SMF konfigürasyonu
cat > smf.yaml << 'EOF'
smf:
  sbi:
    - addr: 0.0.0.0
      port: 29502
  pfcp:
    - addr: 0.0.0.0
  gtpc:
    - addr: 0.0.0.0
  subnet:
    - addr: 10.45.0.1/16
  dns:
    - 8.8.8.8
    - 8.8.4.4
  mtu: 1400
  p-cscf:
    - addr: 10.45.0.2
  freeDiameter: /usr/local/etc/freeDiameter/smf.conf
EOF

# UPF konfigürasyonu
cat > upf.yaml << 'EOF'
upf:
  pfcp:
    - addr: 0.0.0.0
  gtpu:
    - addr: 0.0.0.0
  subnet:
    - addr: 10.45.0.1/16
  dns:
    - 8.8.8.8
    - 8.8.4.4
EOF

# HSS konfigürasyonu
cat > hss.yaml << 'EOF'
hss:
  sbi:
    - addr: 0.0.0.0
      port: 29550
  freeDiameter: /usr/local/etc/freeDiameter/hss.conf
  crypt:
    integrity: EIA2
    ciphering: EEA2
  mme_identity:
    - mmec: 0x1
      mmegi: 0xC35F
  opc:
    - value: 8e27b6af0e692e750f32667a3b14605d
  key:
    - value: 465b5ce8b199b49faa5f0a2ee238a6bc
EOF

# Test abonesi ekle
info "Test abonesi ekleniyor..."
open5gs-dbctl add 901700123456789 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA

success "Open5GS konfigürasyonları tamamlandı"

# ============================================
# OPEN5GS WEBUI KURULUMU
# ============================================

step "OPEN5GS WEBUI KURULUMU"

info "Node.js ve npm kuruluyor..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

info "Open5GS WebUI indiriliyor..."
cd /opt
git clone https://github.com/open5gs/open5gs-webui.git
cd open5gs-webui

info "WebUI bağımlılıkları kuruluyor..."
npm install

info "WebUI build ediliyor..."
npm run build

# WebUI konfigürasyonu
cat > .env << 'EOF'
# Open5GS WebUI Configuration
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# MongoDB Connection
MONGODB_URI=mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs
MONGODB_DB=open5gs

# API Configuration
API_HOST=localhost
API_PORT=3000

# Security
SESSION_SECRET=Open5GS-WebUI-Secret-Key-2024
JWT_SECRET=Open5GS-JWT-Secret-Key-2024

# WebUI Settings
WEBUI_TITLE=Open5GS 5G Core Network
WEBUI_THEME=dark
PAGINATION_LIMIT=50
EOF

success "Open5GS WebUI hazırlandı"

# ============================================
# NGINX + SSL KURULUMU
# ============================================

step "NGINX VE SSL KURULUMU"

info "Nginx kuruluyor..."
apt install -y nginx

# SSL için Let's Encrypt
info "Certbot (Let's Encrypt) kuruluyor..."
apt install -y certbot python3-certbot-nginx

# Nginx konfigürasyonu
cat > /etc/nginx/sites-available/open5gs << 'EOF'
# Open5GS WebUI Nginx Configuration
upstream open5gs_webui {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    # SSL certificates will be added by certbot
    ssl_certificate /etc/letsencrypt/live/$server_name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$server_name/privkey.pem;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # WebUI
    location / {
        proxy_pass http://open5gs_webui;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
    
    # API
    location /api/ {
        proxy_pass http://open5gs_webui;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static files
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_pass http://open5gs_webui;
    }
    
    # WebSocket support
    location /socket.io/ {
        proxy_pass http://open5gs_webui;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

# Nginx'i yapılandır
ln -sf /etc/nginx/sites-available/open5gs /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test ve restart
nginx -t
systemctl restart nginx

# SSL sertifikası iste
info "SSL sertifikası almak için domain adınızı girin"
read -p "Domain adı (enter için IP kullan): " DOMAIN_NAME

if [ -z "$DOMAIN_NAME" ]; then
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    DOMAIN_NAME=$IP_ADDRESS
    warning "IP adresi kullanılacak: $DOMAIN_NAME"
else
    # Let's Encrypt ile SSL al
    certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME
fi

success "Nginx kuruldu ve yapılandırıldı"

# ============================================
# SYSTEMD SERVİSLERİ
# ============================================

step "SYSTEMD SERVİSLERİ"

# Open5GS servisleri
info "Open5GS systemd servisleri oluşturuluyor..."

# AMF servisi
cat > /etc/systemd/system/open5gs-amfd.service << 'EOF'
[Unit]
Description=Open5GS AMF (Access and Mobility Management Function)
After=network.target mongod.service
Requires=mongod.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/local/bin/open5gs-amfd
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
Environment="LD_LIBRARY_PATH=/usr/local/lib"

[Install]
WantedBy=multi-user.target
EOF

# SMF servisi
cat > /etc/systemd/system/open5gs-smfd.service << 'EOF'
[Unit]
Description=Open5GS SMF (Session Management Function)
After=network.target open5gs-amfd.service
Requires=open5gs-amfd.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/local/bin/open5gs-smfd
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
Environment="LD_LIBRARY_PATH=/usr/local/lib"

[Install]
WantedBy=multi-user.target
EOF

# UPF servisi
cat > /etc/systemd/system/open5gs-upfd.service << 'EOF'
[Unit]
Description=Open5GS UPF (User Plane Function)
After=network.target open5gs-smfd.service
Requires=open5gs-smfd.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/local/bin/open5gs-upfd
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
Environment="LD_LIBRARY_PATH=/usr/local/lib"
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# HSS servisi
cat > /etc/systemd/system/open5gs-hssd.service << 'EOF'
[Unit]
Description=Open5GS HSS (Home Subscriber Server)
After=network.target mongod.service
Requires=mongod.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local
ExecStart=/usr/local/bin/open5gs-hssd
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
Environment="LD_LIBRARY_PATH=/usr/local/lib"

[Install]
WantedBy=multi-user.target
EOF

# WebUI servisi
cat > /etc/systemd/system/open5gs-webui.service << 'EOF'
[Unit]
Description=Open5GS Web User Interface
After=network.target mongod.service nginx.service
Requires=mongod.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/open5gs-webui
Environment=NODE_ENV=production
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Systemd reload
systemctl daemon-reload

# Servisleri başlat
info "Servisler başlatılıyor..."
systemctl enable --now open5gs-amfd
systemctl enable --now open5gs-smfd
systemctl enable --now open5gs-upfd
systemctl enable --now open5gs-hssd
systemctl enable --now open5gs-webui

success "Systemd servisleri kuruldu ve başlatıldı"

# ============================================
# FIREWALL AYARLARI
# ============================================

step "FIREWALL KONFİGÜRASYONU"

info "Firewall kuralları ayarlanıyor..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Gerekli portları aç
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw allow 29518/tcp    # AMF SBI
ufw allow 38412/sctp   # AMF N2
ufw allow 2152/udp     # GTP-U
ufw allow 8805/udp     # PFCP
ufw allow 2123/udp     # GTP-C

# Firewall'u etkinleştir
ufw --force enable

success "Firewall kuralları uygulandı"

# ============================================
# YARDIMCI SCRIPT'LER
# ============================================

step "YARDIMCI SCRIPT'LER"

# Durum kontrol script'i
cat > /usr/local/bin/5g-status << 'EOF'
#!/bin/bash

echo "========================================"
echo "      5G CORE NETWORK DURUMU"
echo "========================================"
echo "Tarih: $(date)"
echo "Hostname: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo ""

echo "1. 🗄️  MONGODB DURUMU:"
echo "----------------------------------------"
systemctl status mongod --no-pager | grep -E "(Active:|Main PID:)"

echo ""
echo "2. 📡 OPEN5GS SERVİSLERİ:"
echo "----------------------------------------"
for service in open5gs-amfd open5gs-smfd open5gs-upfd open5gs-hssd open5gs-webui; do
    status=$(systemctl is-active $service 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo "  $service: ✅ ÇALIŞIYOR"
    else
        echo "  $service: ❌ DURDU"
    fi
done

echo ""
echo "3. 🌐 PORT DURUMLARI:"
echo "----------------------------------------"
echo -n "  Port 80 (HTTP): "; nc -z localhost 80 2>/dev/null && echo "✅ AÇIK" || echo "❌ KAPALI"
echo -n "  Port 443 (HTTPS): "; nc -z localhost 443 2>/dev/null && echo "✅ AÇIK" || echo "❌ KAPALI"
echo -n "  Port 3000 (WebUI): "; nc -z localhost 3000 2>/dev/null && echo "✅ AÇIK" || echo "❌ KAPALI"
echo -n "  Port 29518 (AMF): "; nc -z localhost 29518 2>/dev/null && echo "✅ AÇIK" || echo "❌ KAPALI"
echo -n "  Port 38412 (N2): "; nc -z -u localhost 38412 2>/dev/null && echo "✅ AÇIK" || echo "❌ KAPALI"

echo ""
echo "4. 📊 SİSTEM KAYNAKLARI:"
echo "----------------------------------------"
echo "  CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
echo "  RAM: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "  Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"

echo ""
echo "5. 🔗 WEB ERİŞİMİ:"
echo "----------------------------------------"
IP=$(hostname -I | awk '{print $1}')
echo "  WebUI: https://$IP"
echo "  API: https://$IP/api"

echo "========================================"
EOF

chmod +x /usr/local/bin/5g-status

# Backup script'i
cat > /usr/local/bin/5g-backup << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/5gcore"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$DATE"

echo "5G Core Network yedekleme başlatıldı..."
mkdir -p "$BACKUP_PATH"

echo "1. MongoDB yedekleniyor..."
mongodump --uri="mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs" \
    --out="$BACKUP_PATH/mongodb"

echo "2. Konfigürasyonlar yedekleniyor..."
cp -r /usr/local/etc/open5gs "$BACKUP_PATH/config"
cp -r /opt/open5gs-webui/.env "$BACKUP_PATH/webui_env"

echo "3. Systemd servisleri yedekleniyor..."
cp /etc/systemd/system/open5gs-*.service "$BACKUP_PATH/systemd/"

echo "4. Sıkıştırılıyor..."
cd "$BACKUP_DIR"
tar -czf "5gcore_$DATE.tar.gz" "backup_$DATE"
rm -rf "backup_$DATE"

# 7 günden eski yedekleri sil
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "✅ Yedekleme tamamlandı: $BACKUP_DIR/5gcore_$DATE.tar.gz"
EOF

chmod +x /usr/local/bin/5g-backup

# Abone ekleme script'i
cat > /usr/local/bin/5g-add-subscriber << 'EOF'
#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Kullanım: $0 <IMSI> <K> <OPC>"
    echo "Örnek: $0 901700123456789 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA"
    exit 1
fi

IMSI=$1
K=$2
OPC=$3

open5gs-dbctl add "$IMSI" "$K" "$OPC"

if [ $? -eq 0 ]; then
    echo "✅ Abone eklendi: IMSI=$IMSI"
    echo "   K: $K"
    echo "   OPC: $OPC"
else
    echo "❌ Abone eklenemedi!"
fi
EOF

chmod +x /usr/local/bin/5g-add-subscriber

# Log görüntüleme script'i
cat > /usr/local/bin/5g-logs << 'EOF'
#!/bin/bash

case $1 in
    amf)
        journalctl -u open5gs-amfd -f
        ;;
    smf)
        journalctl -u open5gs-smfd -f
        ;;
    upf)
        journalctl -u open5gs-upfd -f
        ;;
    hss)
        journalctl -u open5gs-hssd -f
        ;;
    webui)
        journalctl -u open5gs-webui -f
        ;;
    mongo)
        tail -f /var/log/mongodb/mongod.log
        ;;
    nginx)
        tail -f /var/log/nginx/access.log
        ;;
    *)
        echo "Kullanım: $0 {amf|smf|upf|hss|webui|mongo|nginx}"
        echo "Örnek: $0 amf"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/5g-logs

success "Yardımcı script'ler oluşturuldu"

# ============================================
# KURULUM TAMAMLANDI
# ============================================

step "KURULUM TAMAMLANDI"

# IP adresi
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Kurulum özeti
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}               🎉 KURULUM BAŞARIYLA TAMAMLANDI! 🎉          ${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}🚀 5G CORE NETWORK ERİŞİM BİLGİLERİ:${NC}"
echo -e "  🌐 Web Arayüzü: ${YELLOW}https://$IP_ADDRESS${NC}"
echo -e "  📡 API Endpoint: ${YELLOW}https://$IP_ADDRESS/api${NC}"
echo -e "  🗄️  MongoDB: ${YELLOW}mongodb://open5gs:Open5GS@2024@localhost:27017/open5gs${NC}"
echo ""
echo -e "${CYAN}🔐 VARS
