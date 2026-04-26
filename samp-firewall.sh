#!/bin/bash
###############################################################################
# SA:MP Firewall - expandido para servers SA-MP / open.mp
# Inspirado en Edresson/SAMP-Firewall
###############################################################################
#   sudo bash samp-firewall-pro.sh start    # aplica reglas
#   sudo bash samp-firewall-pro.sh stop     # quita reglas
#   sudo bash samp-firewall-pro.sh status   # muestra estado actual
#   sudo bash samp-firewall-pro.sh panic    # under attack
#   sudo bash samp-firewall-pro.sh save    
###############################################################################

# CONFIG
SAMP_PORT="7777"                # puerto principal del server SA-MP
SSH_PORT="22"                   
ADMIN_IPS=("181.45.0.0/16")     
LOG_PREFIX="SAMP-FW"            
PANIC_MODE_RATE="3"             # Tal cual como si fuese un Under Attack (no creo que lo llegues a utilizar)

# FUNCIONES AUX.

load_kernel_modules() {
    modprobe ipt_recent ip_list_tot=20000 ip_pkt_list_tot=255 2>/dev/null
    modprobe nf_conntrack 2>/dev/null

    # tuneo del kernel para mejor manejo de UDP bajo carga
    sysctl -w net.netfilter.nf_conntrack_udp_timeout=30 >/dev/null
    sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=120 >/dev/null
    sysctl -w net.core.rmem_max=26214400 >/dev/null
    sysctl -w net.core.rmem_default=26214400 >/dev/null
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null  # RPF (anti-spoofing) ccchecquear
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null
    sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
    sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null
    sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null  # loggea IPs spoofeadas
}

flush_rules() {
    iptables -F SAMP-FW 2>/dev/null
    iptables -X SAMP-FW 2>/dev/null
    iptables -F SAMP-DROP 2>/dev/null
    iptables -X SAMP-DROP 2>/dev/null
    iptables -F SAMP-WHITELIST 2>/dev/null
    iptables -X SAMP-WHITELIST 2>/dev/null
    iptables -F SAMP-RATE 2>/dev/null
    iptables -X SAMP-RATE 2>/dev/null

    iptables -D INPUT -j SAMP-FW 2>/dev/null
    iptables -D OUTPUT -p icmp -m icmp --icmp-type echo-reply -j DROP 2>/dev/null
    iptables -D OUTPUT -p icmp -m icmp --icmp-type port-unreachable -j DROP 2>/dev/null
}

###############################################################################
protect_infrastructure() {
    iptables -A INPUT -i lo -j ACCEPT

    # permitir tráfico ya establecido (SSH abierto, consultas de MySQL)
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ssh rate limit para evitar fuerza bruta
    iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW \
        -m recent --set --name SSH_LIMIT
    iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW \
        -m recent --update --seconds 60 --hitcount 4 --name SSH_LIMIT \
        -j LOG --log-prefix "[$LOG_PREFIX-SSH-BF] "
    iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW \
        -m recent --update --seconds 60 --hitcount 4 --name SSH_LIMIT -j DROP
    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT

    # whitelist de ips de personas con privilegios (acceso total sin restricciones) extra remover si no es necesario
    for ip in "${ADMIN_IPS[@]}"; do
        iptables -I INPUT 1 -s "$ip" -j ACCEPT
    done
}

###############################################################################
# anti-spoof y trato de paquetes malformados

anti_spoofing() {
    # logging (logueamos solo 1 de cada 100)
    iptables -N SAMP-DROP 2>/dev/null
    iptables -A SAMP-DROP -m limit --limit 1/s --limit-burst 5 \
        -j LOG --log-prefix "[$LOG_PREFIX-DROP] " --log-level 4
    iptables -A SAMP-DROP -j DROP

    # block paquetes con ips origen falsas / no enrutables
    iptables -A INPUT -s 0.0.0.0/8 -j SAMP-DROP        # Default
    iptables -A INPUT -s 10.0.0.0/8 -j SAMP-DROP       # RFC1918 privada
    iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j SAMP-DROP  # Loopback no-local
    iptables -A INPUT -s 169.254.0.0/16 -j SAMP-DROP   # Link-local
    iptables -A INPUT -s 172.16.0.0/12 -j SAMP-DROP    # RFC1918 privada
    iptables -A INPUT -s 192.0.2.0/24 -j SAMP-DROP     # TEST-NET
    iptables -A INPUT -s 192.168.0.0/16 -j SAMP-DROP   # RFC1918 privada
    iptables -A INPUT -s 198.18.0.0/15 -j SAMP-DROP    # Benchmarking
    iptables -A INPUT -s 198.51.100.0/24 -j SAMP-DROP  # TEST-NET-2
    iptables -A INPUT -s 203.0.113.0/24 -j SAMP-DROP   # TEST-NET-3
    iptables -A INPUT -s 224.0.0.0/4 -j SAMP-DROP      # Multicast
    iptables -A INPUT -s 240.0.0.0/4 -j SAMP-DROP      # Reserved

    # block paquetes con ttl  bajo
    iptables -A INPUT -m ttl --ttl-lt 5 -j SAMP-DROP

    # block paquetes con flags TCP inválidas (redundante pero bueno)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j SAMP-DROP   # null scan
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j SAMP-DROP    # xmas scan
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j SAMP-DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j SAMP-DROP

    # block paquetes udp fragmentados al puerto 7777
    iptables -A INPUT -p udp --dport $SAMP_PORT -f -j SAMP-DROP
}

###############################################################################
anti_volumetric() {
    # block amplification attacks comunes
    iptables -A INPUT -p udp -m multiport --sports 19,53,123,389,1900,11211 \
        ! -s "${ADMIN_IPS[0]}" -j SAMP-DROP

    # connection tracking limit por IP 
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m connlimit --connlimit-above 100 --connlimit-mask 32 \
        -j SAMP-DROP

    iptables -N SAMP-RATE 2>/dev/null
    iptables -A SAMP-RATE -m limit --limit 5000/s --limit-burst 7000 -j RETURN
    iptables -A SAMP-RATE -j SAMP-DROP

    iptables -A INPUT -p udp --dport $SAMP_PORT -j SAMP-RATE
}

###############################################################################
# queries
anti_query_flood() {

    # 'i'
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|69|' --from 38 --to 39 \
        -m recent --name QUERY_I --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|69|' --from 38 --to 39 \
        -m recent --name QUERY_I --rcheck --seconds 5 --hitcount 3 \
        -j SAMP-DROP

    # 'c' 
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|63|' --from 38 --to 39 \
        -m recent --name QUERY_C --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|63|' --from 38 --to 39 \
        -m recent --name QUERY_C --rcheck --seconds 5 --hitcount 3 \
        -j SAMP-DROP

    # 'd'
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|64|' --from 38 --to 39 \
        -m recent --name QUERY_D --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|64|' --from 38 --to 39 \
        -m recent --name QUERY_D --rcheck --seconds 10 --hitcount 2 \
        -j SAMP-DROP

    # 'r'
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|72|' --from 38 --to 39 \
        -m recent --name QUERY_R --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|72|' --from 38 --to 39 \
        -m recent --name QUERY_R --rcheck --seconds 10 --hitcount 2 \
        -j SAMP-DROP

    # 'p'
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
        -m string --algo bm --hex-string '|70|' --from 38 --to 39 \
        -m hashlimit --hashlimit-name QUERY_P \
        --hashlimit-mode srcip --hashlimit-above 5/sec \
        -j SAMP-DROP

    # descomentar en panic mode
    # iptables -A INPUT -p udp --dport $SAMP_PORT \
    #     -m string --algo bm --hex-string '|53414d50|' --from 28 --to 32 \
    #     -m recent --name SAMP_UNKNOWN --set
}

###############################################################################
# anti-handshake raknet
anti_handshake_flood() {
    # ID_OPEN_CONNECTION_REQUEST_1 = 0x05 (primer paquete del handshake)
    # limitar a 3 attempts por IP cada 30 segundos
    # un jugador legítimo abre 1 conexión y se mantiene en eso
    # nota el offset depende del padding 0x05 está al inicio del payload udp
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m length --length 1480:1500 \
        -m string --algo bm --hex-string '|05|' --to 1 \
        -m recent --name CONN_REQ1 --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m length --length 1480:1500 \
        -m string --algo bm --hex-string '|05|' --to 1 \
        -m recent --name CONN_REQ1 --rcheck --seconds 30 --hitcount 4 \
        -j SAMP-DROP

    # ID_OPEN_CONNECTION_REQUEST_2 = 0x07 2do paso del handshake
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|07|' --to 1 \
        -m recent --name CONN_REQ2 --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|07|' --to 1 \
        -m recent --name CONN_REQ2 --rcheck --seconds 30 --hitcount 4 \
        -j SAMP-DROP

    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m length --length 1480:1500 \
        -m hashlimit --hashlimit-name HANDSHAKE_GLOBAL \
        --hashlimit-mode dstip --hashlimit-above 30/sec --hashlimit-burst 50 \
        -j SAMP-DROP
}

###############################################################################
# exploits conocidos
anti_known_tools() {
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m length --length 604:604 \
        -m ttl --ttl-eq 128 \
        -j SAMP-DROP

    # cookies exploit
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|081e77da|' \
        -m recent --name cookie_exploit --set
    iptables -A INPUT -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|081e77da|' \
        -m recent --name cookie_exploit --rcheck --seconds 2 --hitcount 1 \
        -j SAMP-DROP

    # block paquetes udp vacíos
    iptables -A INPUT -p udp --dport $SAMP_PORT -m length --length 0:8 -j SAMP-DROP

    # block paquetes udp imposiblemente grandes para samp max 1500
    iptables -A INPUT -p udp --dport $SAMP_PORT -m length --length 1600:65535 -j SAMP-DROP
}

###############################################################################
whitelist_services() {

    iptables -N SAMP-WHITELIST 2>/dev/null

    # SA-MP servers monitor (sa-mp.com)
    iptables -A SAMP-WHITELIST -s 66.55.155.0/24 -j ACCEPT
    iptables -A SAMP-WHITELIST -s 82.192.84.0/24 -j ACCEPT

    # SAcnr monitor
    iptables -A SAMP-WHITELIST -s 104.28.17.0/24 -j ACCEPT

    # sa-mp.in
    iptables -A SAMP-WHITELIST -s 162.144.7.0/24 -j ACCEPT

    # game-stats.online
    iptables -A SAMP-WHITELIST -s 149.202.241.0/24 -j ACCEPT

    # open.mp launcher backend (verificar ip actual con dig api.open.mp)
    # iptables -A SAMP-WHITELIST -s X.X.X.X -j ACCEPT

    iptables -I INPUT 1 -p udp --dport $SAMP_PORT -j SAMP-WHITELIST
}

############################################################################### innecesario pero extra
geoblock_latam() {
    # requiere xtables-addons + módulo geoip instalado
    # apt install xtables-addons-common libtext-csv-xs-perl
    # /usr/lib/xtables-addons/xt_geoip_dl
    # /usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv

    # si tu comunidad es de latam, podés bloquear todo lo que no sea latam y algunos paises europeos

    # iptables -A INPUT -p udp --dport $SAMP_PORT \
    #     -m geoip ! --src-cc AR,UY,CL,PE,BO,PY,BR,CO,VE,MX,EC,DO,GT,CR,PA,CU,HN,SV,NI,US,ES \
    #     -j SAMP-DROP

    echo "geoblock deshabilitado por defecto."
}

###############################################################################
# logs monitor
configure_logging() {

    iptables -A INPUT -p udp --dport $SAMP_PORT -m limit --limit 10/min \
        -j LOG --log-prefix "[$LOG_PREFIX-ACCEPTED] " --log-level 6

    # En /etc/rsyslog.d/samp-firewall.conf:
    # :msg, contains, "SAMP-FW" -/var/log/samp-firewall.log
    # & stop
}

###############################################################################
accept_legitimate() {
    # despues de todo ese proceso, aceptamos
    iptables -A INPUT -p udp --dport $SAMP_PORT -j ACCEPT

}

###############################################################################
# amp check

protect_output() {
    iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-reply -j DROP

    iptables -A OUTPUT -p icmp -m icmp --icmp-type port-unreachable -j DROP

    iptables -A OUTPUT -p udp --sport $SAMP_PORT \
        -m hashlimit --hashlimit-name OUT_RATE \
        --hashlimit-mode dstip --hashlimit-above 100/sec \
        -j DROP
}

###############################################################################
# under attack (esto mantiene a los jugadores conectados mientras bloquea todas las nuevas conexiones)
panic_mode() {
    echo "=== Under attack ==="

    iptables -I INPUT 1 -p udp --dport $SAMP_PORT \
        -m length --length 1480:1500 \
        -m conntrack --ctstate NEW \
        -j SAMP-DROP

    iptables -I INPUT 1 -p udp --dport $SAMP_PORT \
        -m conntrack --ctstate ESTABLISHED \
        -j ACCEPT

    iptables -I INPUT 1 -p udp --dport $SAMP_PORT \
        -m string --algo bm --hex-string '|53414d50|' \
        -j SAMP-DROP

    echo "Under attack activado. Ningún jugador nuevo puede entrar."
    echo "Los jugadores ya logueados pueden seguir jugando."
    echo "Ejecutar 'stop' y luego 'start' para volver al modo normal."
}

###############################################################################
save_rules() {
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
        echo "rules guardadas con netfilter-persistent."
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4
        echo "rules guardadas en /etc/iptables/rules.v4"
        echo "asegurar de tener iptables-persistent instalado:"
        echo "  apt install iptables-persistent"
    else
        echo "ERROR: No se pudo guardar. Instala iptables-persistent."
    fi
}

###############################################################################
show_status() {
    echo "=== ESTADO ACTUAL DEL FIREWALL ==="
    echo ""
    echo "--- Reglas INPUT activas ---"
    iptables -L INPUT -n -v --line-numbers
    echo ""
    echo "--- Top 10 IPs en tabla recent (potenciales atacantes) ---"
    if [ -f /proc/net/xt_recent/CONN_REQ1 ]; then
        cat /proc/net/xt_recent/CONN_REQ1 | head -10
    fi
    echo ""
    echo "--- Últimos drops registrados ---"
    grep "$LOG_PREFIX" /var/log/kern.log 2>/dev/null | tail -20 || \
        echo "No hay logs aún (verificá rsyslog)"
    echo ""
    echo "--- Conexiones UDP activas al puerto SAMP ---"
    ss -unpa | grep ":$SAMP_PORT" | head -20
}

###############################################################################
# MAIN
###############################################################################
case "$1" in
    start)
        echo "Iniciando firewall"
        load_kernel_modules
        flush_rules
        protect_infrastructure
        anti_spoofing
        anti_volumetric
        anti_query_flood
        anti_handshake_flood
        anti_known_tools
        whitelist_services
        geoblock_latam
        configure_logging
        accept_legitimate
        protect_output
        echo "Firewall activo. Verificar con: $0 status"
        echo "Recuerda ejecutar '$0 save' para persistencia."
        ;;
    stop)
        echo "Removiendo reglas samp-server-firewall..."
        flush_rules
        iptables -P INPUT ACCEPT
        ;;
    panic)
        panic_mode
        ;;
    status)
        show_status
        ;;
    save)
        save_rules
        ;;
    *)
        echo "Uso: $0 {start|stop|panic|status|save}"
        echo ""
        echo "  start  - Activa todas las reglas"
        echo "  stop   - Remueve las reglas"
        echo "  panic  - under attack"
        echo "  status - Muestra estado actual y top atacantes"
        echo "  save   - Guarda reglas para persistencia post-reboot"
        exit 1
        ;;
esac

exit 0
