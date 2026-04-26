# SA:MP Firewall + BotChecker

Protección para servidores SA:MP contra floods UDP, exploits conocidos y bots (RakSAMP, FakeSAMP, RakMagic, Cookies Request, Querys Flood).

- **samp-firewall.sh** — reglas iptables que filtran tráfico a nivel de red (capa 3-4)
- **bot-checker.pwn** — filterscript Pawn.RakNet que analiza conexiones a nivel de protocolo SA:MP (capa 7)

El firewall absorbe el flood volumétrico antes de que llegue al el proceso del servidor. El filterscript detecta bots que lograron pasar el firewall.

Inspirado en [Edresson/SAMP-Firewall](https://github.com/Edresson/SAMP-Firewall).

---

## samp-firewall.sh

Script bash que configura iptables con las siguientes protecciones:

- **Anti-spoofing**: bloqueo de IPs origen en rangos no enrutables (RFC1918, multicast, TEST-NET, link-local), RPF del kernel, drop de TTL anormal y paquetes fragmentados.
- **Rate limiting**: límite global de paquetes/seg al puerto del juego y límite de conexiones por IP.
- **Query flood**: rate limit separado por IP para cada opcode del protocolo de queries SA-MP (`i`, `c`, `d`, `r`, `p`) con thresholds diferenciados.
- **Anti-amplificación**: bloqueo de puertos usados en reflection (DNS, NTP, SSDP, memcached, etc) y limitación del tráfico de salida para evitar que el server actúe como amplificador.
- **Handshake flood**: limitación de intentos de conexión RakNet (`0x05`, `0x07`) por IP.
- **Exploits conocidos**: bloqueo de cookie exploit (`0x081e77da`), paquetes vacíos y paquetes de tamaño imposible.
- **Whitelist**: IPs de servicios de monitoreo (sa-mp.com, SAcnr, game-stats.online).
- **Geoblocking** (opcional, deshabilitado por defecto): requiere xtables-addons.

### Uso

```bash
sudo bash samp-firewall.sh start    # aplica reglas
sudo bash samp-firewall.sh stop     # quita reglas
sudo bash samp-firewall.sh status   # muestra estado y top atacantes
sudo bash samp-firewall.sh save     # persiste reglas post-reboot
```

### Configuración

Editar las variables al inicio del archivo:

```bash
SAMP_PORT="7777"        # puerto del server
SSH_PORT="22"
ADMIN_IPS=("181.45.0.0/16")   # IPs con acceso sin restricciones
```

---

## bot-checker.pwn

Filterscript que opera sobre el protocolo SA:MP usando Pawn.RakNet. Cuatro niveles de detección:

### Nivel 1 — Validación de RPC_ClientJoin.

Intercepta el paquete de conexión y valida, versión del cliente (4057), byteMod (0x01 oficial / 0x02 NPC), longitud y caracteres del nickname, challenge response duplicado, y firmas de bots conocidos.

### Nivel 2 — Análisis Temp.

Mide el tiempo del handshake (< 400ms = bot, > 15s = timeout), verifica actividad post-spawn (movimiento y keystrokes en los primeros 30 segundos), y detecta teleports imposibles (> 100m entre updates).

### Nivel 3 — Reputación de IP.

Compara la IP contra rangos hardcodeados de datacenters conocidos (Hetzner, OVH, DigitalOcean, Vultr, Contabo) y detecta IPs privadas RFC1918 que no deberían llegar al servidor.

### Nivel 4 — Activa challenge

Muestra un dialog invisible post-spawn que requiere respuesta en tiempo humano (200ms–25s).

### Sistema de scoring

Cada detección suma puntos. Un solo flag no kickea; se necesitan múltiples señales:

| Score | Acción |
|-------|--------|
| 0-30 | Solo log |
| 31-60 | Log + monitoreo |
| 61-99 | Log + alerta |
| 100+ | Kick |

Ejemplos: jugador con internet lenta (+30 por handshake lento) no kickea. Bot típico matchea handshake rápido (+70) + IP datacenter (+60) + challenge rápido (+70) = 200, kick.

### Requisitos

- SA-MP server 0.3.7-R2+
- [Pawn.RakNet](https://github.com/katursis/Pawn.RakNet) plugin
- [sscanf2](https://github.com/Y-Less/sscanf) plugin
- Pawn compiler 3.10.10+

### Instalación

1. Instalar plugins Pawn.RakNet y sscanf2 en `plugins/`
2. Copiar includes (`.inc`) a `pawno/include/`
3. Compilar: `./pawno/pawncc filterscripts/bot-checker.pwn -o filterscripts/bot-checker.amx`
4. En `server.cfg`:
   ```
   plugins Pawn.RakNet sscanf2
   filterscripts bot-checker
   ```

### Comandos RCON

| Comando | Descripción |
|---------|-------------|
| `bc_status` | Estado de niveles y contadores |
| `bc_toggle <1-4>` | Activar/desactivar un nivel en runtime |
| `bc_stats <playerid>` | Score y datos de un jugador |

### Configuración

Constantes al inicio de `bot-checker.pwn`:

```pawn
#define MIN_HANDSHAKE_TIME_MS       400
#define MAX_HANDSHAKE_TIME_MS       15000
#define CHALLENGE_TIMEOUT_MS        30000
#define SUSPICION_KICK_THRESHOLD    100
```

Si jugadores legítimos están siendo kickeados, subir `SUSPICION_KICK_THRESHOLD` o bajar los scores individuales en `LogSuspiciousActivity()`.

---

## Notas

- Los rangos de datacenter en el Nivel 3 son estáticos. Para cobertura más amplia, pon una API externa como IPQualityScore o IPinfo.
- No funciona en open.mp.
- El firewall iptables y el filterscript van juntos.

## Licencia

MIT
