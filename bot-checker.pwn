/*
 *  SA:MP Firewall + BotChecker v.1.0.0. agUDP.
 * Inspirado en Edresson/SAMP-Firewall
 * Filterscript de detección y bloqueo de bots para SA-MP 0.3.7
 * Requiere: Pawn.RakNet plugin (https://github.com/katursis/Pawn.RakNet)
 *           sscanf2 plugin (https://github.com/Y-Less/sscanf)
 *
 * INSTALACIÓN:
 *   1. Compilar con Pawn compiler 3.10.10+ con includes de Pawn.RakNet y sscanf2
 *   2. Mover .amx a filterscripts/
 *   3. server.cfg: plugins Pawn.RakNet sscanf2
 *   4. server.cfg: filterscripts bot-checker
 */

#include <a_samp>
#include <Pawn.RakNet>
#include <sscanf2>

#define PLUGIN_VERSION          "1.1.0"
#define LOG_FILE                "botchecker.log"

#define LEVEL_1_RPC_VALIDATION      true
#define LEVEL_2_TIMING_ANALYSIS     true
#define LEVEL_3_IP_REPUTATION       true
#define LEVEL_4_ACTIVE_CHALLENGES   true

// Thresholds
#define MIN_HANDSHAKE_TIME_MS       400
#define MAX_HANDSHAKE_TIME_MS       15000
#define CHALLENGE_TIMEOUT_MS        30000
#define SUSPICION_KICK_THRESHOLD    100

// SA:MP protocolo
#define RPC_CLIENT_JOIN             25
#define EXPECTED_CLIENT_VERSION     4057   // SA-MP 0.3.7
#define MAX_NICKNAME_LENGTH         24
#define EXPECTED_AUTH_KEY_LENGTH     37

// challenge
#define DIALOG_INVISIBLE_CHALLENGE  9999

enum E_PLAYER_DATA {
    bool:gActive,
    gConnectionStartTick,
    gClientJoinTick,
    gSpawnTick,
    gSuspicionScore,
    gIPAddress[16],
    bool:gPassedChallenge,
    gChallengeStartTick,
    bool:gFlaggedAsBot,
    gKeystrokeCount,
    gMovementChanges,
    Float:gLastX,
    Float:gLastY,
    Float:gLastZ,
    bool:gSpawned,
    bool:gIPChecked,
    bool:gChallengeShown
}

new gPlayerData[MAX_PLAYERS][E_PLAYER_DATA];
new bool:gFilterEnabled[5] = {true, true, true, true, true};
new gTotalBlocked = 0;
new gTotalAllowed = 0;

new const gKnownBotSignatures[][] = {
    "RakSAMP",
    "FakeSAMP",
    "RakMagic",
    "SAMP-Bot",
    "ServerStress"
};


LogToFile(const message[]) {
    new File:f = fopen(LOG_FILE, io_append);
    if (f) {
        new timestamp[32], year, month, day, hour, minute, second;
        getdate(year, month, day);
        gettime(hour, minute, second);
        format(timestamp, sizeof(timestamp), "[%04d-%02d-%02d %02d:%02d:%02d] ",
            year, month, day, hour, minute, second);
        fwrite(f, timestamp);
        fwrite(f, message);
        fwrite(f, "\r\n");
        fclose(f);
    }
}

LogSuspiciousActivity(playerid, const reason[], scoreIncrement) {
    new ip[16], name[MAX_PLAYER_NAME], message[256];
    GetPlayerIp(playerid, ip, sizeof(ip));
    GetPlayerName(playerid, name, sizeof(name));

    gPlayerData[playerid][gSuspicionScore] += scoreIncrement;

    format(message, sizeof(message),
        "SUSPICION | pid=%d name=%s ip=%s reason=\"%s\" score+=%d total=%d",
        playerid, name, ip, reason, scoreIncrement,
        gPlayerData[playerid][gSuspicionScore]);
    LogToFile(message);

    if (gPlayerData[playerid][gSuspicionScore] >= SUSPICION_KICK_THRESHOLD
        && !gPlayerData[playerid][gFlaggedAsBot]) {

        new kickMsg[128];
        format(kickMsg, sizeof(kickMsg),
            "KICK | pid=%d name=%s ip=%s final_score=%d",
            playerid, name, ip, gPlayerData[playerid][gSuspicionScore]);
        LogToFile(kickMsg);

        gPlayerData[playerid][gFlaggedAsBot] = true;
        gTotalBlocked++;
        SetTimerEx("DelayedKick", 1000, false, "i", playerid);
    }
}

forward DelayedKick(playerid);
public DelayedKick(playerid) {
    if (IsPlayerConnected(playerid)) {
        Kick(playerid);
    }
}

ResetPlayerData(playerid) {
    gPlayerData[playerid][gActive] = false;
    gPlayerData[playerid][gConnectionStartTick] = 0;
    gPlayerData[playerid][gClientJoinTick] = 0;
    gPlayerData[playerid][gSpawnTick] = 0;
    gPlayerData[playerid][gSuspicionScore] = 0;
    gPlayerData[playerid][gPassedChallenge] = false;
    gPlayerData[playerid][gChallengeStartTick] = 0;
    gPlayerData[playerid][gFlaggedAsBot] = false;
    gPlayerData[playerid][gKeystrokeCount] = 0;
    gPlayerData[playerid][gMovementChanges] = 0;
    gPlayerData[playerid][gLastX] = 0.0;
    gPlayerData[playerid][gLastY] = 0.0;
    gPlayerData[playerid][gLastZ] = 0.0;
    gPlayerData[playerid][gSpawned] = false;
    gPlayerData[playerid][gIPChecked] = false;
    gPlayerData[playerid][gChallengeShown] = false;
    gPlayerData[playerid][gIPAddress][0] = '\0';
}

// ===================================================================
// Validaciones RPC.
IPC RPC:ClientJoin(playerid, BitStream:bs) {
    if (!gFilterEnabled[1]) return 1;

    new iVersion;
    new byteMod;
    new byteNicknameLen;
    new nickname[MAX_NICKNAME_LENGTH + 1];
    new challengeResponse1;
    new byteAuthKeyLen;
    new authKey[64];
    new iClientVerLen;
    new clientVersion[16];
    new challengeResponse2;

    BS_ReadUint32(bs, iVersion);
    BS_ReadUint8(bs, byteMod);
    BS_ReadUint8(bs, byteNicknameLen);

    // nickname con longitud inválida = drop
    if (byteNicknameLen == 0 || byteNicknameLen > MAX_NICKNAME_LENGTH) {
        LogSuspiciousActivity(playerid, "Nickname length anomaly", 100);
        return 0;
    }

    BS_ReadString(bs, nickname, byteNicknameLen);
    BS_ReadUint32(bs, challengeResponse1);
    BS_ReadUint8(bs, byteAuthKeyLen);

    if (byteAuthKeyLen != EXPECTED_AUTH_KEY_LENGTH && byteAuthKeyLen != 0) {
        LogSuspiciousActivity(playerid, "Auth key length unusual", 30);
    }

    if (byteAuthKeyLen > 0 && byteAuthKeyLen < sizeof(authKey)) {
        BS_ReadString(bs, authKey, byteAuthKeyLen);
    }

    BS_ReadUint8(bs, iClientVerLen);
    if (iClientVerLen > 0 && iClientVerLen < sizeof(clientVersion)) {
        BS_ReadString(bs, clientVersion, iClientVerLen);
    }

    // challenge
    new bool:hasDuplicate = false;
    if (BS_GetNumberOfUnreadBits(bs) >= 32) {
        BS_ReadUint32(bs, challengeResponse2);
        hasDuplicate = true;
    }


    // byteMod inválido = drop
    if (byteMod != 0x01 && byteMod != 0x02) {
        LogSuspiciousActivity(playerid, "Invalid byteMod", 80);
        return 0;
    }

    if (iVersion != EXPECTED_CLIENT_VERSION) {
        LogSuspiciousActivity(playerid, "iVersion mismatch", 50);
    }

    if (!hasDuplicate) {
        LogSuspiciousActivity(playerid, "Challenge not duplicated", 60);
    } else if (challengeResponse1 != challengeResponse2) {
        LogSuspiciousActivity(playerid, "Challenge mismatch", 90);
    }

    if (iClientVerLen == 0) {
        LogSuspiciousActivity(playerid, "Empty client version", 40);
    } else if (clientVersion[0] != '0' || clientVersion[1] != '.' || clientVersion[2] != '3') {
        LogSuspiciousActivity(playerid, "Invalid client version format", 70);
    }

    for (new i = 0; i < sizeof(gKnownBotSignatures); i++) {
        if (strfind(authKey, gKnownBotSignatures[i], true) != -1 ||
            strfind(clientVersion, gKnownBotSignatures[i], true) != -1 ||
            strfind(nickname, gKnownBotSignatures[i], true) != -1) {
            LogSuspiciousActivity(playerid, "Known bot signature detected", 150);
            return 0;
        }
    }

    new badCharCount = 0;
    for (new i = 0; i < byteNicknameLen; i++) {
        new c = nickname[i];
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '[' || c == ']' || c == '$' ||
              c == '(' || c == ')' || c == '@' || c == '.' || c == '=')) {
            badCharCount++;
        }
    }
    if (badCharCount > 0) {
        new reason[64];
        format(reason, sizeof(reason), "Nick has %d suspicious chars", badCharCount);
        LogSuspiciousActivity(playerid, reason, badCharCount * 20);
    }

    gPlayerData[playerid][gClientJoinTick] = GetTickCount();
    return 1;
}

CheckIPReputation(playerid) {
    if (!gFilterEnabled[3]) return;
    if (gPlayerData[playerid][gIPChecked]) return;

    gPlayerData[playerid][gIPChecked] = true;

    new ip[16];
    GetPlayerIp(playerid, ip, sizeof(ip));

    new o1, o2, o3, o4;
    if (sscanf(ip, "p<.>iiii", o1, o2, o3, o4)) return; // parse fa

    new bool:isDatacenter = false;

    // Hetzner
    if (o1 == 78 && o2 == 46) isDatacenter = true;
    if (o1 == 88 && o2 == 99) isDatacenter = true;
    if (o1 == 116 && o2 == 202) isDatacenter = true;
    if (o1 == 5 && o2 == 9) isDatacenter = true;

    // OVH
    if (o1 == 51 && (o2 == 255 || o2 == 68)) isDatacenter = true;
    if (o1 == 145 && o2 == 239) isDatacenter = true;

    // DigitalOcean
    if (o1 == 138 && o2 == 197) isDatacenter = true;
    if (o1 == 159 && o2 == 65) isDatacenter = true;
    if (o1 == 167 && o2 == 71) isDatacenter = true;

    // Vultr
    if (o1 == 45 && (o2 == 32 || o2 == 63)) isDatacenter = true;
    if (o1 == 108 && o2 == 61) isDatacenter = true;

    // Contabo
    if (o1 == 161 && o2 == 97) isDatacenter = true;
    if (o1 == 173 && o2 == 212) isDatacenter = true;
    if (o1 == 207 && o2 == 180) isDatacenter = true;

    if (isDatacenter) {
        LogSuspiciousActivity(playerid, "IP from known datacenter", 60);
    }

    // RFC1918 — no debería llegar al server si el firewall está ok
    if (o1 == 10 ||
        (o1 == 172 && o2 >= 16 && o2 <= 31) ||
        (o1 == 192 && o2 == 168)) {
        LogSuspiciousActivity(playerid, "RFC1918 range (firewall bypass?)", 100);
    }
}

// ===================================================================
// challenge

ShowInvisibleChallenge(playerid) {
    if (!gFilterEnabled[4]) return;
    if (gPlayerData[playerid][gChallengeShown]) return;

    gPlayerData[playerid][gChallengeShown] = true;
    gPlayerData[playerid][gChallengeStartTick] = GetTickCount();

    ShowPlayerDialog(playerid, DIALOG_INVISIBLE_CHALLENGE,
        DIALOG_STYLE_MSGBOX,
        " ",   // título vacío (invisible para el jugador)
        " ",   // contenido vacío
        "OK",  // botón
        "");

    SetTimerEx("ChallengeTimeout", CHALLENGE_TIMEOUT_MS, false, "i", playerid);
}

forward ChallengeTimeout(playerid);
public ChallengeTimeout(playerid) {
    if (!IsPlayerConnected(playerid)) return;
    if (!gPlayerData[playerid][gPassedChallenge] && !gPlayerData[playerid][gFlaggedAsBot]) {
        LogSuspiciousActivity(playerid, "Challenge timeout - no response", 80);
    }
}

public OnIncomingConnection(playerid, ip_address[], port) {
    ResetPlayerData(playerid);

    gPlayerData[playerid][gActive] = true;
    gPlayerData[playerid][gConnectionStartTick] = GetTickCount();
    strcopy(gPlayerData[playerid][gIPAddress], ip_address, 16);

    new logMsg[128];
    format(logMsg, sizeof(logMsg), "INCOMING | pid=%d ip=%s port=%d",
        playerid, ip_address, port);
    LogToFile(logMsg);
    return 1;
}

public OnPlayerConnect(playerid) {
    if (gFilterEnabled[2]) {
        new connectionTime = GetTickCount() - gPlayerData[playerid][gConnectionStartTick];

        if (connectionTime < MIN_HANDSHAKE_TIME_MS) {
            new reason[64];
            format(reason, sizeof(reason), "Handshake too fast: %dms", connectionTime);
            LogSuspiciousActivity(playerid, reason, 70);
        }
        if (connectionTime > MAX_HANDSHAKE_TIME_MS) {
            new reason[64];
            format(reason, sizeof(reason), "Handshake too slow: %dms", connectionTime);
            LogSuspiciousActivity(playerid, reason, 30);
        }
    }

    CheckIPReputation(playerid);

    // timer para verificar actividad post-spawn
    SetTimerEx("CheckPostSpawnActivity", 30000, false, "i", playerid);

    return 1;
}

public OnPlayerSpawn(playerid) {
    gPlayerData[playerid][gSpawnTick] = GetTickCount();
    gPlayerData[playerid][gSpawned] = true;

    // mostrar challenge al spawnear
    ShowInvisibleChallenge(playerid);

    return 1;
}

forward CheckPostSpawnActivity(playerid);
public CheckPostSpawnActivity(playerid) {
    if (!IsPlayerConnected(playerid)) return;
    if (gPlayerData[playerid][gFlaggedAsBot]) return;
    if (!gPlayerData[playerid][gSpawned]) return;

    if (gPlayerData[playerid][gMovementChanges] == 0
        && gPlayerData[playerid][gKeystrokeCount] == 0) {
        LogSuspiciousActivity(playerid, "No activity 30s post-spawn", 80);
    }
}

public OnPlayerKeyStateChange(playerid, newkeys, oldkeys) {
    gPlayerData[playerid][gKeystrokeCount]++;
    return 1;
}

public OnPlayerUpdate(playerid) {
    if (!IsPlayerConnected(playerid)) return 1;
    if (!gPlayerData[playerid][gSpawned]) return 1;

    new Float:x, Float:y, Float:z;
    GetPlayerPos(playerid, x, y, z);

    if (gPlayerData[playerid][gLastX] != 0.0
        || gPlayerData[playerid][gLastY] != 0.0
        || gPlayerData[playerid][gLastZ] != 0.0) {

        new Float:dx = x - gPlayerData[playerid][gLastX];
        new Float:dy = y - gPlayerData[playerid][gLastY];
        new Float:dz = z - gPlayerData[playerid][gLastZ];
        new Float:dist = floatsqroot(dx*dx + dy*dy + dz*dz);

        if (dist > 0.1) {
            gPlayerData[playerid][gMovementChanges]++;
        }
        if (dist > 100.0) {
            LogSuspiciousActivity(playerid, "Impossible movement distance", 50);
        }
    }

    gPlayerData[playerid][gLastX] = x;
    gPlayerData[playerid][gLastY] = y;
    gPlayerData[playerid][gLastZ] = z;
    return 1;
}

public OnDialogResponse(playerid, dialogid, response, listitem, inputtext[]) {
    if (dialogid == DIALOG_INVISIBLE_CHALLENGE) {
        new responseTime = GetTickCount() - gPlayerData[playerid][gChallengeStartTick];

        if (responseTime < 200) {
            LogSuspiciousActivity(playerid, "Challenge response too fast", 70);
        } else if (responseTime > 25000) {
            LogSuspiciousActivity(playerid, "Challenge response very slow", 30);
        } else {
            gPlayerData[playerid][gPassedChallenge] = true;
        }
        return 1;
    }
    return 0;
}

public OnPlayerDisconnect(playerid, reason) {
    if (gPlayerData[playerid][gActive] && !gPlayerData[playerid][gFlaggedAsBot]) {
        gTotalAllowed++;
    }
    ResetPlayerData(playerid);
    return 1;
}


public OnRconCommand(cmd[]) {
    new command[32], param[64];
    sscanf(cmd, "s[32]s[64]", command, param);

    if (!strcmp(command, "bc_status", true)) {
        printf("=== bot-checker v%s ===", PLUGIN_VERSION);
        printf("  L1 RPC validation:   %s", gFilterEnabled[1] ? "ON" : "OFF");
        printf("  L2 Timing analysis:  %s", gFilterEnabled[2] ? "ON" : "OFF");
        printf("  L3 IP reputation:    %s", gFilterEnabled[3] ? "ON" : "OFF");
        printf("  L4 Active challenges: %s", gFilterEnabled[4] ? "ON" : "OFF");
        printf("  Blocked: %d | Allowed: %d", gTotalBlocked, gTotalAllowed);
        return 1;
    }

    if (!strcmp(command, "bc_toggle", true)) {
        new level = strval(param);
        if (level >= 1 && level <= 4) {
            gFilterEnabled[level] = !gFilterEnabled[level];
            printf("Level %d -> %s", level, gFilterEnabled[level] ? "ON" : "OFF");
        } else {
            print("Uso: bc_toggle <1-4>");
        }
        return 1;
    }

    if (!strcmp(command, "bc_stats", true)) {
        new pid = strval(param);
        if (IsPlayerConnected(pid)) {
            printf("=== Player %d ===", pid);
            printf("  Score: %d", gPlayerData[pid][gSuspicionScore]);
            printf("  Keys: %d | Moves: %d",
                gPlayerData[pid][gKeystrokeCount],
                gPlayerData[pid][gMovementChanges]);
            printf("  Challenge: %s | Flagged: %s",
                gPlayerData[pid][gPassedChallenge] ? "PASS" : "NO",
                gPlayerData[pid][gFlaggedAsBot] ? "YES" : "NO");
        } else {
            print("Player no conectado.");
        }
        return 1;
    }

    return 0;
}

public OnFilterScriptInit() {
    print("==========================================");
    printf(" bot-checker v%s", PLUGIN_VERSION);
    print("  [1] RPC validation");
    print("  [2] Timing analysis");
    print("  [3] IP reputation");
    print("  [4] Active challenges");
    print("==========================================");
    LogToFile("bot-checker started");

    for (new i = 0; i < MAX_PLAYERS; i++) {
        ResetPlayerData(i);
    }
    return 1;
}

public OnFilterScriptExit() {
    LogToFile("bot-checker stopped");
    return 1;
}
