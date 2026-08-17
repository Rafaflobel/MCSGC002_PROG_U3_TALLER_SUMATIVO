#!/usr/bin/env bash

# invoke-ir.sh — Script de respuesta ante incidentes en Linux
# Módulo: Programación para la ciberseguridad (Unidad 3)
# Autor: Rafael Flores
# Fecha: 2026-08-15
# Descripción: Automatiza la recolección de evidencia volátil, verificación
#              de integridad de binarios críticos y contención inicial ante
#              una sospecha de intrusión activa en un servidor Linux.

set -euo pipefail

# CONSTANTES
# Esto es para identificar esta ejecución de forma única
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Directorio donde se almacenará la evidencia
readonly EVIDENCE_DIR="/tmp/ir_evidence_${TIMESTAMP}"

# Archivo de log/auditoría que registra cada acción del script
readonly LOG_FILE="${EVIDENCE_DIR}/ir_audit.log"

# IP sospechosa para este caso, identificada por el SIEM (rango RFC 5737 — documentación)
readonly SUSPECT_IP="203.0.113.42"

# Binarios críticos del sistema cuya integridad se verificará con SHA-256
readonly -a CRITICAL_BINS=(
    "/usr/bin/ls"
    "/usr/bin/ps"
    "/usr/bin/ss"
    "/usr/bin/netstat"
    "/usr/bin/find"
    "/usr/bin/who"
    "/usr/sbin/iptables"
)

# FUNCIONES DE BASE
# ------------------------------------------------------------------------------
# log_action: Registra un mensaje con marca temporal en el archivo de auditoría
#             y lo muestra simultáneamente en la salida estándar.
# Uso: log_action "NIVEL" "Mensaje descriptivo"
# Niveles: INFO, WARN, ERROR
# ------------------------------------------------------------------------------
log_action() {
    local level="${1}"
    local message="${2}"
    local entry
    entry="[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}"

    echo "${entry}" | tee -a "${LOG_FILE}"
}

# ------------------------------------------------------------------------------
# check_root: Verifica que el script se ejecute con privilegios de root.
#             Las operaciones de contención (iptables) y la lectura completa
#             de procesos y conexiones requieren UID 0.
# ------------------------------------------------------------------------------
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[ERROR] Este script debe ejecutarse como root (sudo)."
        echo "        Uso: sudo bash invoke-ir.sh"
        exit 1
    fi
}


# VALIDACIONES INICIALES
# 1. Verificar privilegios de root antes de cualquier otra acción
check_root

# 2. Crear el directorio de evidencia con permisos (solo root)
mkdir -p "${EVIDENCE_DIR}"
chmod 700 "${EVIDENCE_DIR}"

# 3. Registrar el inicio de la respuesta ante incidentes
log_action "INFO" "=== INICIO DE RESPUESTA ANTE INCIDENTES ==="
log_action "INFO" "Directorio de evidencia creado: ${EVIDENCE_DIR}"
log_action "INFO" "Permisos del directorio: $(stat -c '%a' "${EVIDENCE_DIR}")"
log_action "INFO" "Operador: $(whoami) | Hostname: $(hostname)"
log_action "INFO" "IP sospechosa objetivo: ${SUSPECT_IP}"


# PREGUNTA 2 — Preservación de evidencia volátil (procesos)
# ------------------------------------------------------------------------------
# collect_processes: Captura el estado completo de procesos del sistema,
#                    identifica procesos sospechosos (sin TTY y alto consumo
#                    de CPU) y registra advertencias en el log de auditoría.
# ------------------------------------------------------------------------------
collect_processes() {
    local proc_file="${EVIDENCE_DIR}/processes_full.txt"
    local suspicious_file="${EVIDENCE_DIR}/processes_suspicious.txt"
    local count

    # a) Captura completa del árbol de procesos
    log_action "INFO" "Capturando estado completo de procesos..."
    ps aux --forest > "${proc_file}" 2>&1
    log_action "INFO" "Snapshot de procesos almacenado en: ${proc_file}"

    # b) Registrar cantidad de procesos capturados (sin la cabecera)
    count="$(wc -l < "${proc_file}")"
    log_action "INFO" "Total de líneas capturadas: ${count}"

    # c) Identificar procesos sospechosos:
    #    - Sin TTY asignada (columna 7 = '?')  → posible proceso en background
    #      no interactivo, típico de shells reversas o miners
    #    - Con consumo de CPU > 5% (columna 3) → actividad inusual
    #    no se consideran las las cabeceras y el propio comando grep/awk
    log_action "INFO" "Buscando procesos sospechosos (sin TTY + CPU > 5%)..."
    awk 'NR > 1 && $7 == "?" && $3 > 5.0 {print $0}' "${proc_file}" \
        > "${suspicious_file}" 2>&1

    # d) Registrar advertencias si se detectan hallazgos
    if [[ -s "${suspicious_file}" ]]; then
        count="$(wc -l < "${suspicious_file}")"
        log_action "WARN" "Se detectaron ${count} proceso(s) sospechoso(s)."
        log_action "WARN" "Detalle en: ${suspicious_file}"

        # Registrar cada proceso sospechoso en el log de auditoría
        while IFS= read -r line; do
            log_action "WARN" "Proceso sospechoso: ${line}"
        done < "${suspicious_file}"
    else
        log_action "INFO" "No se detectaron procesos sospechosos."
    fi
}

# Ejecutar módulo de procesos
collect_processes

# PREGUNTA 3 — Preservación de evidencia de red
# ------------------------------------------------------------------------------
# collect_network: Captura las conexiones de red activas, registra aquellas
#                  con procesos asociados, extrae conexiones establecidas
#                  hacia IP externas y excluye tráfico local (127.0.0.1).
# ------------------------------------------------------------------------------
collect_network() {
    local net_file="${EVIDENCE_DIR}/network_full.txt"
    local external_file="${EVIDENCE_DIR}/network_external.txt"
    local count

    # a) Captura completa de conexiones activas
    #    -t: TCP  -u: UDP  -n: numérico  -a: todas  -p: proceso asociado
    log_action "INFO" "Capturando conexiones de red activas..."
    ss -tunap > "${net_file}" 2>&1
    log_action "INFO" "Snapshot de red almacenado en: ${net_file}"

    # b) Registrar cantidad de conexiones con procesos asociados
    #    Las líneas que contienen 'users:(' tienen un proceso vinculado
    count="$(grep -c 'users:(' "${net_file}" || true)"
    log_action "INFO" "Conexiones con proceso asociado: ${count}"

    # c) y d) Extraer conexiones ESTAB hacia IP externas,
    #         excluyendo tráfico local (127.0.0.1)
    #    - Filtra solo estado ESTAB (conexiones activamente establecidas)
    #    - Elimina cualquier línea que contenga 127.0.0.1 (loopback)
    #    Esto permite identificar comunicaciones activas con hosts remotos,
    #    relevantes para detectar exfiltración o C2 (Command & Control).
    log_action "INFO" "Extrayendo conexiones establecidas hacia IP externas..."
    grep 'ESTAB' "${net_file}" \
        | grep -v '127.0.0.1' \
        > "${external_file}" 2>&1 || true

    # Registrar hallazgos de conexiones externas
    if [[ -s "${external_file}" ]]; then
        count="$(wc -l < "${external_file}")"
        log_action "WARN" "Se detectaron ${count} conexión(es) externa(s) establecida(s)."
        log_action "WARN" "Detalle en: ${external_file}"

        while IFS= read -r line; do
            log_action "WARN" "Conexión externa: ${line}"
        done < "${external_file}"
    else
        log_action "INFO" "No se detectaron conexiones externas establecidas."
    fi
}

# Ejecutar módulo de red
collect_network

# PREGUNTA 4 — Verificación de integridad
# ----------------------------------------------------------------------------
# verify_integrity: Calcula hashes SHA-256 de los binarios críticos definidos
#                   en CRITICAL_BINS, almacena los resultados como evidencia
#                   y registra cada operación en el log de auditoría.
#                   Un atacante podría reemplazar binarios del sistema con
#                   versiones troyanizadas; los hashes permiten detectar
#                   alteraciones comparándolos con valores conocidos.
# -----------------------------------------------------------------------------
verify_integrity() {
    local hash_file="${EVIDENCE_DIR}/integrity_hashes.txt"
    local hash_value
    local verified=0
    local skipped=0

    log_action "INFO" "Iniciando verificación de integridad de binarios críticos..."
    log_action "INFO" "Binarios a verificar: ${#CRITICAL_BINS[@]}"

    # a) La lista de binarios está definida como constante readonly al inicio.
    # b) Recorrer cada binario y calcular su hash SHA-256.
    for binary in "${CRITICAL_BINS[@]}"; do

        # Validar que el binario existe antes de calcular el hash
        if [[ -f "${binary}" ]]; then
            hash_value="$(sha256sum "${binary}" | awk '{print $1}')"

            # c) Almacenar el resultado en el archivo de evidencia
            #    Formato: hash  ruta_del_binario (compatible con sha256sum --check)
            echo "${hash_value}  ${binary}" >> "${hash_file}"

            # d) Registrar la operación en el log de auditoría
            log_action "INFO" "SHA-256 [${binary}]: ${hash_value}"
            verified=$((verified + 1))
        else
            log_action "WARN" "Binario no encontrado: ${binary} — omitido."
            skipped=$((skipped + 1))
        fi
    done

    # Resumen de la verificación
    log_action "INFO" "Verificación completada: ${verified} verificado(s), ${skipped} omitido(s)."
    log_action "INFO" "Hashes almacenados en: ${hash_file}"
}

# Ejecutar módulo de integridad
verify_integrity

# PREGUNTA 5 — Contención inicial
# ------------------------------------------------------------------------------
# contain_threat: Aplica una regla de bloqueo con iptables para la IP
#                 sospechosa, verifica que la regla haya sido insertada
#                 correctamente y registra toda la operación en el log.
#                 Se implementa con precauciones para no afectar el tráfico
#                 legítimo del servidor en producción.
# -----------------------------------------------------------------------------
contain_threat() {
    local iptables_before="${EVIDENCE_DIR}/iptables_before.txt"
    local iptables_after="${EVIDENCE_DIR}/iptables_after.txt"

    log_action "INFO" "Iniciando contención de IP sospechosa: ${SUSPECT_IP}"

    # d) Precaución frente al impacto operativo:
    #    - Se captura el estado actual de iptables ANTES de modificar las reglas,
    #      permitiendo una restauración manual si la contención afecta servicios.
    #    - Se usa INSERT (-I) en lugar de APPEND (-A) para que la regla tenga
    #      prioridad, pero solo afecta a la IP específica (no al tráfico general).
    #    - Se bloquea únicamente INPUT desde esa IP, sin tocar OUTPUT ni FORWARD.
    log_action "INFO" "Capturando estado actual de iptables (pre-contención)..."
    iptables -L -n -v --line-numbers > "${iptables_before}" 2>&1
    log_action "INFO" "Reglas pre-contención almacenadas en: ${iptables_before}"

    # Verificar si la regla ya existe para evitar duplicados
    if iptables -C INPUT -s "${SUSPECT_IP}" -j DROP 2>/dev/null; then
        log_action "WARN" "La regla de bloqueo para ${SUSPECT_IP} ya existe. No se duplica."
    else
        # a) Aplicar la regla de bloqueo: descartar todo el tráfico entrante
        #    desde la IP sospechosa
        iptables -I INPUT 1 -s "${SUSPECT_IP}" -j DROP

        # b) Registrar la acción realizada
        log_action "INFO" "Regla aplicada: iptables -I INPUT 1 -s ${SUSPECT_IP} -j DROP"
    fi

    # c) Verificar que la regla fue aplicada correctamente
    log_action "INFO" "Verificando aplicación de la regla de bloqueo..."
    if iptables -C INPUT -s "${SUSPECT_IP}" -j DROP 2>/dev/null; then
        log_action "INFO" "Verificación exitosa: la IP ${SUSPECT_IP} está bloqueada en INPUT."
    else
        log_action "ERROR" "Verificación fallida: la regla NO se aplicó correctamente."
    fi

    # Capturar estado de iptables posterior a la contención
    iptables -L -n -v --line-numbers > "${iptables_after}" 2>&1
    log_action "INFO" "Reglas post-contención almacenadas en: ${iptables_after}"

    # d) Nota operativa en el log sobre reversión
    log_action "INFO" "Para revertir la contención ejecutar: iptables -D INPUT -s ${SUSPECT_IP} -j DROP"
}

# Ejecutar módulo de contención
contain_threat

# PREGUNTA 6 — Sellado criptográfico de la evidencia
# ------------------------------------------------------------------------------
# seal_evidence: Calcula hashes SHA-256 de todos los archivos de evidencia
#                generados durante la ejecución y los almacena en un archivo
#                de sellado. Esto permite verificar a posteriori que ningún
#                archivo fue modificado después de la recolección, fortaleciendo
#                la cadena de custodia de la evidencia digital.
# -----------------------------------------------------------------------------
seal_evidence() {
    local seal_file="${EVIDENCE_DIR}/evidencia.sha256"

    log_action "INFO" "Sellando evidencia criptográficamente..."

    # Recorrer todos los archivos del directorio de evidencia, excluyendo
    # el propio archivo de sellado para evitar referencia circular
    find "${EVIDENCE_DIR}" -type f ! -name "evidencia.sha256" \
        -exec sha256sum {} + > "${seal_file}"

    log_action "INFO" "Sellado completado. Archivo: ${seal_file}"
    log_action "INFO" "Para verificar integridad ejecutar: sha256sum --check ${seal_file}"
}

# Ejecutar cierre de la evidencia
seal_evidence
log_action "INFO" "=== FIN DE RESPUESTA ANTE INCIDENTES ==="
log_action "INFO" "Evidencia disponible en: ${EVIDENCE_DIR}"


