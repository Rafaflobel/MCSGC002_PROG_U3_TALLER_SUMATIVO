# invoke-ir.sh — Script de Respuesta ante Incidentes en Linux

Script Bash para automatizar la respuesta inicial ante un incidente de seguridad en un servidor Linux. Desarrollado como taller sumativo del módulo **Programación para la ciberseguridad** (Unidad 3: Scripting con Linux Shell), Universidad San Sebastián.

## Qué hace

Ante una alerta del SIEM por comportamiento anómalo, el script ejecuta secuencialmente:

1. **Preservación de evidencia volátil** — Captura el árbol completo de procesos (`ps aux --forest`) e identifica procesos sospechosos sin TTY y con consumo elevado de CPU.
2. **Preservación de evidencia de red** — Registra conexiones activas (`ss -tunap`), extrae conexiones establecidas hacia IP externas y excluye tráfico loopback.
3. **Verificación de integridad** — Calcula hashes SHA-256 de binarios críticos del sistema (`ls`, `ps`, `ss`, `netstat`, `find`, `who`, `iptables`).
4. **Contención inicial** — Bloquea la IP sospechosa con `iptables`, verificando duplicados y registrando el estado pre/post contención.
5. **Sellado criptográfico** — Genera hashes SHA-256 de todos los archivos de evidencia para garantizar la cadena de custodia.

## Uso

```bash
sudo bash invoke-ir.sh
```

Requiere privilegios de root. La evidencia se almacena en `/tmp/ir_evidence_<timestamp>/` con permisos `700`.

## Archivos generados

| Archivo                    | Descripción                            |
| -------------------------- | -------------------------------------- |
| `ir_audit.log`             | Log de auditoría con marcas temporales |
| `processes_full.txt`       | Árbol completo de procesos             |
| `processes_suspicious.txt` | Procesos detectados por heurística     |
| `network_full.txt`         | Conexiones TCP/UDP activas             |
| `network_external.txt`     | Conexiones ESTAB hacia IP externas     |
| `integrity_hashes.txt`     | Hashes SHA-256 de binarios críticos    |
| `iptables_before.txt`      | Reglas de firewall pre-contención      |
| `iptables_after.txt`       | Reglas de firewall post-contención     |
| `evidencia.sha256`         | Sellado criptográfico de la evidencia  |

## Revertir contención

```bash
sudo iptables -D INPUT -s 203.0.113.42 -j DROP
```

## Entorno de ejecución

- Ubuntu 26.04 (Intel N150)
- Bash 5.x
- Herramientas nativas: `ps`, `ss`, `sha256sum`, `iptables`, `awk`, `grep`, `find`

## Autor

Grupo 01 - Magíster en Ciberseguridad, USS
