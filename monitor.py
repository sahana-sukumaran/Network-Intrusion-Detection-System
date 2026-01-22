import time
import threading
import re
import logging
from datetime import datetime
import pymysql
import pymysql.cursors
from dotenv import load_dotenv
import os
load_dotenv()
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except Exception as e:
    raise SystemExit("scapy is required. Install with: pip install scapy") from e
try:
    import nmap
except Exception as e:
    raise SystemExit("python-nmap is required. Install with: pip install python-nmap") from e
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "database": os.getenv("DB_NAME"),
    "autocommit": False,
    "cursorclass": pymysql.cursors.DictCursor
}
SUBNET = os.getenv("NIDS_SUBNET", "192.168.1.0/24")
SNIF_INTERFACE = os.getenv("NIDS_INTERFACE")
PACKET_COMMIT_BATCH = 1
RULE_SCAN_INTERVAL = 5
USER_SCAN_INTERVAL = 300
LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL, format="%(asctime)s %(levelname)s: %(message)s")
def get_db_connection():
    try:
        return pymysql.connect(**DB_CONFIG)
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        return None
def upsert_user(conn, ip):
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM USERS WHERE user_name = %s LIMIT 1", (ip,))
        r = cur.fetchone()
        if r and r.get("id"):
            uid = r["id"]
        else:
            cur.execute(
                "INSERT INTO USERS (user_name, role, created_at) VALUES (%s, %s, NOW())",
                (ip, "network_device")
            )
            conn.commit()
            uid = cur.lastrowid
        cur.close()
        return uid
    except Exception as e:
        logging.debug("upsert_user error: %s", e)
        try:
            cur.close()
        except Exception:
            pass
        return None
def insert_network_log(conn, user_ip, src_ip, dst_ip, sport, dport, protocol, size, flags):
    """
    Insert a row into NETWORK_LOGS. Your NETWORK_LOGS schema includes:
    (user_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_size, flags, timestamp, is_suspicious)
    """
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM USERS WHERE user_name = %s LIMIT 1", (user_ip,))
        rr = cur.fetchone()
        user_id = rr["id"] if rr else None

        cur.execute(
            """INSERT INTO NETWORK_LOGS
               (user_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_size, flags, timestamp, is_suspicious)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), 0)""",
            (user_id, src_ip, dst_ip, sport, dport, protocol, size, flags)
        )
        conn.commit()
        log_id = cur.lastrowid
        cur.close()
        return log_id
    except Exception as e:
        logging.debug("insert_network_log error: %s", e)
        try:
            cur.close()
        except Exception:
            pass
        return None
def mark_log_suspicious(conn, log_id):
    try:
        cur = conn.cursor()
        cur.execute("UPDATE NETWORK_LOGS SET is_suspicious = 1 WHERE id = %s", (log_id,))
        conn.commit()
        cur.close()
    except Exception as e:
        logging.debug("mark_log_suspicious error: %s", e)

def insert_alert(conn, message, rule_id, log_id):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO ALERTS (MESSAGE, RULE_ID, LOG_ID, ALERT_TIME) VALUES (%s, %s, %s, NOW())",
                    (message, rule_id, log_id))
        conn.commit()
        cur.close()
    except Exception as e:
        logging.debug("insert_alert error: %s", e)

def fetch_active_rules(conn):
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM RULES WHERE ACTIVE = 1")
        rows = cur.fetchall()
        cur.close()
        return rows
    except Exception as e:
        logging.debug("fetch_active_rules error: %s", e)
        return []

def fetch_unprocessed_logs(conn, limit=1000):
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM NETWORK_LOGS WHERE is_suspicious = 0 ORDER BY id ASC LIMIT %s", (limit,))
        rows = cur.fetchall()
        cur.close()
        return rows
    except Exception as e:
        logging.debug("fetch_unprocessed_logs error: %s", e)
        return []

def sql_to_python_expr(expr):
    if not expr:
        return expr
    s = expr.strip()
    s = s.replace('"', "'")

    s = re.sub(r"(\b\w+\b)\s+LIKE\s+'%([^']+)%'", lambda m: f"'{m.group(2)}' in {m.group(1)}", s, flags=re.I)

    s = re.sub(r"(\b\w+\b)\s+LIKE\s+'([^%']+)%'", lambda m: f"{m.group(1)}.startswith('{m.group(2)}')", s, flags=re.I)
 
    s = re.sub(r"(\b\w+\b)\s+LIKE\s+'%([^']+)'", lambda m: f"{m.group(1)}.endswith('{m.group(2)}')", s, flags=re.I)

    s = re.sub(r"\bIS\s+NULL\b", "is None", s, flags=re.I)
    s = re.sub(r"\bIS\s+NOT\s+NULL\b", "is not None", s, flags=re.I)

    s = re.sub(r"\bAND\b", "and", s, flags=re.I)
    s = re.sub(r"\bOR\b", "or", s, flags=re.I)
    s = re.sub(r"\bNOT\b", "not", s, flags=re.I)

    s = re.sub(r"(?<![<>!])=(?!=)", "==", s)
    s = re.sub(r"\bNULL\b", "None", s, flags=re.I)

    return re.sub(r"\s+", " ", s).strip()

def safe_eval(py_expr, context):
    try:
        safe_globals = {"__builtins__": None}
        return bool(eval(py_expr, safe_globals, context))
    except Exception as e:
        logging.debug("safe_eval error for expr '%s': %s", py_expr, e)
        return False

def nmap_scan_loop(stop_event):
    nm = nmap.PortScanner()
    while not stop_event.is_set():
        try:
            logging.info("Running nmap ping scan on %s", SUBNET)
            nm.scan(hosts=SUBNET, arguments='-sn')
            conn = get_db_connection()
            if not conn:
                stop_event.wait(USER_SCAN_INTERVAL)
                continue
            for host in nm.all_hosts():
                try:
                    if nm[host].state() == "up":
                        logging.info("Found host: %s", host)
                        upsert_user(conn, host)
                except Exception as e:
                    logging.debug("nmap host handling error: %s", e)
            conn.close()
        except Exception as e:
            logging.error("nmap scan failed: %s", e)
        stop_event.wait(USER_SCAN_INTERVAL)

def packet_sniffer_loop(stop_event):
    conn = get_db_connection()
    if not conn:
        return
    packet_count = 0

    def process_packet(packet):
        nonlocal packet_count
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                size = len(packet)
                protocol = None
                sport = None
                dport = None
                flags = ""

                if TCP in packet:
                    protocol = "TCP"
                    sport, dport = packet[TCP].sport, packet[TCP].dport
                    flags = packet.sprintf("%TCP.flags%") or ""
                elif UDP in packet:
                    protocol = "UDP"
                    sport, dport = packet[UDP].sport, packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"
                else:
                    protocol = str(packet[IP].proto)

                upsert_user(conn, src)
                log_id = insert_network_log(conn, src, src, dst, sport, dport, protocol, size, flags)
                if log_id:
                    packet_count += 1
                    if packet_count % 10 == 0:
                        logging.info("Captured %d packets", packet_count)
                    # debug line for immediate feedback
                    logging.debug("Inserted network_log id=%s for %s -> %s proto=%s size=%s", log_id, src, dst, protocol, size)

        except Exception as e:
            logging.debug("Error handling packet: %s", e)

    logging.info("Starting packet capture on %s", SNIF_INTERFACE or "default")
    try:
        sniff(iface=SNIF_INTERFACE, prn=process_packet, store=0, stop_filter=lambda x: stop_event.is_set(), promisc=True)
    except Exception as e:
        logging.error("Packet sniffing failed: %s", e)
    finally:
        conn.close()

def rule_engine_loop(stop_event):
    conn = get_db_connection()
    if not conn:
        return
    while not stop_event.is_set():
        try:
            rules = fetch_active_rules(conn)
            compiled_rules = []
            for r in rules:
                rc = r.get("CONDITION") or r.get("rule_condition") or ""
                py_expr = sql_to_python_expr(rc)
                compiled_rules.append({
                    "id": r.get("id"),
                    "name": r.get("RULE_NAME") or r.get("rule_name") or "Unnamed Rule",
                    "severity": r.get("SEVERITY") or r.get("severity"),
                    "expr": py_expr
                })

            logs = fetch_unprocessed_logs(conn, limit=500)
            if not logs:
                stop_event.wait(RULE_SCAN_INTERVAL)
                continue

            for log in logs:
                context = {
                    "packet_size": log.get("packet_size"),
                    "destination_port": log.get("destination_port"),
                    "source_port": log.get("source_port"),
                    "protocol": log.get("protocol"),
                    "flags": log.get("flags")
                }

                matched_any = False
                for cr in compiled_rules:
                    expr = cr["expr"]
                    if expr and safe_eval(expr, context):
                        message = f"{cr['name']} detected on {log.get('destination_ip')} (Severity: {cr.get('severity')})"
                        insert_alert(conn, message, cr["id"], log["id"])
                        mark_log_suspicious(conn, log["id"])
                        logging.info("[ALERT] %s (rule_id=%s, log_id=%s)", message, cr["id"], log["id"])
                        matched_any = True
            stop_event.wait(RULE_SCAN_INTERVAL)
        except Exception as e:
            logging.error("Rule engine error: %s", e)
            stop_event.wait(RULE_SCAN_INTERVAL)
    conn.close()

def main():
    logging.info("Starting integrated NIDS monitor")
    stop_event = threading.Event()
    threads = [
        threading.Thread(target=nmap_scan_loop, args=(stop_event,), daemon=True),
        threading.Thread(target=packet_sniffer_loop, args=(stop_event,), daemon=True),
        threading.Thread(target=rule_engine_loop, args=(stop_event,), daemon=True)
    ]
    for t in threads:
        t.start()
    logging.info("All threads started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping monitor...")
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        logging.info("Monitor stopped.")

if __name__ == "__main__":
    main()