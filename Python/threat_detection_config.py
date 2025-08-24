THRESHOLDS = {
    "port_scan": {
        "alerts_no": 20,
        "time_window": 120,         # 2 minuti
        "action": "block_24h"
    },
    "brute_force": {
        "alerts_no": 5,       # tentativi di accesso
        "time_window": 180,         # 3 minuti
        "action": "block_1h"
    },
    "sql_injection": {
        "alerts_no": 500,   # signature matches
        "duration": 300,            # 5 minuti
        "action": "block_immediate"
    }
}