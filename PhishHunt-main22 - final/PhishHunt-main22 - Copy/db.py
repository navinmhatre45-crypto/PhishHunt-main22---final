import mysql.connector
from mysql.connector import Error
from config import MYSQL

def get_conn():
    return mysql.connector.connect(
        host=MYSQL["host"],
        user=MYSQL["user"],
        password=MYSQL["password"],
        database=MYSQL["database"],
        port=MYSQL["port"]
    )

def log_result(input_type, raw_input, verdict, score, reasons_json):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO analysis_logs (input_type, raw_input, verdict, score, reasons) VALUES (%s,%s,%s,%s,%s)",
            (input_type, raw_input, verdict, score, reasons_json)
        )
        conn.commit()
    except Error as e:
        print("DB Error:", e)
    finally:
        try:
            cur.close(); conn.close()
        except: pass
