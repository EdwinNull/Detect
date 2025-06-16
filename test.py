import sqlite3
conn = sqlite3.connect('security_scanner.db')
cursor = conn.cursor()
try:
    cursor.execute("ALTER TABLE scan_records ADD COLUMN package_type TEXT;")
except Exception as e:
    print("字段可能已存在：", e)
conn.commit()
conn.close()