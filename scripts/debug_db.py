import sqlite3
import os

# 连接到数据库
conn = sqlite3.connect('security_scanner.db')
cursor = conn.cursor()

# 获取samples表的结构
cursor.execute("PRAGMA table_info(samples)")
columns = cursor.fetchall()
print("样本表结构:")
for col in columns:
    print(f"  {col[0]}: {col[1]} ({col[2]})")

# 获取样本数据
cursor.execute("SELECT id, filename, file_path, type, package_type FROM samples")
samples = cursor.fetchall()
print("\n样本数据:")
for sample in samples:
    print(f"  ID: {sample[0]}, 文件名: {sample[1]}, 路径: {sample[2]}, 类型: {sample[3]}, 包类型: {sample[4] if len(sample) > 4 else 'N/A'}")

# 检查文件路径是否存在
print("\n文件路径检查:")
for sample in samples:
    file_path = sample[2]
    exists = os.path.exists(file_path)
    print(f"  {file_path}: {'存在' if exists else '不存在'}")

conn.close() 