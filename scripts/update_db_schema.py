"""
更新数据库架构
"""
import sqlite3
import sys
import os
from datetime import datetime
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.config import Config

def update_schema():
    """更新数据库架构"""
    print("开始更新数据库架构...")
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查scan_records表是否存在updated_at字段
    cursor.execute("PRAGMA table_info(scan_records)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'updated_at' not in columns:
        print("添加updated_at字段到scan_records表...")
        cursor.execute("ALTER TABLE scan_records ADD COLUMN updated_at TIMESTAMP")
        
        # 初始化更新日期为创建日期
        cursor.execute("UPDATE scan_records SET updated_at = created_at")
        
        conn.commit()
        print("更新完成！")
    else:
        print("updated_at字段已存在，无需更新。")
    
    conn.close()

if __name__ == "__main__":
    update_schema() 