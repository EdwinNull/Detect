import sqlite3
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config

def update_database_schema():
    """更新数据库结构，添加恶意代码位置信息字段和爬虫标记字段"""
    print("开始更新数据库结构...")
    
    # 确保数据库文件存在
    if not os.path.exists(Config.DATABASE_PATH):
        print(f"错误: 数据库文件不存在: {Config.DATABASE_PATH}")
        return False
    
    try:
        # 连接到数据库
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # 检查 malicious_code_info 列是否已存在
        cursor.execute("PRAGMA table_info(scan_records)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'malicious_code_info' not in column_names:
            # 添加 malicious_code_info 列
            cursor.execute('''
                ALTER TABLE scan_records
                ADD COLUMN malicious_code_info TEXT
            ''')
            print("已添加 malicious_code_info 列")
        else:
            print("malicious_code_info 列已存在")
        
        # 检查 is_crawled 列是否已存在
        if 'is_crawled' not in column_names:
            # 添加 is_crawled 列
            cursor.execute('''
                ALTER TABLE scan_records
                ADD COLUMN is_crawled INTEGER DEFAULT 0
            ''')
            print("已添加 is_crawled 列")
        else:
            print("is_crawled 列已存在")
        
        # 提交更改
        conn.commit()
        conn.close()
        
        print("数据库更新完成")
        return True
    
    except Exception as e:
        print(f"更新数据库结构时出错: {e}")
        return False

if __name__ == "__main__":
    update_database_schema() 