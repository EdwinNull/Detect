#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
更新现有包记录，添加爬虫标记，用于测试
"""

import os
import sys
import sqlite3
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config

def mark_packages_as_crawled():
    print("开始更新爬虫标记...")
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 获取所有.tgz文件的ID
    cursor.execute('''
        SELECT id, filename 
        FROM scan_records 
        WHERE filename LIKE '%.tgz'
        LIMIT 5
    ''')
    
    records = cursor.fetchall()
    print(f"找到 {len(records)} 条记录")
    
    for id, filename in records:
        print(f"更新记录 ID: {id}, 文件名: {filename}")
        cursor.execute('''
            UPDATE scan_records 
            SET is_crawled = 1, 
                risk_level = 'high',
                confidence = 0.95
            WHERE id = ?
        ''', (id,))
    
    conn.commit()
    conn.close()
    
    print("更新完成")

if __name__ == "__main__":
    mark_packages_as_crawled() 