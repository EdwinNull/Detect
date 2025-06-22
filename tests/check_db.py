import sqlite3
import json
import os
from config.config import Config

def main():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查最新的特征数据
    cursor.execute('SELECT feature_data FROM features ORDER BY scan_id DESC LIMIT 1')
    result = cursor.fetchone()
    if result:
        features = json.loads(result[0])
        print(f"特征数量: {len(features)}")
        print("特征列表:")
        for key in features.keys():
            print(f"- {key}")
    else:
        print("没有找到特征数据")
    
    conn.close()

if __name__ == "__main__":
    main() 