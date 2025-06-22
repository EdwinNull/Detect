"""
更新社区模块的数据库架构
"""
import sqlite3
import os
import sys
from pathlib import Path
import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.config import Config

def update_schema():
    """更新数据库架构"""
    print("开始更新社区模块数据库架构...")
    
    # 确保数据库目录存在
    db_dir = os.path.dirname(Config.DATABASE_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # 连接数据库
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查community_posts表是否存在category字段
    cursor.execute("PRAGMA table_info(community_posts)")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    
    if 'category' not in column_names:
        print("添加category字段到community_posts表...")
        cursor.execute("ALTER TABLE community_posts ADD COLUMN category TEXT DEFAULT 'discovery'")
        conn.commit()
    
    # 检查是否存在post_likes表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='post_likes'")
    if not cursor.fetchone():
        print("创建post_likes表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (post_id) REFERENCES community_posts (id),
                UNIQUE(user_id, post_id)
            )
        ''')
        conn.commit()
    
    # 检查是否存在comment_likes表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='comment_likes'")
    if not cursor.fetchone():
        print("创建comment_likes表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comment_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                comment_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (comment_id) REFERENCES community_comments (id),
                UNIQUE(user_id, comment_id)
            )
        ''')
        conn.commit()
    
    # 如果存在旧的community_likes表，迁移数据
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='community_likes'")
    if cursor.fetchone():
        print("从community_likes表迁移数据...")
        
        # 迁移帖子点赞数据
        cursor.execute('''
            INSERT OR IGNORE INTO post_likes (user_id, post_id, created_at)
            SELECT user_id, post_id, created_at FROM community_likes
            WHERE post_id IS NOT NULL
        ''')
        
        # 迁移评论点赞数据
        cursor.execute('''
            INSERT OR IGNORE INTO comment_likes (user_id, comment_id, created_at)
            SELECT user_id, comment_id, created_at FROM community_likes
            WHERE comment_id IS NOT NULL
        ''')
    
    # 检查是否存在post_reports表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='post_reports'")
    if not cursor.fetchone():
        print("创建post_reports表...")
        cursor.execute('''
            CREATE TABLE post_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY (post_id) REFERENCES community_posts (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    
    conn.commit()
    conn.close()
    print("数据库架构更新完成！")

if __name__ == "__main__":
    update_schema() 