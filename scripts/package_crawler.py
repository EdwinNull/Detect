#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
开源包抓取工具
支持从 npm 和 PyPI 抓取包进行安全检测
"""

import requests
import json
import time
import os
import sys
import zipfile
import tarfile
import shutil
from urllib.parse import urljoin, urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
import hashlib
import sqlite3
from config.config import Config

class PackageCrawler:
    def __init__(self):
        self.download_dir = Path("downloads")
        self.download_dir.mkdir(exist_ok=True)
        self.npm_dir = self.download_dir / "npm"
        self.pypi_dir = self.download_dir / "pypi"
        self.npm_dir.mkdir(exist_ok=True)
        self.pypi_dir.mkdir(exist_ok=True)
        
        # 数据库连接
        self.db_path = Config.DATABASE_PATH
        
    def crawl_npm_packages(self, limit=10):
        """从npm抓取最新的包"""
        print(f"开始抓取npm包，限制数量: {limit}")
        
        # 直接使用知名包列表，避免API问题
        popular_packages = [
            "express", "lodash", "axios", "moment", "chalk",
            "react", "vue", "angular", "jquery", "bootstrap"
        ]
        
        for i, name in enumerate(popular_packages[:limit]):
            try:
                print(f"[{i+1}/{limit}] 下载知名包: {name}")
                self.download_npm_package(name, "latest")
                time.sleep(1)
            except Exception as e:
                print(f"下载 {name} 失败: {e}")
                continue
    
    def download_npm_package(self, name, version):
        """下载指定的npm包"""
        try:
            # 使用npm pack命令下载
            cmd = f"npm pack {name}@{version}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.npm_dir)
            
            if result.returncode == 0:
                # 查找下载的文件
                tgz_files = list(self.npm_dir.glob(f"{name}-*.tgz"))
                if tgz_files:
                    file_path = tgz_files[0]
                    print(f"  [OK] 下载成功: {file_path.name}")
                    
                    # 保存到数据库
                    self.save_package_info(name, version, str(file_path), 'npm')
                else:
                    print(f"  [ERROR] 未找到下载的文件")
            else:
                print(f"  [ERROR] 下载失败: {result.stderr}")
                
        except Exception as e:
            print(f"  [ERROR] 下载异常: {e}")
    
    def crawl_pypi_packages(self, limit=10):
        """从PyPI抓取最新的包"""
        print(f"开始抓取PyPI包，限制数量: {limit}")
        
        try:
            # 这里简化处理，实际应该解析HTML或使用API
            # 为了演示，我们下载一些知名包
            popular_packages = [
                "requests", "numpy", "pandas", "flask", "django",
                "matplotlib", "scikit-learn", "tensorflow", "pytorch", "fastapi"
            ]
            
            for i, name in enumerate(popular_packages[:limit]):
                try:
                    print(f"[{i+1}/{limit}] 下载: {name}")
                    self.download_pypi_package(name)
                    time.sleep(1)
                except Exception as e:
                    print(f"下载 {name} 失败: {e}")
                    continue
                    
        except Exception as e:
            print(f"抓取PyPI包失败: {e}")
    
    def download_pypi_package(self, name):
        """下载指定的PyPI包"""
        try:
            # 使用pip download命令
            cmd = f"pip download {name} --no-deps --no-binary=:all: -d {self.pypi_dir}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # 查找下载的文件
                tar_files = list(self.pypi_dir.glob(f"{name}-*.tar.gz"))
                if tar_files:
                    file_path = tar_files[0]
                    print(f"  [OK] 下载成功: {file_path.name}")
                    
                    # 保存到数据库
                    self.save_package_info(name, "latest", str(file_path), 'pypi')
                else:
                    print(f"  [ERROR] 未找到下载的文件")
            else:
                print(f"  [ERROR] 下载失败: {result.stderr}")
                
        except Exception as e:
            print(f"  [ERROR] 下载异常: {e}")
    
    def save_package_info(self, name, version, file_path, package_type):
        """保存包信息到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 检查是否已存在
            cursor.execute('''
                SELECT id FROM scan_records 
                WHERE filename = ? AND package_type = ?
            ''', (os.path.basename(file_path), package_type))
            
            if not cursor.fetchone():
                # 插入新记录
                cursor.execute('''
                    INSERT INTO scan_records 
                    (user_id, filename, file_size, file_hash, scan_status, package_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    1,  # 默认用户ID
                    os.path.basename(file_path),
                    os.path.getsize(file_path),
                    self.calculate_file_hash(file_path),
                    'pending',
                    package_type,
                    datetime.now()
                ))
                conn.commit()
                print(f"  [OK] 已保存到数据库")
            else:
                print(f"  [WARN] 包已存在，跳过")
                
            conn.close()
            
        except Exception as e:
            print(f"  [ERROR] 保存到数据库失败: {e}")
    
    def calculate_file_hash(self, file_path):
        """计算文件哈希"""
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def list_downloaded_packages(self):
        """列出已下载的包"""
        print("\n=== 已下载的包 ===")
        
        # npm包
        npm_files = list(self.npm_dir.glob("*.tgz"))
        print(f"\nNPM包 ({len(npm_files)}个):")
        for file in npm_files:
            print(f"  - {file.name}")
        
        # PyPI包
        pypi_files = list(self.pypi_dir.glob("*.tar.gz"))
        print(f"\nPyPI包 ({len(pypi_files)}个):")
        for file in pypi_files:
            print(f"  - {file.name}")
    
    def run_crawler(self, npm_limit=5, pypi_limit=5):
        """运行抓取器"""
        print("=== 开源包抓取工具 ===")
        print(f"下载目录: {self.download_dir.absolute()}")
        print(f"数据库: {self.db_path}")
        
        # 抓取npm包
        if npm_limit > 0:
            self.crawl_npm_packages(npm_limit)
        
        # 抓取PyPI包
        if pypi_limit > 0:
            self.crawl_pypi_packages(pypi_limit)
        
        # 显示结果
        self.list_downloaded_packages()
        
        print("\n=== 抓取完成 ===")
        print("您可以在Web界面中查看和检测这些包")

def main():
    """主函数"""
    crawler = PackageCrawler()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "npm":
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            crawler.crawl_npm_packages(limit)
        elif command == "pypi":
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            crawler.crawl_pypi_packages(limit)
        elif command == "list":
            crawler.list_downloaded_packages()
        else:
            print("用法: python package_crawler.py [npm|pypi|list] [数量]")
    else:
        # 默认抓取
        crawler.run_crawler()

if __name__ == "__main__":
    main() 