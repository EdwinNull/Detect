import requests
import json
import os
import tempfile
import time
import random
from urllib.request import urlretrieve
import sqlite3
from config import Config
import threading
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta

class PackageFetcher:
    """自动抓取PyPI和npm包的服务"""
    
    def __init__(self):
        self.pypi_base_url = "https://pypi.org"
        self.pypi_simple_url = "https://pypi.org/simple/"
        self.pypi_search_url = "https://pypi.org/search/"
        self.npm_api_url = "https://registry.npmjs.org"
        self.temp_dir = tempfile.gettempdir()
        self.pypi_last_fetched = {}  # 记录已经抓取过的包，避免重复
        self.npm_last_fetched = {}
        self.page_size = 20  # PyPI搜索页面每页显示的包数量
    
    def fetch_latest_packages(self, limit=5):
        """抓取最新的PyPI和npm包"""
        try:
            print(f"开始抓取最新的包，目标数量: {limit}")
            pypi_packages = self.fetch_latest_pypi(limit)
            npm_packages = self.fetch_latest_npm(limit // 5)  # npm包数量控制为PyPI的1/5
            
            all_packages = pypi_packages + npm_packages
            print(f"成功抓取到 {len(all_packages)} 个包（PyPI: {len(pypi_packages)}, npm: {len(npm_packages)}）")
            
            # 确保包列表不为空
            if all_packages:
                # 自动检测抓取到的包
                print(f"准备开始检测 {len(all_packages)} 个抓取到的包...")
                self.scan_all_packages(all_packages)
                print(f"所有包的检测任务已提交完成")
            else:
                print("未抓取到任何包，跳过检测步骤")
            
            return all_packages
        except Exception as e:
            print(f"抓取包时出错: {e}")
            import traceback
            print(traceback.format_exc())
            return []
    
    def fetch_latest_pypi(self, limit=100):
        """抓取最新的PyPI包，获取多页结果以达到目标数量"""
        try:
            print(f"开始获取PyPI最新包，目标数量: {limit}...")
            
            # 直接使用随机方法获取包，放弃搜索页面方法，因为搜索页面结构可能变化
            print(f"使用Simple API随机抓取PyPI包...")
            packages = self.fetch_random_pypi_packages(limit)
                
            print(f"PyPI包抓取完成，共获取 {len(packages)} 个包")
            return packages
        except Exception as e:
            print(f"抓取PyPI包时出错: {e}")
            # 尝试回退到简单随机抓取一些包
            return self.fetch_simple_random_packages(limit)
    
    def _fetch_pypi_page(self, page=1, limit=20):
        """获取PyPI搜索页面的一页结果（不再使用，仅作备份）"""
        try:
            # 获取最新上传的包（按上传时间排序）
            params = {
                "q": "",
                "o": "-created",  # 按创建时间倒序排列
                "c": "Programming Language :: Python",
                "page": page
            }
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml"
            }
            
            response = requests.get(self.pypi_search_url, params=params, headers=headers)
            if response.status_code != 200:
                print(f"PyPI 搜索页面返回错误: {response.status_code} (页面 {page})")
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            package_elements = soup.select('.package-snippet')
            
            if not package_elements:
                print(f"页面 {page} 未找到包元素，可能是最后一页或解析错误")
                return []
            
            packages = []
            
            for package_element in package_elements:
                if len(packages) >= limit:
                    break
                    
                try:
                    package_name = package_element.select_one('.package-snippet__name').text.strip()
                    
                    # 跳过已抓取的包
                    if package_name in self.pypi_last_fetched:
                        continue
                    
                    # 获取包详情
                    package_info = self.get_pypi_package_info(package_name)
                    if not package_info:
                        continue
                    
                    # 下载包
                    download_url = package_info.get('download_url')
                    if not download_url:
                        continue
                    
                    file_path = self.download_package(download_url, package_name)
                    if file_path:
                        packages.append({
                            'name': package_name,
                            'version': package_info.get('version'),
                            'file_path': file_path,
                            'size': os.path.getsize(file_path),
                            'type': 'pypi',
                            'source': 'auto'
                        })
                        
                        # 记录已抓取
                        self.pypi_last_fetched[package_name] = time.time()
                except Exception as e:
                    print(f"处理PyPI包 {package_name if 'package_name' in locals() else '未知'} 时出错: {e}")
                    continue
            
            return packages
        except Exception as e:
            print(f"获取PyPI页面 {page} 时出错: {e}")
            return []
    
    def fetch_random_pypi_packages(self, limit=5):
        """随机抓取一些PyPI包作为备选方案"""
        try:
            print(f"开始随机抓取PyPI包，目标数量: {limit}...")
            # 获取simple页面，里面有所有包的列表
            response = requests.get(self.pypi_simple_url)
            if response.status_code != 200:
                print(f"PyPI Simple API返回错误: {response.status_code}")
                return self.fetch_simple_random_packages(limit)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            all_packages = soup.find_all('a')
            
            if not all_packages:
                print("无法从PyPI Simple API获取包列表，尝试使用简单方法")
                return self.fetch_simple_random_packages(limit)
                
            print(f"从PyPI Simple API获取到 {len(all_packages)} 个包名")
            
            # 随机选择一些包
            sample_size = min(limit * 5, len(all_packages))  # 增加抽样比例，提高成功率
            random_packages = random.sample(all_packages, sample_size)
            
            packages = []
            for package_link in random_packages:
                if len(packages) >= limit:
                    break
                    
                try:
                    package_name = package_link.text.strip()
                    
                    # 跳过已抓取的包
                    if package_name in self.pypi_last_fetched:
                        continue
                    
                    # 获取包详情
                    package_info = self.get_pypi_package_info(package_name)
                    if not package_info:
                        continue
                    
                    # 下载包
                    download_url = package_info.get('download_url')
                    if not download_url:
                        continue
                    
                    file_path = self.download_package(download_url, package_name)
                    if file_path:
                        packages.append({
                            'name': package_name,
                            'version': package_info.get('version'),
                            'file_path': file_path,
                            'size': os.path.getsize(file_path),
                            'type': 'pypi',
                            'source': 'auto'
                        })
                        
                        # 记录已抓取
                        self.pypi_last_fetched[package_name] = time.time()
                        
                        print(f"成功抓取PyPI包: {package_name} v{package_info.get('version')}")
                except Exception as e:
                    print(f"处理随机PyPI包 {package_name if 'package_name' in locals() else '未知'} 时出错: {e}")
                    continue
            
            print(f"随机抓取PyPI包完成，获取 {len(packages)} 个包")
            
            # 如果没有抓到足够的包，尝试使用简单方法补充
            if len(packages) < limit // 2:
                print(f"随机抓取仅获取到 {len(packages)} 个包，尝试使用简单方法补充...")
                simple_packages = self.fetch_simple_random_packages(limit - len(packages))
                packages.extend(simple_packages)
                
            return packages
        except Exception as e:
            print(f"随机抓取PyPI包时出错: {e}")
            return self.fetch_simple_random_packages(limit)
    
    def fetch_simple_random_packages(self, limit=5):
        """使用简单方法随机生成包名并尝试抓取"""
        print(f"使用简单方法随机抓取PyPI包，目标数量: {limit}...")
        
        # 一些常见的包名前缀
        prefixes = ['py', 'python', 'django', 'flask', 'requests', 'pandas', 'numpy', 'scikit', 'tensorflow', 
                   'torch', 'crypto', 'data', 'web', 'api', 'test', 'dev', 'cloud', 'aws', 'azure', 'google',
                   'ml', 'ai', 'deep', 'net', 'io', 'util', 'tool', 'helper', 'common', 'core', 'base', 'lib',
                   'service', 'cli', 'app', 'framework', 'plugin', 'module', 'package', 'sdk', 'client', 'server']
        
        # 一些常见的包名
        common_packages = ['django', 'flask', 'requests', 'numpy', 'pandas', 'pytest', 'black', 'pylint', 
                          'sphinx', 'tox', 'sqlalchemy', 'click', 'rich', 'typer', 'fastapi', 'pillow',
                          'matplotlib', 'seaborn', 'beautifulsoup4', 'scrapy', 'celery', 'redis', 'pyyaml',
                          'jsonschema', 'pydantic', 'httpx', 'uvicorn', 'gunicorn', 'jinja2', 'aiohttp']
        
        packages = []
        attempts = 0
        max_attempts = limit * 10
        
        # 先尝试常见包
        for package_name in common_packages:
            if len(packages) >= limit:
                break
                
            if package_name in self.pypi_last_fetched:
                continue
                
            try:
                package_info = self.get_pypi_package_info(package_name)
                if not package_info:
                    continue
                
                download_url = package_info.get('download_url')
                if not download_url:
                    continue
                
                file_path = self.download_package(download_url, package_name)
                if file_path:
                    packages.append({
                        'name': package_name,
                        'version': package_info.get('version'),
                        'file_path': file_path,
                        'size': os.path.getsize(file_path),
                        'type': 'pypi',
                        'source': 'auto'
                    })
                    
                    self.pypi_last_fetched[package_name] = time.time()
                    print(f"成功抓取常见PyPI包: {package_name} v{package_info.get('version')}")
            except Exception as e:
                print(f"处理常见包 {package_name} 时出错: {e}")
                continue
        
        # 如果常见包不够，尝试随机生成
        while len(packages) < limit and attempts < max_attempts:
            attempts += 1
            
            # 生成随机包名
            prefix = random.choice(prefixes)
            suffix = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(random.randint(3, 8)))
            package_name = f"{prefix}-{suffix}"
            
            if package_name in self.pypi_last_fetched:
                continue
            
            try:
                package_info = self.get_pypi_package_info(package_name)
                if not package_info:
                    continue
                
                download_url = package_info.get('download_url')
                if not download_url:
                    continue
                
                file_path = self.download_package(download_url, package_name)
                if file_path:
                    packages.append({
                        'name': package_name,
                        'version': package_info.get('version'),
                        'file_path': file_path,
                        'size': os.path.getsize(file_path),
                        'type': 'pypi',
                        'source': 'auto'
                    })
                    
                    self.pypi_last_fetched[package_name] = time.time()
                    print(f"成功抓取随机生成的PyPI包: {package_name} v{package_info.get('version')}")
            except Exception as e:
                continue
        
        print(f"简单方法抓取PyPI包完成，获取 {len(packages)} 个包")
        return packages
    
    def get_pypi_package_info(self, package_name):
        """获取PyPI包的详细信息"""
        try:
            response = requests.get(f"{self.pypi_base_url}/pypi/{package_name}/json")
            if response.status_code != 200:
                return None
            
            data = response.json()
            releases = data.get('releases', {})
            
            if not releases:
                return None
            
            # 获取最新版本
            latest_version = data.get('info', {}).get('version')
            if not latest_version or latest_version not in releases:
                versions = list(releases.keys())
                if not versions:
                    return None
                latest_version = versions[-1]
            
            release_files = releases.get(latest_version, [])
            if not release_files:
                return None
            
            # 优先选择whl文件，其次是tar.gz
            whl_files = [f for f in release_files if f.get('packagetype') == 'bdist_wheel']
            tar_files = [f for f in release_files if f.get('packagetype') == 'sdist']
            
            download_file = None
            if whl_files:
                download_file = whl_files[0]
            elif tar_files:
                download_file = tar_files[0]
            else:
                download_file = release_files[0]
            
            return {
                'name': package_name,
                'version': latest_version,
                'download_url': download_file.get('url'),
                'file_name': download_file.get('filename')
            }
        except Exception as e:
            print(f"获取PyPI包信息时出错: {e}")
            return None
    
    def fetch_latest_npm(self, limit=20):
        """抓取最新的npm包"""
        try:
            print(f"开始抓取npm最新包，目标数量: {limit}...")
            # 使用npm的搜索API获取最近的包
            response = requests.get(f"{self.npm_api_url}/-/v1/search?text=boost:recent&size={min(100, limit * 2)}")
                
            if response.status_code != 200:
                print(f"npm API返回错误: {response.status_code}")
                return []
            
            data = response.json()
            packages = []
            
            # 解析搜索结果
            items = data.get('objects', [])
            print(f"从npm API获取到 {len(items)} 个包信息")
            
            for item in items:
                if len(packages) >= limit:
                    break
                    
                try:
                    package = item.get('package', {})
                    package_name = package.get('name')
                    
                    if not package_name or package_name in self.npm_last_fetched:
                        continue
                    
                    # 获取包详情
                    package_info = self.get_npm_package_info(package_name)
                    if not package_info:
                        continue
                    
                    # 下载包
                    download_url = package_info.get('download_url')
                    if not download_url:
                        continue
                    
                    file_path = self.download_package(download_url, package_name)
                    if file_path:
                        packages.append({
                            'name': package_name,
                            'version': package_info.get('version'),
                            'file_path': file_path,
                            'size': os.path.getsize(file_path),
                            'type': 'npm',
                            'source': 'auto'
                        })
                        
                        # 记录已抓取
                        self.npm_last_fetched[package_name] = time.time()
                        print(f"成功抓取npm包: {package_name} v{package_info.get('version')}")
                except Exception as e:
                    print(f"处理npm包 {package_name if 'package_name' in locals() else '未知'} 时出错: {e}")
                    continue
            
            print(f"npm包抓取完成，共获取 {len(packages)} 个包")
            return packages
        except Exception as e:
            print(f"抓取npm包时出错: {e}")
            return []
    
    def get_npm_package_info(self, package_name):
        """获取npm包的详细信息"""
        try:
            response = requests.get(f"{self.npm_api_url}/{package_name}")
            if response.status_code != 200:
                return None
            
            data = response.json()
            latest_version = data.get('dist-tags', {}).get('latest')
            
            if not latest_version:
                return None
            
            version_info = data.get('versions', {}).get(latest_version, {})
            if not version_info:
                return None
            
            dist = version_info.get('dist', {})
            tarball = dist.get('tarball')
            
            if not tarball:
                return None
            
            return {
                'name': package_name,
                'version': latest_version,
                'download_url': tarball,
                'file_name': f"{package_name}-{latest_version}.tgz"
            }
        except Exception as e:
            print(f"获取npm包信息时出错: {e}")
            return None
    
    def download_package(self, url, package_name):
        """下载包文件到临时目录"""
        try:
            file_name = url.split('/')[-1]
            file_path = os.path.join(Config.UPLOAD_FOLDER, file_name)
            
            # 确保目录存在
            os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
            
            # 下载文件
            urlretrieve(url, file_path)
            
            if os.path.exists(file_path):
                return file_path
            return None
        except Exception as e:
            print(f"下载包文件时出错: {e}")
            return None
    
    def scan_package(self, package_info, admin_user_id=1):
        """扫描下载的包"""
        from app.tasks import background_scan, scan_tasks
        
        try:
            # 创建扫描记录
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            
            # 使用admin用户ID创建记录
            cursor.execute('''
                INSERT INTO scan_records 
                (user_id, filename, file_size, file_hash, scan_status, package_type, source) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                admin_user_id, 
                package_info['name'], 
                package_info['size'],
                'auto_' + str(int(time.time())),  # 使用时间戳作为hash
                'pending',
                package_info['type'],
                'auto'  # 标记为自动抓取
            ))
            
            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # 初始化任务状态
            scan_tasks[scan_id] = {
                'status': 'pending',
                'progress': 0,
                'current_task': '开始检测'
            }
            
            # 启动后台扫描任务
            thread = threading.Thread(
                target=background_scan, 
                args=(scan_id, package_info['file_path'], admin_user_id)
            )
            thread.daemon = True
            thread.start()
            
            return scan_id
        except Exception as e:
            print(f"扫描包时出错: {e}")
            return None
    
    def scan_all_packages(self, packages):
        """扫描所有抓取到的包"""
        print(f"开始检测 {len(packages)} 个抓取到的包...")
        
        # 获取admin用户ID
        admin_id = self.get_admin_user_id()
        if not admin_id:
            print("未找到管理员用户，使用默认ID 1")
            admin_id = 1
        
        print(f"使用管理员ID {admin_id} 创建检测任务")
        
        successful_scans = 0
        failed_scans = 0
        
        for i, package in enumerate(packages):
            try:
                print(f"[{i+1}/{len(packages)}] 准备检测包: {package['name']}")
                
                # 检查文件是否存在
                if not os.path.exists(package['file_path']):
                    print(f"[{i+1}/{len(packages)}] 包文件不存在: {package['file_path']}")
                    failed_scans += 1
                    continue
                    
                scan_id = self.scan_package(package, admin_id)
                if scan_id:
                    print(f"[{i+1}/{len(packages)}] 成功创建扫描任务 {scan_id} 用于包 {package['name']}")
                    successful_scans += 1
                else:
                    print(f"[{i+1}/{len(packages)}] 为包 {package['name']} 创建扫描任务失败")
                    failed_scans += 1
            except Exception as e:
                print(f"[{i+1}/{len(packages)}] 处理包 {package['name']} 时出错: {e}")
                import traceback
                print(traceback.format_exc())
                failed_scans += 1
        
        print(f"所有包检测任务已创建完成: 成功 {successful_scans}, 失败 {failed_scans}")
        return successful_scans
    
    def get_admin_user_id(self):
        """获取系统中的管理员用户ID"""
        try:
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return result[0]
            return None
        except:
            return None

# 创建单例实例
package_fetcher = PackageFetcher() 