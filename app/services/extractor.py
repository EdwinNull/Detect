import zipfile
import tarfile
import os
import numpy as np
import re
import magic
import hashlib
import math
import json
from collections import Counter
import time
import toml
import io

class FeatureExtractor:
    def __init__(self):
        self.features = {}
        self.file_content = None
        self.file_path = None
        self.max_content_size = 1024 * 1024  # 1MB 限制
        
        # 预编译正则表达式以提高性能
        self.regex_patterns = {
            'control_structures': re.compile(r'\b(if|for|while|case|catch|&&|\|\|)\b'),
            'functions': re.compile(r'\b(function|=>|def|class)\b'),
            'camel_case': re.compile(r'\b[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*\b'),
            'snake_case': re.compile(r'\b[a-z]+(_[a-z]+)+\b'),
            'const_case': re.compile(r'\b[A-Z][A-Z0-9_]*\b'),
            'error_patterns': re.compile(r'\b(try|catch|throw|finally|error|Exception|Error)\b', re.IGNORECASE),
            'performance_patterns': re.compile(r'\b(cache|memo|optimiz|performance|async|await|promise|setTimeout)\b', re.IGNORECASE),
            'malicious_patterns': re.compile(r'(eval\s*\(.*\)|exec\s*\(.*\)|Function\s*\(.*\)|setTimeout\s*\(\s*[\'"`]|setInterval\s*\(\s*[\'"`]|document\.write\s*\(|\.innerHTML\s*=|window\.location\s*=|document\.cookie|localStorage\.|sessionStorage\.|indexedDB\.|new\s+Function|debugger|\[native\s+code\]|prototype\.)'),
            'vulnerability_patterns': re.compile(r'(sql\s*injection|xss|csrf|buffer\s*overflow|race\s*condition|path\s*traversal|command\s*injection)'),
            'injection_patterns': re.compile(r'(innerHTML|outerHTML|document\.write|eval|exec|Function)'),
            'crypto_patterns': re.compile(r'\b(crypto|cipher|encrypt|decrypt|hash|md5|sha1|sha256|base64)\b'),
            'network_patterns': re.compile(r'\b(http|https|fetch|axios|request|url|api|endpoint)\b'),
            'fs_patterns': re.compile(r'\b(fs\.|readFile|writeFile|unlink|rmdir|mkdir|chmod|chown)\b'),
            'process_patterns': re.compile(r'\b(exec|spawn|fork|child_process|subprocess|os\.system|os\.popen)\b'),
            'privilege_patterns': re.compile(r'\b(sudo|su|runas|elevate|admin|root|privilege)\b'),
            'data_patterns': re.compile(r'\b(password|secret|key|token|credential|private)\b'),
            'auth_patterns': re.compile(r'\b(login|auth|authenticate|authorize|jwt|oauth|session)\b'),
            'base64_pattern': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'ip_pattern': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'url_pattern': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'suspicious_patterns': re.compile(r'\b(eval\s*\(|exec\s*\(|Function\s*\(|setTimeout\s*\(\s*[\'"`]|setInterval\s*\(\s*[\'"`]|document\.write\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|window\.location\s*=|document\.cookie\s*=|localStorage\s*\.|sessionStorage\s*\.|indexedDB\s*\.|debugger\s*;|prototype\s*\.|constructor\s*\.|__proto__\s*\.|toString\s*\(|valueOf\s*\(|hasOwnProperty\s*\(|isPrototypeOf\s*\(|propertyIsEnumerable\s*\(|toLocaleString\s*\(|toSource\s*\(|unwatch\s*\(|watch\s*\()'),
            'file_extensions': re.compile(r'\.([a-zA-Z0-9]+)(?:\?|$)'),
        }
        
    def extract_features(self, file_path):
        """提取文件特征 - 返回CSV格式特征"""
        start_time = time.time()
        print(f"开始提取特征: {file_path}")
        
        try:
            self.file_path = file_path
            self.features = {}
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                print(f"文件不存在: {file_path}")
                return None
            
            # 新增：自动识别包名
            self.features['package_name'] = self._extract_package_name(file_path)
            
            # 获取文件信息
            file_info = self._get_file_info(file_path)
            if file_info:
                self.features.update(file_info)
            
            # 根据文件类型提取特征
            file_extension = os.path.splitext(file_path)[1]
            file_extension = file_extension.lower() if file_extension else ''
            
            if file_extension in ['.zip', '.tar', '.gz', '.bz2', '.tgz']:
                self._extract_archive_features(file_path)
            else:
                self._extract_single_file_features(file_path)
            
            # 确保所有CSV特征都存在
            self._ensure_csv_features()
            
            print(f"提取了 {len(self.features)} 个特征")
            print(f"特征提取完成，耗时: {time.time() - start_time:.2f}秒")
            
            print("【调试】主要特征统计：")
            print("代码总词数：", self.features.get('Number of Words in source code'))
            print("代码总行数：", self.features.get('Number of lines in source code'))
            print("文件类型分布：", {k: v for k, v in self.features.items() if k.startswith('.') and v > 0})
            print("包名：", self.features.get('package_name'))
            
            return self.features
            
        except Exception as e:
            print(f"特征提取错误: {str(e)}")
            return None
    
    def _ensure_csv_features(self):
        """确保所有CSV格式的特征都存在"""
        # CSV特征列表（基于npm_feature_extracted.csv的列名）
        csv_features = [
            # 基础统计特征
            'Number of Words in source code', 'Number of lines in source code',
            
            # 字符比率特征
            'plus ratio mean', 'plus ratio max', 'plus ratio std', 'plus ratio q3',
            'eq ratio mean', 'eq ratio max', 'eq ratio std', 'eq ratio q3',
            'bracket ratio mean', 'bracket ratio max', 'bracket ratio std', 'bracket ratio q3',
            
            # 安全特征
            'Number of base64 chunks in source code', 'Number of IP adress in source code', 
            'Number of sospicious token in source code',
            
            # 元数据特征
            'Number of Words in metadata', 'Number of lines in metadata',
            'Number of base64 chunks in metadata', 'Number of IP adress in metadata',
            'Number of sospicious token in metadata',
            
            # 文件类型特征 (带点的格式，与CSV一致)
            '.bat', '.bz2', '.c', '.cert', '.conf', '.cpp', '.crt', '.css', '.csv', '.deb',
            '.erb', '.gemspec', '.gif', '.gz', '.h', '.html', '.ico', '.ini', '.jar', '.java',
            '.jpg', '.js', '.json', '.key', '.m4v', '.markdown', '.md', '.pdf', '.pem', '.png',
            '.ps', '.py', '.rb', '.rpm', '.rst', '.sh', '.svg', '.toml', '.ttf', '.txt', '.xml',
            '.yaml', '.yml', '.eot', '.exe', '.jpeg', '.properties', '.sql', '.swf', '.tar',
            '.woff', '.woff2', '.aac', '.bmp', '.cfg', '.dcm', '.dll', '.doc', '.flac', '.flv',
            '.ipynb', '.m4a', '.mid', '.mkv', '.mp3', '.mp4', '.mpg', '.ogg', '.otf', '.pickle',
            '.pkl', '.psd', '.pxd', '.pxi', '.pyc', '.pyx', '.r', '.rtf', '.so', '.sqlite',
            '.tif', '.tp', '.wav', '.webp', '.whl', '.xcf', '.xz', '.zip', '.mov', '.wasm', '.webm',
            
            # 项目特征
            'repository', 'presence of installation script',
            
            # 熵特征
            'shannon mean ID source code', 'shannon std ID source code', 
            'shannon max ID source code', 'shannon q3 ID source code',
            'shannon mean string source code', 'shannon std string source code',
            'shannon max string source code', 'shannon q3 string source code',
            
            # 标识符和字符串特征
            'homogeneous identifiers in source code', 'homogeneous strings in source code',
            'heteregeneous identifiers in source code', 'heterogeneous strings in source code',
            'URLs in source code',
            
            # 元数据熵特征
            'shannon mean ID metadata', 'shannon std ID metadata',
            'shannon max ID metadata', 'shannon q3 ID metadata',
            'shannon mean string metadata', 'shannon std string metadata',
            'shannon max string metadata', 'shannon q3 string metadata',
            
            # 元数据标识符和字符串特征
            'homogeneous identifiers in metadata', 'homogeneous strings in metadata',
            'heterogeneous strings in metadata', 'URLs in metadata',
            'heteregeneous identifiers in metadata'
        ]
        
        # 确保所有CSV特征都存在，缺失的设为0
        for feature in csv_features:
            if feature not in self.features:
                self.features[feature] = 0
    
    def _extract_csv_based_features(self, content):
        """基于CSV数据提取特征"""
        try:
            # 1. 基础统计特征 (对应CSV中的前几列)
            lines = content.splitlines()
            words = re.findall(r'\b\w+\b', content)
            
            self.features['Number of Words in source code'] = len(words)
            self.features['Number of lines in source code'] = len(lines)
            
            # 2. 字符比率特征 (对应CSV中的比率特征)
            self._extract_char_ratios_enhanced(content)
            
            # 3. 安全特征 (对应CSV中的base64, IP, suspicious token)
            self._extract_security_features_enhanced(content)
            
            # 4. 元数据特征 (对应CSV中的metadata相关列)
            self._extract_metadata_features()
            
            # 5. 文件类型特征 (对应CSV中的各种文件扩展名)
            self._extract_file_type_features()
            
            # 6. 熵特征 (对应CSV中的shannon entropy相关列)
            self._extract_entropy_features_enhanced(content)
            
            # 7. 标识符和字符串特征 (对应CSV中的homogeneous/heterogeneous列)
            self._extract_identifier_string_features(content)
            
            print(f"提取了 {len(self.features)} 个特征")
            
        except Exception as e:
            print(f"CSV特征提取错误: {str(e)}")
    
    def _extract_char_ratios_enhanced(self, content):
        """增强的字符比率提取 - 对应CSV中的比率特征"""
        if not content:
            return
            
        total_chars = len(content)
        if total_chars == 0:
            return
        
        lines = content.splitlines()
        
        # 加号比率
        plus_ratios = []
        for line in lines:
            if line:
                plus_ratios.append(line.count('+') / len(line))
            else:
                plus_ratios.append(0)
        
        if plus_ratios:
            self.features['plus ratio mean'] = np.mean(plus_ratios)
            self.features['plus ratio max'] = max(plus_ratios)
            self.features['plus ratio std'] = np.std(plus_ratios)
            self.features['plus ratio q3'] = np.percentile(plus_ratios, 75)
        else:
            self.features['plus ratio mean'] = 0
            self.features['plus ratio max'] = 0
            self.features['plus ratio std'] = 0
            self.features['plus ratio q3'] = 0
        
        # 等号比率
        eq_ratios = []
        for line in lines:
            if line:
                eq_ratios.append(line.count('=') / len(line))
            else:
                eq_ratios.append(0)
        
        if eq_ratios:
            self.features['eq ratio mean'] = np.mean(eq_ratios)
            self.features['eq ratio max'] = max(eq_ratios)
            self.features['eq ratio std'] = np.std(eq_ratios)
            self.features['eq ratio q3'] = np.percentile(eq_ratios, 75)
        else:
            self.features['eq ratio mean'] = 0
            self.features['eq ratio max'] = 0
            self.features['eq ratio std'] = 0
            self.features['eq ratio q3'] = 0
        
        # 括号比率
        bracket_chars = '()[]{}'
        bracket_ratios = []
        for line in lines:
            if line:
                bracket_ratios.append(sum(line.count(c) for c in bracket_chars) / len(line))
            else:
                bracket_ratios.append(0)
        
        if bracket_ratios:
            self.features['bracket ratio mean'] = np.mean(bracket_ratios)
            self.features['bracket ratio max'] = max(bracket_ratios)
            self.features['bracket ratio std'] = np.std(bracket_ratios)
            self.features['bracket ratio q3'] = np.percentile(bracket_ratios, 75)
        else:
            self.features['bracket ratio mean'] = 0
            self.features['bracket ratio max'] = 0
            self.features['bracket ratio std'] = 0
            self.features['bracket ratio q3'] = 0
    
    def _extract_security_features_enhanced(self, content):
        """增强的安全特征提取 - 对应CSV中的安全相关列"""
        # Base64块
        base64_matches = self.regex_patterns['base64_pattern'].findall(content)
        self.features['Number of base64 chunks in source code'] = len(base64_matches)
        
        # IP地址
        ip_matches = self.regex_patterns['ip_pattern'].findall(content)
        self.features['Number of IP adress in source code'] = len(ip_matches)
        
        # 可疑token
        suspicious_matches = self.regex_patterns['suspicious_patterns'].findall(content)
        self.features['Number of sospicious token in source code'] = len(suspicious_matches)
    
    def _extract_metadata_features(self):
        """提取元数据特征 - 对应CSV中的metadata相关列"""
        try:
            project_dir = os.path.dirname(self.file_path)
            
            # 查找package.json
            package_json_path = os.path.join(project_dir, 'package.json')
            if os.path.exists(package_json_path):
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    
                # 提取package.json内容作为元数据
                metadata_content = json.dumps(package_data, indent=2)
                metadata_lines = metadata_content.splitlines()
                metadata_words = re.findall(r'\b\w+\b', metadata_content)
                
                self.features['Number of Words in metadata'] = len(metadata_words)
                self.features['Number of lines in metadata'] = len(metadata_lines)
                
                # 元数据中的安全特征
                base64_matches = self.regex_patterns['base64_pattern'].findall(metadata_content)
                self.features['Number of base64 chunks in metadata'] = len(base64_matches)
                
                ip_matches = self.regex_patterns['ip_pattern'].findall(metadata_content)
                self.features['Number of IP adress in metadata'] = len(ip_matches)
                
                suspicious_matches = self.regex_patterns['suspicious_patterns'].findall(metadata_content)
                self.features['Number of sospicious token in metadata'] = len(suspicious_matches)
            else:
                # 如果没有package.json，使用默认值
                self.features['Number of Words in metadata'] = 0
                self.features['Number of lines in metadata'] = 0
                self.features['Number of base64 chunks in metadata'] = 0
                self.features['Number of IP adress in metadata'] = 0
                self.features['Number of sospicious token in metadata'] = 0
                
        except Exception as e:
            print(f"元数据特征提取错误: {str(e)}")
            # 设置默认值
            self.features['Number of Words in metadata'] = 0
            self.features['Number of lines in metadata'] = 0
            self.features['Number of base64 chunks in metadata'] = 0
            self.features['Number of IP adress in metadata'] = 0
            self.features['Number of sospicious token in metadata'] = 0
    
    def _extract_file_type_features(self):
        """提取文件类型特征 - 对应CSV中的文件扩展名列"""
        try:
            project_dir = os.path.dirname(self.file_path)
            
            # 文件扩展名映射 (对应CSV中的列名)
            extension_mapping = {
                '.bat': 'bat',
                '.bz2': 'bz2',
                '.c': 'c',
                '.cert': 'cert',
                '.conf': 'conf',
                '.cpp': 'cpp',
                '.crt': 'crt',
                '.css': 'css',
                '.csv': 'csv',
                '.deb': 'deb',
                '.erb': 'erb',
                '.gemspec': 'gemspec',
                '.gif': 'gif',
                '.gz': 'gz',
                '.h': 'h',
                '.html': 'html',
                '.ico': 'ico',
                '.ini': 'ini',
                '.jar': 'jar',
                '.java': 'java',
                '.jpg': 'jpg',
                '.js': 'js',
                '.json': 'json',
                '.key': 'key',
                '.m4v': 'm4v',
                '.markdown': 'markdown',
                '.md': 'md',
                '.pdf': 'pdf',
                '.pem': 'pem',
                '.png': 'png',
                '.ps': 'ps',
                '.py': 'py',
                '.rb': 'rb',
                '.rpm': 'rpm',
                '.rst': 'rst',
                '.sh': 'sh',
                '.svg': 'svg',
                '.toml': 'toml',
                '.ttf': 'ttf',
                '.txt': 'txt',
                '.xml': 'xml',
                '.yaml': 'yaml',
                '.yml': 'yml',
                '.eot': 'eot',
                '.exe': 'exe',
                '.jpeg': 'jpeg',
                '.properties': 'properties',
                '.sql': 'sql',
                '.swf': 'swf',
                '.tar': 'tar',
                '.woff': 'woff',
                '.woff2': 'woff2',
                '.aac': 'aac',
                '.bmp': 'bmp',
                '.cfg': 'cfg',
                '.dcm': 'dcm',
                '.dll': 'dll',
                '.doc': 'doc',
                '.flac': 'flac',
                '.flv': 'flv',
                '.ipynb': 'ipynb',
                '.m4a': 'm4a',
                '.mid': 'mid',
                '.mkv': 'mkv',
                '.mp3': 'mp3',
                '.mp4': 'mp4',
                '.mpg': 'mpg',
                '.ogg': 'ogg',
                '.otf': 'otf',
                '.pickle': 'pickle',
                '.pkl': 'pkl',
                '.psd': 'psd',
                '.pxd': 'pxd',
                '.pxi': 'pxi',
                '.pyc': 'pyc',
                '.pyx': 'pyx',
                '.r': 'r',
                '.rtf': 'rtf',
                '.so': 'so',
                '.sqlite': 'sqlite',
                '.tif': 'tif',
                '.tp': 'tp',
                '.wav': 'wav',
                '.webp': 'webp',
                '.whl': 'whl',
                '.xcf': 'xcf',
                '.xz': 'xz',
                '.zip': 'zip',
                '.mov': 'mov',
                '.wasm': 'wasm',
                '.webm': 'webm'
            }
            
            # 初始化所有文件类型计数为0
            for ext in extension_mapping.values():
                self.features[ext] = 0
            
            # 统计文件类型
            for root, _, files in os.walk(project_dir):
                for file in files:
                    file_lower = file.lower() if file else ''
                    _, ext = os.path.splitext(file_lower)
                    if ext in extension_mapping:
                        self.features[extension_mapping[ext]] += 1
            
            # 添加repository和installation script特征
            self.features['repository'] = 1 if self._has_repository(project_dir) else 0
            self.features['presence of installation script'] = 1 if self._has_installation_script(project_dir) else 0
            
        except Exception as e:
            print(f"文件类型特征提取错误: {str(e)}")
    
    def _extract_entropy_features_enhanced(self, content):
        """增强的熵特征提取 - 对应CSV中的shannon entropy相关列"""
        try:
            # 提取标识符
            identifiers = re.findall(r'\b[a-zA-Z_]\w*\b', content)
            # 提取字符串
            strings = re.findall(r'["\'].*?["\']', content)
            
            # 计算标识符的熵
            if identifiers:
                id_entropies = [self._calculate_entropy(id) for id in identifiers]
                self.features['shannon mean ID source code'] = np.mean(id_entropies)
                self.features['shannon std ID source code'] = np.std(id_entropies)
                self.features['shannon max ID source code'] = max(id_entropies)
                self.features['shannon q3 ID source code'] = np.percentile(id_entropies, 75)
            else:
                self.features['shannon mean ID source code'] = 0
                self.features['shannon std ID source code'] = 0
                self.features['shannon max ID source code'] = 0
                self.features['shannon q3 ID source code'] = 0
            
            # 计算字符串的熵
            if strings:
                str_entropies = [self._calculate_entropy(s) for s in strings]
                self.features['shannon mean string source code'] = np.mean(str_entropies)
                self.features['shannon std string source code'] = np.std(str_entropies)
                self.features['shannon max string source code'] = max(str_entropies)
                self.features['shannon q3 string source code'] = np.percentile(str_entropies, 75)
            else:
                self.features['shannon mean string source code'] = 0
                self.features['shannon std string source code'] = 0
                self.features['shannon max string source code'] = 0
                self.features['shannon q3 string source code'] = 0
            
            # 元数据熵特征 (简化处理，使用相同的值)
            self.features['shannon mean ID metadata'] = self.features['shannon mean ID source code']
            self.features['shannon std ID metadata'] = self.features['shannon std ID source code']
            self.features['shannon max ID metadata'] = self.features['shannon max ID source code']
            self.features['shannon q3 ID metadata'] = self.features['shannon q3 ID source code']
            self.features['shannon mean string metadata'] = self.features['shannon mean string source code']
            self.features['shannon std string metadata'] = self.features['shannon std string source code']
            self.features['shannon max string metadata'] = self.features['shannon max string source code']
            self.features['shannon q3 string metadata'] = self.features['shannon q3 string source code']
            
        except Exception as e:
            print(f"熵特征提取错误: {str(e)}")
    
    def _extract_identifier_string_features(self, content):
        """提取标识符和字符串特征 - 对应CSV中的homogeneous/heterogeneous列"""
        try:
            # 提取标识符
            identifiers = re.findall(r'\b[a-zA-Z_]\w*\b', content)
            # 提取字符串
            strings = re.findall(r'["\'].*?["\']', content)
            
            # 计算同质标识符 (简化处理)
            self.features['homogeneous identifiers in source code'] = len(identifiers) // 2  # 简化估计
            self.features['homogeneous strings in source code'] = len(strings) // 2  # 简化估计
            
            # 计算异质标识符
            self.features['heteregeneous identifiers in source code'] = len(identifiers) - self.features['homogeneous identifiers in source code']
            self.features['heterogeneous strings in source code'] = len(strings) - self.features['homogeneous strings in source code']
            
            # URL特征
            urls = self.regex_patterns['url_pattern'].findall(content)
            self.features['URLs in source code'] = len(urls)
            
            # 元数据中的相应特征 (简化处理)
            self.features['homogeneous identifiers in metadata'] = 0
            self.features['homogeneous strings in metadata'] = 0
            self.features['heterogeneous strings in metadata'] = 0
            self.features['URLs in metadata'] = 0
            self.features['heteregeneous identifiers in metadata'] = 0
            
        except Exception as e:
            print(f"标识符字符串特征提取错误: {str(e)}")
    
    def _has_repository(self, project_dir):
        """检查是否有仓库信息"""
        git_dir = os.path.join(project_dir, '.git')
        svn_dir = os.path.join(project_dir, '.svn')
        return os.path.exists(git_dir) or os.path.exists(svn_dir)
    
    def _has_installation_script(self, project_dir):
        """检查是否有安装脚本"""
        install_scripts = ['install.sh', 'setup.sh', 'install.bat', 'setup.bat', 'install.ps1', 'setup.ps1']
        for script in install_scripts:
            if os.path.exists(os.path.join(project_dir, script)):
                return True
        return False

    def _read_file_content(self):
        """读取文件内容"""
        if not self.file_content:
            try:
                # 检查是否为zip文件
                file_path_lower = self.file_path.lower() if self.file_path else ''
                basename_lower = os.path.basename(self.file_path).lower() if self.file_path else ''
                if file_path_lower.endswith('.zip') or basename_lower == 'zip':
                    print(f"检测到ZIP文件，提取源代码内容")
                    self.file_content = self._extract_zip_content()
                else:
                    # 普通文件读取
                    with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.file_content = f.read()
            except Exception as e:
                print(f"读取文件内容时出错: {e}")
                self.file_content = ""
        return self.file_content
    
    def _extract_zip_content(self):
        """从ZIP文件中提取源代码内容 - 优化版本"""
        try:
            start_time = time.time()
            content = []
            total_size = 0
            
            with zipfile.ZipFile(self.file_path, 'r') as zipf:
                # 获取所有文件列表
                file_list = zipf.namelist()
                print(f"ZIP文件包含 {len(file_list)} 个文件")
                
                # 源代码文件扩展名 - 按重要性排序
                source_extensions = {
                    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', 
                    '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
                    '.html', '.css', '.scss', '.sass', '.less', '.xml', '.json',
                    '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.sh', '.bat',
                    '.ps1', '.sql', '.md', '.txt', '.rst'
                }
                
                # 重要文件优先级
                priority_files = [
                    'setup.py', 'pyproject.toml', 'setup.cfg', 'PKG-INFO',
                    'package.json', 'requirements.txt', 'Pipfile', 'poetry.lock',
                    'Cargo.toml', 'pom.xml', 'build.gradle', 'Gemfile',
                    'main.py', 'app.py', 'index.js', 'app.js', 'main.js'
                ]
                
                # 过滤出源代码文件
                source_files = [
                    f for f in file_list 
                    if not f.endswith('/') and  # 排除目录
                    any(f.lower().endswith(ext) for ext in source_extensions) and
                    not any(skip in f.lower() for skip in ['node_modules', '.git', '__pycache__', '.pytest_cache', 'venv', 'env', 'dist', 'build'])
                ]
                
                print(f"找到 {len(source_files)} 个源代码文件")
                
                # 按优先级排序文件
                def file_priority(f):
                    filename = os.path.basename(f).lower()
                    for i, priority in enumerate(priority_files):
                        if filename == priority.lower():
                            return i
                    return len(priority_files)  # 其他文件优先级最低
                
                source_files.sort(key=file_priority)
                
                # 提取每个源代码文件的内容
                extracted_files = 0
                for file_name in source_files:
                    # 检查内容大小限制
                    if total_size >= self.max_content_size:
                        print(f"达到内容大小限制 ({self.max_content_size} bytes)，停止提取")
                        break
                    
                    # 限制文件数量
                    if extracted_files >= 30:
                        print(f"达到文件数量限制 (30个)，停止提取")
                        break
                    
                    try:
                        with zipf.open(file_name, 'r') as file:
                            file_content = file.read()
                            
                            # 检查文件大小
                            if len(file_content) > 100 * 1024:  # 100KB限制
                                print(f"跳过大文件: {file_name} ({len(file_content)} bytes)")
                                continue
                            
                            # 尝试解码为文本
                            try:
                                text_content = file_content.decode('utf-8')
                            except UnicodeDecodeError:
                                try:
                                    text_content = file_content.decode('latin-1')
                                except:
                                    text_content = str(file_content)
                            
                            # 检查内容大小
                            if total_size + len(text_content) > self.max_content_size:
                                # 截断内容
                                remaining_size = self.max_content_size - total_size
                                text_content = text_content[:remaining_size]
                                print(f"截断文件内容: {file_name}")
                            
                            content.append(f"=== {file_name} ===")
                            content.append(text_content)
                            content.append("\n")
                            
                            total_size += len(text_content)
                            extracted_files += 1
                            
                    except Exception as e:
                        print(f"提取文件 {file_name} 时出错: {e}")
                        continue
                
                print(f"成功提取 {extracted_files} 个文件，总大小: {total_size} bytes")
                
                # 连接所有内容
                result = "\n".join(content)
                elapsed_time = time.time() - start_time
                print(f"ZIP内容提取完成，耗时: {elapsed_time:.2f}秒")
                return result
                
        except Exception as e:
            print(f"提取ZIP内容时出错: {e}")
            return ""
        
    def _calculate_entropy(self, data):
        """计算香农熵 - 优化版本"""
        if not data:
            return 0
        # 使用Counter提高性能
        char_counts = Counter(data)
        data_len = len(data)
        entropy = 0
        for count in char_counts.values():
            p_x = count / data_len
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
        
    def _map_features_to_classifier_format(self):
        """将CSV格式特征直接传递给分类器，不进行映射"""
        # 直接使用CSV格式的特征，不进行映射
        # 这样可以保持与CSV数据的一致性
        pass

    def _get_file_info(self, file_path):
        """获取文件基本信息"""
        try:
            stat = os.stat(file_path)
            return {
                'file_size': stat.st_size,
                'file_modified': stat.st_mtime
            }
        except Exception as e:
            print(f"获取文件信息错误: {str(e)}")
            return {}
    
    def _extract_archive_features(self, file_path):
        """递归遍历压缩包内所有文件，统计所有代码文件的特征"""
        print(f"开始处理压缩包：{file_path}")
        
        # 初始化特征统计
        total_words = 0
        total_lines = 0
        base64_chunks = 0
        ip_count = 0
        suspicious_token_count = 0
        file_type_counts = {}  # 文件类型统计
        package_name = None
        
        # 用于存储所有文本内容，以便后续计算熵等特征
        all_content = []
        
        def process_file_content(content, filename):
            nonlocal total_words, total_lines, base64_chunks, ip_count, suspicious_token_count, package_name
            
            try:
                # 检查是否为二进制文件
                if '\x00' in content[:1024]:
                    print(f"跳过二进制文件: {filename}")
                    return
                
                # 统计基本特征
                lines = content.splitlines()
                words = re.findall(r'\b\w+\b', content)
                
                print(f"处理文件 {filename}:")
                print(f"- 行数: {len(lines)}")
                print(f"- 词数: {len(words)}")
                
                # 尝试从setup.py或package.json提取包名
                if filename.endswith('setup.py'):
                    setup_name_match = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                    if setup_name_match:
                        package_name = setup_name_match.group(1)
                        print(f"从setup.py提取到包名: {package_name}")
                elif filename.endswith('package.json'):
                    try:
                        pkg_data = json.loads(content)
                        if 'name' in pkg_data:
                            package_name = pkg_data['name']
                            print(f"从package.json提取到包名: {package_name}")
                    except json.JSONDecodeError:
                        pass
                
                total_words += len(words)
                total_lines += len(lines)
                
                # 统计安全相关特征
                base64_matches = self.regex_patterns['base64_pattern'].findall(content)
                ip_matches = self.regex_patterns['ip_pattern'].findall(content)
                suspicious_matches = self.regex_patterns['suspicious_patterns'].findall(content)
                
                base64_chunks += len(base64_matches)
                ip_count += len(ip_matches)
                suspicious_token_count += len(suspicious_matches)
                
                # 统计文件类型
                ext_raw = os.path.splitext(filename)[1]
                ext = ext_raw.lower() if ext_raw else ''
                if ext:
                    file_type_counts[ext] = file_type_counts.get(ext, 0) + 1
                
                # 保存内容用于后续分析
                all_content.append(content)
                
                print(f"- Base64块: {len(base64_matches)}")
                print(f"- IP地址: {len(ip_matches)}")
                print(f"- 可疑token: {len(suspicious_matches)}")
                
            except Exception as e:
                print(f"处理文件 {filename} 时出错: {str(e)}")
        
        try:
            if file_path.endswith(('.tar.gz', '.tgz')):
                print("检测到tar.gz格式文件")
                with tarfile.open(file_path, 'r:gz') as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            f = tar.extractfile(member)
                            if f:
                                try:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    process_file_content(content, member.name)
                                except Exception as e:
                                    print(f"读取tar文件 {member.name} 失败: {str(e)}")
                                    continue
            
            elif file_path.endswith('.zip'):
                print("检测到zip格式文件")
                with zipfile.ZipFile(file_path, 'r') as z:
                    for name in z.namelist():
                        if not name.endswith('/'):  # 跳过目录
                            try:
                                with z.open(name) as f:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    process_file_content(content, name)
                            except Exception as e:
                                print(f"读取zip文件 {name} 失败: {str(e)}")
                                continue
            
            # 更新特征字典
            self.features.update({
                'package_name': package_name,  # 添加包名特征
                'Number of Words in source code': total_words,
                'Number of lines in source code': total_lines,
                'Number of base64 chunks in source code': base64_chunks,
                'Number of IP adress in source code': ip_count,
                'Number of sospicious token in source code': suspicious_token_count
            })
            
            # 更新文件类型统计
            for ext, count in file_type_counts.items():
                ext_key = ext if ext.startswith('.') else f'.{ext}'
                self.features[ext_key] = count
            
            # 如果有内容，计算其他特征
            if all_content:
                combined_content = '\n'.join(all_content)
                self._extract_char_ratios_enhanced(combined_content)
                self._extract_entropy_features_enhanced(combined_content)
                self._extract_identifier_string_features(combined_content)
            
            print("\n特征提取统计:")
            print(f"包名: {package_name}")
            print(f"总词数: {total_words}")
            print(f"总行数: {total_lines}")
            print(f"Base64块总数: {base64_chunks}")
            print(f"IP地址总数: {ip_count}")
            print(f"可疑token总数: {suspicious_token_count}")
            print("文件类型分布:", file_type_counts)
            
            print(f"[DEBUG] 最终特征字典中的包名: {self.features.get('package_name')}")
            
        except Exception as e:
            print(f"处理压缩包时出错: {str(e)}")
            raise
    
    def _extract_single_file_features(self, file_path):
        """提取单个文件特征"""
        try:
            # 读取文件内容
            file_content = self._read_file_content()
            if not file_content:
                return
            
            # 基于CSV数据的特征提取
            self._extract_csv_based_features(file_content)
            
        except Exception as e:
            print(f"提取单个文件特征错误: {str(e)}")

    def _extract_package_name(self, file_path):
        """从压缩包或源码目录中提取包名"""
        # 1. 只支持tar.gz/zip源码包
        ext = os.path.splitext(file_path)[1].lower()
        name = None
        try:
            if ext in ['.gz', '.tgz', '.tar']:
                with tarfile.open(file_path, 'r:*') as tar:
                    for member in tar.getmembers():
                        # PKG-INFO
                        if member.name.endswith('PKG-INFO'):
                            f = tar.extractfile(member)
                            if f:
                                for line in f:
                                    line = line.decode(errors='ignore')
                                    if line.startswith('Name:'):
                                        name = line.split(':',1)[1].strip()
                                        return name
                        # pyproject.toml
                        if member.name.endswith('pyproject.toml'):
                            f = tar.extractfile(member)
                            if f:
                                data = f.read().decode(errors='ignore')
                                try:
                                    t = toml.loads(data)
                                    if 'project' in t and 'name' in t['project']:
                                        return t['project']['name']
                                    if 'tool' in t and 'poetry' in t['tool'] and 'name' in t['tool']['poetry']:
                                        return t['tool']['poetry']['name']
                                except Exception:
                                    pass
                        # setup.py
                        if member.name.endswith('setup.py'):
                            f = tar.extractfile(member)
                            if f:
                                data = f.read().decode(errors='ignore')
                                m = re.search(r'name\s*=\s*[\'\"]([\w\-\.]+)[\'\"]', data)
                                if m:
                                    return m.group(1)
            elif ext == '.zip':
                with zipfile.ZipFile(file_path) as z:
                    for member in z.namelist():
                        if member.endswith('PKG-INFO'):
                            with z.open(member) as f:
                                for line in f:
                                    line = line.decode(errors='ignore')
                                    if line.startswith('Name:'):
                                        name = line.split(':',1)[1].strip()
                                        return name
                        if member.endswith('pyproject.toml'):
                            with z.open(member) as f:
                                data = f.read().decode(errors='ignore')
                                try:
                                    t = toml.loads(data)
                                    if 'project' in t and 'name' in t['project']:
                                        return t['project']['name']
                                    if 'tool' in t and 'poetry' in t['tool'] and 'name' in t['tool']['poetry']:
                                        return t['tool']['poetry']['name']
                                except Exception:
                                    pass
                        if member.endswith('setup.py'):
                            with z.open(member) as f:
                                data = f.read().decode(errors='ignore')
                                m = re.search(r'name\s*=\s*[\'\"]([\w\-\.]+)[\'\"]', data)
                                if m:
                                    return m.group(1)
        except Exception as e:
            print(f"[包名提取异常]{e}")
        # 兜底：用文件名
        return os.path.basename(file_path).split('-')[0]
