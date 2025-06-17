import zipfile
import tarfile
import os
import numpy as np
import shutil
import tempfile
import re
import json
import hashlib
from werkzeug.utils import secure_filename
import glob

class FeatureExtractor:
    def __init__(self):
        self.temp_dir = tempfile.gettempdir()
        self.file_categories = {
            'executable': ['.exe', '.dll', '.so', '.dylib', '.bin', '.com', '.bat', '.cmd', '.sh'],
            'script': ['.py', '.js', '.php', '.rb', '.pl', '.sh', '.bash', '.ps1', '.psm1', '.psd1'],
            'config': ['.json', '.xml', '.yaml', '.yml', '.ini', '.conf', '.cfg', '.toml'],
            'data': ['.csv', '.txt', '.md', '.rst', '.log', '.dat', '.data'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico'],
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archive': ['.zip', '.tar', '.gz', '.tgz', '.bz2', '.rar', '.7z', '.xz'],
            'package': ['.whl', '.egg', '.jar', '.war', '.npm']
        }
        
        # 可疑的扩展名列表
        self.suspicious_extensions = [
            '.exe', '.dll', '.so', '.dylib', '.bin', '.com', '.bat', '.cmd', 
            '.ps1', '.psm1', '.psd1', '.vbs', '.js', '.scr', '.msi', '.reg'
        ]
    
    def extract_features(self, file_path):
        """提取软件包的安全特征"""
        try:
            # 获取文件基本信息
            file_info = self._get_file_info(file_path)
            
            # 解压文件
            extract_dir = self._extract_package(file_path)
            if not extract_dir:
                return self._generate_error_features(file_path, "解压失败")
            
            # 扫描解压后的文件
            file_list = self._scan_directory(extract_dir)
            file_count = len(file_list)
            print(f"解压后共发现 {file_count} 个文件")
            
            # 分析代码文件
            python_files = [f for f in file_list if f.endswith('.py')]
            js_files = [f for f in file_list if f.endswith('.js')]
            c_files = [f for f in file_list if f.endswith('.c') or f.endswith('.cpp') or f.endswith('.h')]
            
            # 提取代码特征
            code_features = self._extract_code_features(extract_dir, python_files, js_files, c_files)
            
            # 提取元数据特征
            metadata_features = self._extract_metadata_features(extract_dir)
            
            # 提取安装脚本特征
            install_features = self._extract_install_features(extract_dir)
            
            # 提取依赖特征
            dependency_features = self._extract_dependency_features(extract_dir)
            
            # 提取文件系统特征
            filesystem_features = self._extract_filesystem_features(extract_dir, file_list)
            
            # 合并所有特征
            features = {
                **file_info,
                **code_features,
                **metadata_features,
                **install_features,
                **dependency_features,
                **filesystem_features
            }
            
            # 清理临时目录
            self._cleanup_extract_dir(extract_dir)
            
            # 添加特征总数统计
            feature_count = len(features)
            print(f"特征提取完成，共提取 {feature_count} 个特征")
            
            # 处理特征不足的情况
            if feature_count < 100:  # 模型期望141个特征
                print(f"警告: 提取的特征数量({feature_count})不足，可能影响模型预测准确性")
                # 添加额外补充特征
                additional_features = self._generate_additional_features(features, file_path)
                features.update(additional_features)
                print(f"已添加补充特征，当前特征总数: {len(features)}")
            
            return features
        except Exception as e:
            print(f"特征提取错误: {e}")
            import traceback
            traceback.print_exc()
            return self._generate_error_features(file_path, str(e))
    
    def _extract_file(self, file_path, extract_dir):
        """解压各种类型的归档文件"""
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension in ['.zip', '.whl', '.egg']:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif file_extension in ['.tar', '.tgz', '.gz', '.bz2', '.xz']:
            if tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    # 过滤掉可能包含绝对路径的成员
                    members = []
                    for member in tar_ref.getmembers():
                        if member.name.startswith('/') or '..' in member.name:
                            continue
                        members.append(member)
                    tar_ref.extractall(extract_dir, members=members)
            else:
                # 如果不是tar文件，可能是单独的gzip或bzip2文件
                shutil.copy2(file_path, extract_dir)
        elif file_extension == '.jar':
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        else:
            # 对于不支持的格式，将文件复制到目标目录
            shutil.copy2(file_path, extract_dir)
    
    def _get_all_files(self, directory):
        """获取目录下的所有文件"""
        file_list = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_list.append(os.path.join(root, file))
        return file_list
    
    def _get_max_directory_depth(self, directory):
        """获取目录的最大深度"""
        max_depth = 0
        for root, dirs, files in os.walk(directory):
            depth = root.count(os.sep) - directory.count(os.sep)
            max_depth = max(max_depth, depth)
        return max_depth
    
    def _count_files_by_extensions(self, file_list, extensions):
        """计算具有特定扩展名的文件数量"""
        return sum(1 for f in file_list if os.path.splitext(f)[1].lower() in extensions)
    
    def _count_binary_files(self, file_list):
        """计算二进制文件数量"""
        binary_count = 0
        for file_path in file_list:
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    with open(file_path, 'rb') as f:
                        content = f.read(1024)
                        if b'\x00' in content:
                            binary_count += 1
            except:
                continue
        return binary_count
    
    def _count_text_files(self, file_list):
        """计算文本文件数量"""
        return len(file_list) - self._count_binary_files(file_list)
    
    def _count_hidden_files(self, file_list):
        """计算隐藏文件数量"""
        return sum(1 for f in file_list if os.path.basename(f).startswith('.'))
    
    def _count_suspicious_names(self, file_list):
        """计算可疑文件名数量"""
        suspicious_patterns = [
            r'backdoor', r'exploit', r'hack', r'crack', r'keylog', r'steal', 
            r'trojan', r'virus', r'malware', r'rootkit', r'spy', r'RAT'
        ]
        pattern = '|'.join(suspicious_patterns)
        return sum(1 for f in file_list if re.search(pattern, f, re.IGNORECASE))
    
    def _check_for_obfuscation(self, file_list):
        """检查是否存在混淆代码"""
        obfuscation_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith('.py') or file_path.endswith('.js'):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # 检查长变量名或函数名
                        if re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]{30,}\b', content):
                            obfuscation_count += 1
                        # 检查大量的base64编码字符串
                        elif re.search(r'[A-Za-z0-9+/=]{40,}', content):
                            obfuscation_count += 1
                        # 检查eval、exec等函数与字符串的组合
                        elif re.search(r'(eval|exec|Function)\s*\(\s*([\'"`][^\'"`]*[\'"`]|\w+)', content):
                            obfuscation_count += 1
            except:
                continue
        return obfuscation_count
    
    def _check_for_malicious_imports(self, file_list):
        """检查是否存在恶意导入"""
        malicious_imports = [
            r'socket', r'subprocess', r'os\.system', r'os\.popen', r'pty', r'child_process',
            r'exec', r'eval', r'base64', r'hashlib', r'crypt', r'pickle', r'marshal', r'ptrace'
        ]
        pattern = '|'.join(malicious_imports)
        import_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith('.py'):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(r'import\s+(' + pattern + r')|from\s+(' + pattern + r')\s+import', content):
                            import_count += 1
            except:
                continue
        return import_count
    
    def _check_for_network_operations(self, file_list):
        """检查是否存在网络操作"""
        network_ops = [
            r'socket', r'http[s]?://', r'urllib', r'requests', r'curl', r'wget',
            r'connect\(', r'listen\(', r'bind\(', r'fetch', r'XMLHttpRequest'
        ]
        pattern = '|'.join(network_ops)
        network_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith(('.py', '.js', '.php', '.rb')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(pattern, content):
                            network_count += 1
            except:
                continue
        return network_count
    
    def _check_for_system_commands(self, file_list):
        """检查是否存在系统命令执行"""
        system_cmds = [
            r'os\.system', r'subprocess', r'exec', r'execfile', r'spawn', r'popen',
            r'shell_exec', r'passthru', r'eval\(', r'child_process', r'Process.Start'
        ]
        pattern = '|'.join(system_cmds)
        cmd_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith(('.py', '.js', '.php', '.rb')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(pattern, content):
                            cmd_count += 1
            except:
                continue
        return cmd_count
    
    def _check_for_crypto_operations(self, file_list):
        """检查是否存在加密操作"""
        crypto_ops = [
            r'crypt', r'encrypt', r'decrypt', r'hashlib', r'md5', r'sha', r'aes',
            r'blowfish', r'des', r'rsa', r'cipher', r'cryptography'
        ]
        pattern = '|'.join(crypto_ops)
        crypto_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith(('.py', '.js', '.php', '.rb')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(pattern, content):
                            crypto_count += 1
            except:
                continue
        return crypto_count
    
    def _check_for_file_operations(self, file_list):
        """检查是否存在文件操作"""
        file_ops = [
            r'open\(', r'read\(', r'write\(', r'file\(', r'fopen', r'fwrite',
            r'FileStream', r'readFile', r'writeFile', r'fs\.', r'io\.'
        ]
        pattern = '|'.join(file_ops)
        file_op_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith(('.py', '.js', '.php', '.rb')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(pattern, content):
                            file_op_count += 1
            except:
                continue
        return file_op_count
    
    def _check_for_privilege_escalation(self, file_list):
        """检查是否存在权限提升操作"""
        priv_esc = [
            r'sudo', r'setuid', r'setgid', r'chmod', r'chown', r'suid', r'sgid',
            r'runas', r'privilege', r'administrator', r'root', r'superuser'
        ]
        pattern = '|'.join(priv_esc)
        priv_count = 0
        for file_path in file_list:
            try:
                if file_path.endswith(('.py', '.js', '.php', '.rb', '.sh')):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(pattern, content):
                            priv_count += 1
            except:
                continue
        return priv_count
    
    def _get_empty_features(self):
        """获取空特征向量"""
        print("返回空特征向量")
        return {
            'file_count': 0,
            'total_size': 0,
            'avg_file_size': 0,
            'directory_depth': 0,
            'executable_files': 0,
            'script_files': 0,
            'config_files': 0,
            'data_files': 0,
            'image_files': 0,
            'document_files': 0,
            'archive_files': 0,
            'package_files': 0,
            'binary_files': 0,
            'text_files': 0,
            'hidden_files': 0,
            'suspicious_extensions': 0,
            'suspicious_names': 0,
            'obfuscated_code': 0,
            'malicious_imports': 0,
            'network_operations': 0,
            'system_commands': 0,
            'crypto_operations': 0,
            'file_operations': 0,
            'privilege_escalation': 0,
            'exec_ratio': 0,
            'script_ratio': 0,
            'config_ratio': 0,
            'binary_ratio': 0,
            'text_ratio': 0,
            'suspicious_ratio': 0
        }

    def _get_file_info(self, file_path):
        """获取文件基本信息"""
        print(f"开始提取特征: {file_path}")
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return {}
        
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_name)[1].lower()
        
        print(f"文件 {file_name} 大小: {file_size}, 扩展名: {file_extension}")
        
        return {
            'file_size': file_size,
            'file_extension': file_extension,
            'is_package': 1 if file_extension in ['.whl', '.egg', '.tar.gz', '.tgz', '.zip'] else 0
        }

    def _extract_package(self, file_path):
        """解压软件包文件"""
        file_name = os.path.basename(file_path)
        extract_dir = os.path.join(self.temp_dir, 'extract_' + hashlib.md5(file_name.encode()).hexdigest())
        os.makedirs(extract_dir, exist_ok=True)
        
        print(f"创建临时解压目录: {extract_dir}")
        
        try:
            self._extract_file(file_path, extract_dir)
            print(f"文件解压成功: {file_path} -> {extract_dir}")
            return extract_dir
        except Exception as e:
            print(f"解压文件失败: {e}")
            return None

    def _scan_directory(self, directory):
        """扫描目录获取所有文件"""
        file_list = self._get_all_files(directory)
        
        if not file_list:
            print(f"解压后未找到任何文件，可能是损坏的包")
            return []
        
        return file_list

    def _extract_code_features(self, extract_dir, python_files, js_files, c_files):
        """提取代码相关特征"""
        features = {}
        
        # 代码文件统计
        features['python_file_count'] = len(python_files)
        features['js_file_count'] = len(js_files)
        features['c_file_count'] = len(c_files)
        
        # 检查可疑代码
        features['obfuscated_code'] = self._check_for_obfuscation(python_files + js_files)
        features['malicious_imports'] = self._check_for_malicious_imports(python_files)
        features['network_operations'] = self._check_for_network_operations(python_files + js_files)
        features['system_commands'] = self._check_for_system_commands(python_files + js_files + c_files)
        features['crypto_operations'] = self._check_for_crypto_operations(python_files + js_files)
        features['file_operations'] = self._check_for_file_operations(python_files + js_files + c_files)
        features['privilege_escalation'] = self._check_for_privilege_escalation(python_files + c_files)
        
        # 检查JavaScript特有风险
        features['eval_usage'] = self._check_for_pattern(js_files, [r'eval\(', r'new Function\('])
        features['dom_manipulation'] = self._check_for_pattern(js_files, [r'document\.write', r'innerHTML'])
        
        # 检查Python特有风险
        features['exec_usage'] = self._check_for_pattern(python_files, [r'exec\(', r'eval\('])
        features['unsafe_deserialization'] = self._check_for_pattern(python_files, [r'pickle\.loads', r'yaml\.load\((?!.*Loader)'])
        
        # 检查C代码特有风险
        features['buffer_operations'] = self._check_for_pattern(c_files, [r'strcpy\(', r'memcpy\(', r'strcat\('])
        features['memory_allocation'] = self._check_for_pattern(c_files, [r'malloc\(', r'calloc\(', r'realloc\('])
        
        return features

    def _extract_metadata_features(self, extract_dir):
        """提取元数据相关特征"""
        features = {}
        
        # 查找setup.py或package.json
        setup_files = glob.glob(os.path.join(extract_dir, '**/setup.py'), recursive=True)
        package_json_files = glob.glob(os.path.join(extract_dir, '**/package.json'), recursive=True)
        
        features['has_setup_py'] = 1 if setup_files else 0
        features['has_package_json'] = 1 if package_json_files else 0
        
        # 分析setup.py
        if setup_files:
            setup_content = self._read_file_content(setup_files[0])
            features['setup_py_size'] = len(setup_content)
            features['setup_entry_points'] = 1 if 'entry_points' in setup_content else 0
            features['setup_scripts'] = 1 if 'scripts' in setup_content else 0
        else:
            features['setup_py_size'] = 0
            features['setup_entry_points'] = 0
            features['setup_scripts'] = 0
        
        # 分析package.json
        if package_json_files:
            try:
                with open(package_json_files[0], 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    
                features['npm_has_scripts'] = 1 if 'scripts' in package_data else 0
                features['npm_dependencies'] = len(package_data.get('dependencies', {}))
                features['npm_dev_dependencies'] = len(package_data.get('devDependencies', {}))
                features['npm_has_install_script'] = 1 if 'install' in package_data.get('scripts', {}) else 0
                features['npm_has_postinstall'] = 1 if 'postinstall' in package_data.get('scripts', {}) else 0
            except:
                features['npm_has_scripts'] = 0
                features['npm_dependencies'] = 0
                features['npm_dev_dependencies'] = 0
                features['npm_has_install_script'] = 0
                features['npm_has_postinstall'] = 0
        else:
            features['npm_has_scripts'] = 0
            features['npm_dependencies'] = 0
            features['npm_dev_dependencies'] = 0
            features['npm_has_install_script'] = 0
            features['npm_has_postinstall'] = 0
        
        return features

    def _extract_install_features(self, extract_dir):
        """提取安装脚本相关特征"""
        features = {}
        
        # 检查setup.py的install命令
        setup_files = glob.glob(os.path.join(extract_dir, '**/setup.py'), recursive=True)
        if setup_files:
            setup_content = self._read_file_content(setup_files[0])
            features['setup_has_cmdclass'] = 1 if 'cmdclass' in setup_content else 0
            features['setup_custom_install'] = 1 if re.search(r'class\s+(\w+Install|Install\w+)', setup_content) else 0
        else:
            features['setup_has_cmdclass'] = 0
            features['setup_custom_install'] = 0
        
        # 检查特殊文件
        features['has_preinstall'] = len(glob.glob(os.path.join(extract_dir, '**/preinstall.*'), recursive=True)) > 0
        features['has_postinstall'] = len(glob.glob(os.path.join(extract_dir, '**/postinstall.*'), recursive=True)) > 0
        features['has_install_script'] = len(glob.glob(os.path.join(extract_dir, '**/install.*'), recursive=True)) > 0
        
        return features

    def _extract_dependency_features(self, extract_dir):
        """提取依赖相关特征"""
        features = {}
        
        # 查找requirements.txt
        req_files = glob.glob(os.path.join(extract_dir, '**/requirements.txt'), recursive=True)
        features['has_requirements'] = 1 if req_files else 0
        
        if req_files:
            req_content = self._read_file_content(req_files[0])
            req_lines = [line.strip() for line in req_content.split('\n') if line.strip() and not line.startswith('#')]
            features['requirements_count'] = len(req_lines)
            
            # 检查可疑依赖
            suspicious_deps = ['cryptography', 'pycrypto', 'paramiko', 'requests', 'socket', 'subprocess']
            features['suspicious_dependencies'] = sum(1 for dep in req_lines if any(s in dep.lower() for s in suspicious_deps))
        else:
            features['requirements_count'] = 0
            features['suspicious_dependencies'] = 0
        
        return features

    def _extract_filesystem_features(self, extract_dir, file_list):
        """提取文件系统相关特征"""
        features = {}
        
        # 基本文件统计
        features['file_count'] = len(file_list)
        features['total_size'] = sum(os.path.getsize(f) for f in file_list if os.path.exists(f))
        features['avg_file_size'] = features['total_size'] / features['file_count'] if features['file_count'] > 0 else 0
        features['directory_depth'] = self._get_max_directory_depth(extract_dir)
        
        # 文件类型统计
        features['executable_files'] = self._count_files_by_extensions(file_list, self.file_categories['executable'])
        features['script_files'] = self._count_files_by_extensions(file_list, self.file_categories['script'])
        features['config_files'] = self._count_files_by_extensions(file_list, self.file_categories['config'])
        features['data_files'] = self._count_files_by_extensions(file_list, self.file_categories['data'])
        features['image_files'] = self._count_files_by_extensions(file_list, self.file_categories['image'])
        features['document_files'] = self._count_files_by_extensions(file_list, self.file_categories['document'])
        features['archive_files'] = self._count_files_by_extensions(file_list, self.file_categories['archive'])
        features['package_files'] = self._count_files_by_extensions(file_list, self.file_categories['package'])
        features['binary_files'] = self._count_binary_files(file_list)
        features['text_files'] = self._count_text_files(file_list)
        features['hidden_files'] = self._count_hidden_files(file_list)
        features['suspicious_extensions'] = self._count_files_by_extensions(file_list, self.suspicious_extensions)
        features['suspicious_names'] = self._count_suspicious_names(file_list)
        
        # 文件类型比例
        total_files = len(file_list)
        if total_files > 0:
            features['exec_ratio'] = features['executable_files'] / total_files
            features['script_ratio'] = features['script_files'] / total_files
            features['config_ratio'] = features['config_files'] / total_files
            features['binary_ratio'] = features['binary_files'] / total_files
            features['text_ratio'] = features['text_files'] / total_files
            features['suspicious_ratio'] = features['suspicious_extensions'] / total_files
        else:
            features['exec_ratio'] = 0
            features['script_ratio'] = 0
            features['config_ratio'] = 0
            features['binary_ratio'] = 0
            features['text_ratio'] = 0
            features['suspicious_ratio'] = 0
        
        return features

    def _cleanup_extract_dir(self, extract_dir):
        """清理临时解压目录"""
        try:
            shutil.rmtree(extract_dir)
            print(f"清理临时目录: {extract_dir}")
        except Exception as e:
            print(f"清理临时目录失败: {extract_dir}, 错误: {e}")

    def _generate_error_features(self, file_path, error_message):
        """生成错误情况下的特征字典"""
        print(f"生成错误特征: {error_message}")
        features = self._get_empty_features()
        features['error'] = 1
        features['error_message'] = error_message
        return features

    def _generate_additional_features(self, current_features, file_path):
        """生成额外补充特征以匹配模型期望"""
        print("生成补充特征以匹配模型期望数量")
        additional_features = {}
        
        # 填充常见统计特征的空值
        common_features = [
            'code_complexity', 'function_count', 'class_count',
            'comment_ratio', 'string_entropy', 'variable_entropy',
            'imports_count', 'exports_count', 'third_party_imports'
        ]
        
        for feature in common_features:
            if feature not in current_features:
                additional_features[feature] = 0
        
        # 填充高级代码分析特征
        advanced_features = [
            'dynamic_imports', 'reflection_usage', 'monkey_patching',
            'binary_payload', 'shellcode_detection', 'string_obfuscation',
            'anti_debugging', 'anti_vm', 'anti_analysis',
            'persistence_mechanism', 'privilege_abuse', 'data_exfiltration'
        ]
        
        for feature in advanced_features:
            if feature not in current_features:
                additional_features[feature] = 0
        
        # 填充网络行为特征
        network_features = [
            'dns_queries', 'http_requests', 'https_requests',
            'unusual_ports', 'known_bad_ips', 'known_bad_domains',
            'network_protocols', 'socket_usage', 'remote_connections'
        ]
        
        for feature in network_features:
            if feature not in current_features:
                additional_features[feature] = 0
        
        # 填充安全相关特征
        security_features = [
            'encryption_usage', 'decryption_usage', 'hashing_usage',
            'random_usage', 'temp_file_usage', 'registry_access',
            'process_creation', 'memory_manipulation', 'hooking_functions'
        ]
        
        for feature in security_features:
            if feature not in current_features:
                additional_features[feature] = 0
        
        # 历史和元数据特征
        metadata_features = [
            'author_reputation', 'package_age', 'update_frequency',
            'download_count', 'community_score', 'dependency_count',
            'is_popular', 'recent_updates', 'version_pattern'
        ]
        
        for feature in metadata_features:
            if feature not in current_features:
                additional_features[feature] = 0
        
        # 统计当前特征和额外特征后的总数
        total_features = len(current_features) + len(additional_features)
        print(f"当前特征: {len(current_features)}, 补充特征: {len(additional_features)}, 总特征: {total_features}")
        
        # 如果仍然不足，添加空白特征直到达到目标数量
        target_feature_count = 141  # 模型期望的特征数量
        if total_features < target_feature_count:
            remaining = target_feature_count - total_features
            for i in range(1, remaining + 1):
                additional_features[f'placeholder_feature_{i}'] = 0
            
            print(f"添加 {remaining} 个占位特征以达到目标特征数量: {target_feature_count}")
        
        return additional_features

    def _check_for_pattern(self, file_list, patterns):
        """在文件列表中检查特定模式"""
        count = 0
        for file_path in file_list:
            content = self._read_file_content(file_path)
            if not content:
                continue
            
            for pattern in patterns:
                if re.search(pattern, content):
                    count += 1
                    break
        
        return count

    def _read_file_content(self, file_path, max_size=1024*1024):
        """安全地读取文件内容，限制大小"""
        try:
            if not os.path.exists(file_path) or os.path.getsize(file_path) > max_size:
                return ""
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            return ""
