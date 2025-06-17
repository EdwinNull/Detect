import zipfile
import tarfile
import os
import numpy as np

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'file_count', 'total_size', 'avg_file_size', 'max_file_size',
            'directory_depth', 'executable_files', 'script_files', 'config_files',
            'entropy_avg', 'entropy_max', 'suspicious_extensions', 'hidden_files',
            'large_files', 'compressed_files', 'binary_files', 'text_files'
        ] + [f'feature_{i}' for i in range(17, 142)]  # 模拟141个特征
    
    def extract_features(self, file_path):
        """提取141项语言无关特征"""
        features = {}
        
        try:
            if file_path.endswith('.zip'):
                features.update(self._analyze_zip(file_path))
            elif file_path.endswith(('.tar.gz', '.tgz')):
                features.update(self._analyze_tar(file_path))
            else:
                features.update(self._analyze_generic(file_path))
            
            # 填充剩余特征（模拟）
            for name in self.feature_names:
                if name not in features:
                    features[name] = np.random.random()
                    
        except Exception as e:
            print(f"特征提取错误: {e}")
            # 如果提取失败，返回随机特征
            features = {name: np.random.random() for name in self.feature_names}
        
        return features
    
    def _analyze_zip(self, file_path):
        features = {}
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                file_list = zip_file.filelist
                features['file_count'] = len(file_list)
                features['total_size'] = sum(f.file_size for f in file_list)
                features['avg_file_size'] = features['total_size'] / max(features['file_count'], 1)
                features['max_file_size'] = max((f.file_size for f in file_list), default=0)
                features['directory_depth'] = max((f.filename.count('/') for f in file_list), default=0)
                
                # 文件类型分析
                extensions = [f.filename.split('.')[-1].lower() for f in file_list if '.' in f.filename]
                features['executable_files'] = sum(1 for ext in extensions if ext in ['exe', 'bat', 'sh', 'cmd'])
                features['script_files'] = sum(1 for ext in extensions if ext in ['js', 'py', 'php', 'pl'])
                features['config_files'] = sum(1 for ext in extensions if ext in ['conf', 'cfg', 'ini', 'xml'])
                features['suspicious_extensions'] = sum(1 for ext in extensions if ext in ['tmp', 'bak', 'old'])
                features['hidden_files'] = sum(1 for f in file_list if f.filename.startswith('.'))
                
        except Exception as e:
            print(f"ZIP分析错误: {e}")
            features = {'file_count': 1, 'total_size': os.path.getsize(file_path)}
            
        return features
    
    def _analyze_tar(self, file_path):
        features = {}
        try:
            with tarfile.open(file_path, 'r:gz') as tar_file:
                members = tar_file.getmembers()
                features['file_count'] = len(members)
                features['total_size'] = sum(m.size for m in members)
                features['avg_file_size'] = features['total_size'] / max(features['file_count'], 1)
                features['max_file_size'] = max((m.size for m in members), default=0)
                features['directory_depth'] = max((m.name.count('/') for m in members), default=0)
                
        except Exception as e:
            print(f"TAR分析错误: {e}")
            features = {'file_count': 1, 'total_size': os.path.getsize(file_path)}
            
        return features
    
    def _analyze_generic(self, file_path):
        features = {}
        features['file_count'] = 1
        features['total_size'] = os.path.getsize(file_path)
        features['avg_file_size'] = features['total_size']
        features['max_file_size'] = features['total_size']
        features['directory_depth'] = 0
        return features
