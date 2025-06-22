import os
import csv
import numpy as np

class CsvFeatureExtractor:
    def __init__(self, csv_path=None):
        # 自动读取csv第一行，获取特征名顺序
        if csv_path is None:
            csv_path = os.path.join(os.path.dirname(__file__), '../../data/datasets/npm_feature_extracted.csv')
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
        # 去掉Package Name
        self.feature_names = [name for name in header if name.strip() != 'Package Name']

    def extract_features(self, file_path, extra_features=None):
        """
        从文件中提取特征，确保所有特征都有合理的默认值
        
        Args:
            file_path: 文件路径
            extra_features: 额外的特征字典
            
        Returns:
            dict: 特征字典，包含所有必要的特征
        """
        features = {}
        
        # 设置基本特征的默认值
        basic_features = {
            'Number of Words in source code': 0,
            'Number of lines in source code': 0,
            'Number of base64 chunks in source code': 0,
            'Number of IP adress in source code': 0,
            'Number of sospicious token in source code': 0,
            'Number of Words in metadata': 0,
            'Number of lines in metadata': 0,
            'Number of base64 chunks in metadata': 0,
            'Number of IP adress in metadata': 0,
            'Number of sospicious token in metadata': 0,
        }
        
        # 设置比率特征的默认值
        ratio_features = {
            'plus ratio mean': 0.0,
            'plus ratio max': 0.0,
            'plus ratio std': 0.0,
            'plus ratio q3': 0.0,
            'eq ratio mean': 0.0,
            'eq ratio max': 0.0,
            'eq ratio std': 0.0,
            'eq ratio q3': 0.0,
            'bracket ratio mean': 0.0,
            'bracket ratio max': 0.0,
            'bracket ratio std': 0.0,
            'bracket ratio q3': 0.0,
        }
        
        # 设置熵特征的默认值
        entropy_features = {
            'shannon mean ID source code': 0.0,
            'shannon std ID source code': 0.0,
            'shannon max ID source code': 0.0,
            'shannon q3 ID source code': 0.0,
            'shannon mean string source code': 0.0,
            'shannon std string source code': 0.0,
            'shannon max string source code': 0.0,
            'shannon q3 string source code': 0.0,
            'shannon mean ID metadata': 0.0,
            'shannon std ID metadata': 0.0,
            'shannon max ID metadata': 0.0,
            'shannon q3 ID metadata': 0.0,
            'shannon mean string metadata': 0.0,
            'shannon std string metadata': 0.0,
            'shannon max string metadata': 0.0,
            'shannon q3 string metadata': 0.0,
        }
        
        # 设置标识符和字符串特征的默认值
        identifier_features = {
            'homogeneous identifiers in source code': 0,
            'homogeneous strings in source code': 0,
            'heteregeneous identifiers in source code': 0,
            'heterogeneous strings in source code': 0,
            'homogeneous identifiers in metadata': 0,
            'homogeneous strings in metadata': 0,
            'heterogeneous strings in metadata': 0,
            'heteregeneous identifiers in metadata': 0,
            'URLs in source code': 0,
            'URLs in metadata': 0,
        }
        
        # 设置文件类型特征的默认值
        file_type_features = {ext: 0 for ext in [
            '.bat', '.bz2', '.c', '.cert', '.conf', '.cpp', '.crt', '.css', '.csv',
            '.deb', '.erb', '.gemspec', '.gif', '.gz', '.h', '.html', '.ico', '.ini',
            '.jar', '.java', '.jpg', '.js', '.json', '.key', '.m4v', '.markdown',
            '.md', '.pdf', '.pem', '.png', '.ps', '.py', '.rb', '.rpm', '.rst',
            '.sh', '.svg', '.toml', '.ttf', '.txt', '.xml', '.yaml', '.yml',
            '.eot', '.exe', '.jpeg', '.properties', '.sql', '.swf', '.tar',
            '.woff', '.woff2', '.aac', '.bmp', '.cfg', '.dcm', '.dll', '.doc',
            '.flac', '.flv', '.ipynb', '.m4a', '.mid', '.mkv', '.mp3', '.mp4',
            '.mpg', '.ogg', '.otf', '.pickle', '.pkl', '.psd', '.pxd', '.pxi',
            '.pyc', '.pyx', '.r', '.rtf', '.so', '.sqlite', '.tif', '.tp',
            '.wav', '.webp', '.whl', '.xcf', '.xz', '.zip', '.mov', '.wasm', '.webm'
        ]}
        
        # 设置其他特征的默认值
        other_features = {
            'repository': 0,
            'presence of installation script': 0,
        }
        
        # 合并所有默认特征
        features.update(basic_features)
        features.update(ratio_features)
        features.update(entropy_features)
        features.update(identifier_features)
        features.update(file_type_features)
        features.update(other_features)
        
        # 如果提供了额外特征，使用它们覆盖默认值
        if extra_features:
            for name, value in extra_features.items():
                if name in features:
                    features[name] = value
                    
        print(f"\n特征向量统计:")
        print(f"- 基本特征数: {len(basic_features)}")
        print(f"- 比率特征数: {len(ratio_features)}")
        print(f"- 熵特征数: {len(entropy_features)}")
        print(f"- 标识符特征数: {len(identifier_features)}")
        print(f"- 文件类型特征数: {len(file_type_features)}")
        print(f"- 其他特征数: {len(other_features)}")
        print(f"- 总特征数: {len(features)}")
        
        # 检查是否有非零特征
        non_zero_features = {k: v for k, v in features.items() if v != 0}
        if non_zero_features:
            print("\n非零特征:")
            for k, v in non_zero_features.items():
                print(f"- {k}: {v}")
        else:
            print("\n警告: 所有特征都为0!")
            
        return features

    def get_feature_vector(self, features):
        """按csv顺序生成特征向量"""
        return [features.get(name, 0) for name in self.feature_names] 