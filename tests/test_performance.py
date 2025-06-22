#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.extractor import FeatureExtractor
from app.utils.helpers import detect_package_type

def test_performance():
    """测试特征提取性能"""
    extractor = FeatureExtractor()
    
    # 测试文件列表
    test_files = [
        "uploads/vicious.zip",
        "uploads/0xzyo-confutionrce.zip"
    ]
    
    for file_path in test_files:
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            continue
            
        print(f"\n{'='*50}")
        print(f"测试文件: {file_path}")
        print(f"文件大小: {os.path.getsize(file_path) / 1024 / 1024:.2f} MB")
        print(f"{'='*50}")
        
        # 测试包类型检测
        start_time = time.time()
        package_type = detect_package_type(file_path)
        type_time = time.time() - start_time
        print(f"包类型检测: {package_type} (耗时: {type_time:.2f}秒)")
        
        # 测试特征提取
        start_time = time.time()
        features = extractor.extract_features(file_path)
        extract_time = time.time() - start_time
        
        if features:
            print(f"特征提取成功 (耗时: {extract_time:.2f}秒)")
            print(f"提取特征数量: {len(features)}")
            
            # 显示一些关键特征
            key_features = ['file_size', 'line_count', 'malicious_patterns', 'vulnerability_patterns']
            for key in key_features:
                if key in features:
                    print(f"  {key}: {features[key]}")
        else:
            print(f"特征提取失败 (耗时: {extract_time:.2f}秒)")
        
        print(f"总耗时: {type_time + extract_time:.2f}秒")

if __name__ == "__main__":
    test_performance() 