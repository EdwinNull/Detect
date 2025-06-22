#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.extractor import FeatureExtractor
from app.services.classifier import SecurityClassifier
import json

def test_csv_based_detection():
    """测试基于CSV数据的检测系统"""
    print("=== 测试基于CSV数据的检测系统 ===")
    
    # 初始化特征提取器和分类器
    extractor = FeatureExtractor()
    classifier = SecurityClassifier(model_type='xgboost')
    
    # 测试恶意包路径
    malicious_packages = [
        'vicious/agoric-zoe-0.26.3-u14.0.tgz',
        'vicious/ckeditor-ckeditor5-document-outline-41.2.1.tgz',
        'vicious/ckeditor-ckeditor5-export-pdf-41.2.1.tgz',
        'vicious/ckeditor-ckeditor5-format-painter-41.2.1.tgz',
        'vicious/ckeditor-ckeditor5-import-word-41.2.1.tgz',
        'vicious/ckeditor-ckeditor5-pagination-41.2.1.tgz',
        'vicious/ckeditor-ckeditor5-slash-command-41.2.1.tgz',
        'vicious/loadingio-loading.css-3.2.1.tgz',
        'vicious/pulumi-aws-6.28.2.tgz',
        'vicious/vipen-0.2.4.tgz'
    ]
    
    print(f"找到 {len(malicious_packages)} 个恶意包进行测试")
    
    for i, package_path in enumerate(malicious_packages, 1):
        if not os.path.exists(package_path):
            print(f"跳过不存在的包: {package_path}")
            continue
            
        print(f"\n--- 测试包 {i}: {os.path.basename(package_path)} ---")
        
        try:
            # 提取特征
            print("正在提取特征...")
            features = extractor.extract_features(package_path)
            
            if features is None:
                print("特征提取失败")
                continue
                
            print(f"提取了 {len(features)} 个特征")
            
            # 显示一些关键特征
            key_features = [
                'Number of Words in source code',
                'Number of lines in source code',
                'Number of base64 chunks in source code',
                'Number of IP adress in source code',
                'Number of sospicious token in source code',
                'shannon mean ID source code',
                'shannon max ID source code',
                'plus ratio max',
                'eq ratio max',
                'bracket ratio max'
            ]
            
            print("关键特征值:")
            for feature in key_features:
                value = features.get(feature, 0)
                print(f"  {feature}: {value}")
            
            # 进行预测
            print("正在进行风险预测...")
            result = classifier.predict(features)
            
            if result:
                print(f"预测结果:")
                print(f"  风险等级: {result['risk_level']}")
                print(f"  风险分数: {result['risk_score']:.3f}")
                print(f"  置信度: {result['confidence']:.3f}")
                print(f"  预测标签: {'恶意' if result['prediction'] == 1 else '正常'}")
            else:
                print("预测失败")
                
        except Exception as e:
            print(f"处理包时出错: {str(e)}")
            continue
    
    print("\n=== 测试完成 ===")

def test_feature_extraction():
    """测试特征提取功能"""
    print("\n=== 测试特征提取功能 ===")
    
    extractor = FeatureExtractor()
    
    # 测试一个简单的包
    test_package = 'vicious/vipen-0.2.4.tgz'
    
    if os.path.exists(test_package):
        print(f"测试包: {test_package}")
        
        try:
            features = extractor.extract_features(test_package)
            
            if features:
                print(f"成功提取 {len(features)} 个特征")
                
                # 显示所有特征
                print("所有特征:")
                for feature, value in features.items():
                    print(f"  {feature}: {value}")
            else:
                print("特征提取失败")
                
        except Exception as e:
            print(f"特征提取错误: {str(e)}")
    else:
        print(f"测试包不存在: {test_package}")

if __name__ == "__main__":
    test_csv_based_detection()
    test_feature_extraction() 