import os
import json
import sqlite3
import hashlib
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from flask import current_app, g
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import joblib
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

# 导入配置
from config.config import Config
from app.services.extractor import FeatureExtractor
from app.services.classifier import SecurityClassifier
from app.services.analyzer import DeepSeekAnalyzer
from app.services.csv_feature_extractor import CsvFeatureExtractor

# 初始化服务实例
feature_extractor = FeatureExtractor()

# 初始化csv特征提取器
csv_feature_extractor = CsvFeatureExtractor()

# 预初始化所有模型
security_classifiers = {
    'js_model': SecurityClassifier(model_type='js_model'),
    'py_model': SecurityClassifier(model_type='py_model'),
    'cross_language': SecurityClassifier(model_type='cross_language'),
    'xgboost': SecurityClassifier(model_type='xgboost')
}

deepseek_analyzer = DeepSeekAnalyzer()

# 扫描任务管理
scan_tasks = {}

def background_scan(scan_id, file_path, user_id):
    """后台扫描任务"""
    start_time = time.time()
    try:
        print(f"[DEBUG] 开始扫描任务: scan_id={scan_id}, file_path={file_path}")
        
        # 更新状态
        update_scan_status(scan_id, 'extracting_features')
        time.sleep(2)  # 模拟特征提取时间
        
        # 判断是否用csv体系
        use_csv_features = False
        # 你可以根据模型类型、文件名、配置等条件判断
        # 这里举例：如果模型类型为'csv_model'，则用csv特征体系
        filename = os.path.basename(file_path)
        print(f"[DEBUG] 文件名: {filename}")
        
        if filename.endswith('.js') or filename.endswith('.json'):
            model_type = 'js_model'
        elif filename.endswith('.py'):
            model_type = 'py_model'
        elif filename.endswith('.csvmodel') or filename.endswith('.csvpkg'):
            model_type = 'csv_model'
            use_csv_features = True
        else:
            model_type = 'cross_language'
        
        print(f"[DEBUG] 选择的模型类型: {model_type}")
        
        if use_csv_features or model_type == 'csv_model':
            features = csv_feature_extractor.extract_features(file_path)
            print(f"[DEBUG] (CSV) 文件: {file_path}")
            print(f"[DEBUG] (CSV) 特征名: {csv_feature_extractor.feature_names}")
            print(f"[DEBUG] (CSV) 特征向量: {csv_feature_extractor.get_feature_vector(features)}")
        else:
            features = feature_extractor.extract_features(file_path)
            print(f"[DEBUG] 文件: {file_path}")
            print(f"[DEBUG] 提取特征: {json.dumps(features, ensure_ascii=False, indent=2)}")
        
        if not features:
            raise Exception("特征提取失败")
        
        # 检查包名是否在白名单中
        package_name = features.get('package_name')
        print(f"[DEBUG] 提取到的包名: {package_name}")
        
        # 根据文件类型选择合适的模型
        if filename.endswith('.js') or filename.endswith('.json'):
            model_type = 'js_model'
        elif filename.endswith('.py'):
            model_type = 'py_model'
        else:
            model_type = 'cross_language'
        
        print(f"[DEBUG] 最终选择的模型类型: {model_type}")
        
        # 更新状态
        update_scan_status(scan_id, f'{model_type}_analysis')
        time.sleep(3)  # 模拟模型分析时间
        
        # 专用模型分析
        classifier = security_classifiers.get(model_type)
        if not classifier or not classifier.is_trained:
            print(f"专用模型{model_type}未就绪，尝试重新加载")
            classifier = SecurityClassifier(model_type=model_type)
            security_classifiers[model_type] = classifier
        
        # 打印特征向量
        if hasattr(classifier, 'feature_names'):
            feature_vector = [features.get(f, 0) for f in classifier.feature_names]
            print(f"[DEBUG] 特征名: {classifier.feature_names}")
            print(f"[DEBUG] 特征向量: {feature_vector}")
        
        print(f"[DEBUG] 开始模型预测...")
        model_result = classifier.predict(features)
        print(f"[DEBUG] 模型输出: {model_result}")
        
        if not model_result:
            # 如果专用模型分析失败,使用通用XGBoost模型
            print("专用模型分析失败，使用XGBoost模型")
            update_scan_status(scan_id, 'xgboost_analysis')
            classifier = security_classifiers.get('xgboost')
            if not classifier or not classifier.is_trained:
                classifier = SecurityClassifier(model_type='xgboost')
                security_classifiers['xgboost'] = classifier
            model_result = classifier.predict(features)
            print(f"[DEBUG] XGBoost模型输出: {model_result}")
            
            if not model_result:
                # 如果模型预测失败，使用默认值
                model_result = {
                    'prediction': 0,
                    'confidence': 0.5,
                    'risk_score': 0.0,
                    'risk_level': 'unknown',
                    'feature_importance': {}
                }
        
        # 确保model_result包含所有必要字段
        if 'risk_score' not in model_result:
            model_result['risk_score'] = 0.0
        if 'feature_importance' not in model_result:
            model_result['feature_importance'] = {}
        if 'risk_level' not in model_result:
            model_result['risk_level'] = 'unknown'
        
        print(f"[DEBUG] 最终模型结果: {model_result}")
        
        # 更新状态
        update_scan_status(scan_id, 'llm_analysis')
        time.sleep(5)  # 模拟大模型分析时间
        
        # DeepSeek分析
        print("[DEBUG] 即将调用 deepseek_analyzer.analyze_package")
        llm_result = deepseek_analyzer.analyze_package(filename, features, model_result)
        print("[DEBUG] deepseek_analyzer.analyze_package 调用完成，llm_result:", llm_result)
        if not llm_result:
            raise Exception("大模型分析失败")
        
        # 计算最终结果
        model_confidence = model_result.get('confidence', 0.5)
        llm_confidence = llm_result.get('confidence', 0.5)
        final_confidence = (model_confidence + llm_confidence) / 2
        scan_time = time.time() - start_time
        
        print(f"[DEBUG] 最终风险等级: {model_result.get('risk_level', 'unknown')}")
        print(f"[DEBUG] 最终置信度: {final_confidence}")
        
        # 更新数据库
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # 预处理代码片段，确保是字符串
        snippet_data = llm_result.get('malicious_code_snippet', '')
        if isinstance(snippet_data, list):
            snippet_to_save = '\n'.join(snippet_data)
        else:
            snippet_to_save = str(snippet_data)

        cursor.execute('''
            UPDATE scan_records 
            SET scan_status = ?, risk_level = ?, confidence = ?, 
                xgboost_result = ?, llm_result = ?, risk_explanation = ?, scan_time = ?,
                malicious_code_snippet = ?, code_location = ?, malicious_action = ?,
                technical_details = ?
            WHERE id = ?
        ''', (
            'completed',
            llm_result.get('risk_level', 'unknown'),
            final_confidence,
            json.dumps(model_result),
            json.dumps(llm_result),
            llm_result.get('risk_explanation', '分析失败'),
            scan_time,
            snippet_to_save,
            llm_result.get('code_location', ''),
            llm_result.get('malicious_action', ''),
            llm_result.get('technical_details', ''),
            scan_id
        ))
        
        # 保存特征数据
        cursor.execute('''
            INSERT INTO features (scan_id, feature_data)
            VALUES (?, ?)
        ''', (scan_id, json.dumps(features)))
        
        conn.commit()
        conn.close()
        
        # 更新任务状态
        scan_tasks[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'current_task': '检测完成'
        }
        
        # 清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)
            
    except Exception as e:
        print(f"扫描任务失败: {str(e)}")
        # 更新任务状态为失败
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scan_records 
            SET scan_status = ?, error_message = ?
            WHERE id = ?
        ''', ('failed', str(e), scan_id))
        conn.commit()
        conn.close()
        
        # 更新任务状态
        scan_tasks[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'current_task': f'检测失败: {str(e)}'
        }
        
        # 清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)

def update_scan_status(scan_id, status):
    """更新扫描状态"""
    status_map = {
        'extracting_features': {'progress': 25, 'task': '提取语言无关特征'},
        'xgboost_analysis': {'progress': 50, 'task': 'XGBoost模型初筛'},
        'llm_analysis': {'progress': 75, 'task': '大模型复筛分析'},
        'completed': {'progress': 100, 'task': '检测完成'},
        'failed': {'progress': 0, 'task': '检测失败'}
    }
    
    if scan_id in scan_tasks:
        info = status_map.get(status, {'progress': 0, 'task': '未知状态'})
        scan_tasks[scan_id].update({
            'status': status,
            'progress': info['progress'],
            'current_task': info['task']
        })
