import time
import json
import os
import threading
import sqlite3
from app.services.extractor import FeatureExtractor
from app.services.classifier import SecurityClassifier
from app.services.analyzer import DeepSeekAnalyzer
from config import Config

# 初始化服务实例
feature_extractor = FeatureExtractor()
security_classifier = SecurityClassifier()
deepseek_analyzer = DeepSeekAnalyzer()

# 扫描任务管理
scan_tasks = {}

def background_scan(scan_id, file_path, user_id):
    """后台扫描任务"""
    start_time = time.time()
    try:
        # 更新状态
        update_scan_status(scan_id, 'extracting_features')
        time.sleep(2)  # 模拟特征提取时间
        
        # 提取特征
        features = feature_extractor.extract_features(file_path)
        
        # 更新状态
        update_scan_status(scan_id, 'xgboost_analysis')
        time.sleep(3)  # 模拟XGBoost分析时间
        
        # XGBoost分析
        xgboost_result = security_classifier.predict(features)
        
        # 更新状态
        update_scan_status(scan_id, 'llm_analysis')
        time.sleep(5)  # 模拟大模型分析时间
        
        # DeepSeek分析
        filename = os.path.basename(file_path)
        llm_result = deepseek_analyzer.analyze_package(filename, features, xgboost_result)
        
        # 计算最终结果
        final_confidence = (xgboost_result['confidence'] + llm_result['confidence']) / 2
        scan_time = time.time() - start_time
        
        # 更新数据库
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE scan_records 
            SET scan_status = ?, risk_level = ?, confidence = ?, 
                xgboost_result = ?, llm_result = ?, risk_explanation = ?, scan_time = ?
            WHERE id = ?
        ''', (
            'completed',
            llm_result['risk_level'],
            final_confidence,
            json.dumps(xgboost_result),
            json.dumps(llm_result),
            llm_result['analysis'],
            scan_time,
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
        print(f"扫描任务错误: {e}")
        update_scan_status(scan_id, 'failed')
        scan_tasks[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'current_task': '检测失败'
        }

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
