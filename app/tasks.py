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
        print(f"开始扫描任务 {scan_id} 文件: {file_path}")
        
        # 更新状态
        update_scan_status(scan_id, 'extracting_features')
        print(f"扫描 {scan_id}: 开始提取特征")
        time.sleep(2)  # 模拟特征提取时间
        
        # 提取特征
        features = feature_extractor.extract_features(file_path)
        print(f"扫描 {scan_id}: 特征提取完成")
        
        # 更新状态
        update_scan_status(scan_id, 'xgboost_analysis')
        print(f"扫描 {scan_id}: 开始XGBoost分析")
        time.sleep(3)  # 模拟XGBoost分析时间
        
        # XGBoost分析
        xgboost_result = security_classifier.predict(features)
        
        # 确保XGBoost结果包含所需字段
        if 'risk_level' not in xgboost_result:
            xgboost_result['risk_level'] = 'medium'  # 默认中等风险
            print(f"扫描 {scan_id}: XGBoost结果缺少风险等级，使用默认值: medium")
        
        print(f"扫描 {scan_id}: XGBoost分析完成，结果: {xgboost_result['risk_level']}")
        
        # 更新状态
        update_scan_status(scan_id, 'llm_analysis')
        print(f"扫描 {scan_id}: 开始大模型分析")
        time.sleep(5)  # 模拟大模型分析时间
        
        # DeepSeek分析
        filename = os.path.basename(file_path)
        llm_result = deepseek_analyzer.analyze_package(filename, features, xgboost_result)
        print(f"扫描 {scan_id}: 大模型分析完成，结果: {llm_result['risk_level']}")
        
        # 计算最终结果 - 确保置信度不超过1.0
        xgboost_confidence = min(1.0, xgboost_result.get('confidence', 0.5))
        llm_confidence = min(1.0, llm_result.get('confidence', 0.5))
        final_confidence = min(1.0, (xgboost_confidence + llm_confidence) / 2)
        
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
        
        print(f"扫描 {scan_id}: 数据库记录已更新，风险级别: {llm_result['risk_level']}, 置信度: {final_confidence:.2f}")
        
        # 保存特征数据
        try:
            cursor.execute('''
                INSERT INTO features (scan_id, feature_data)
                VALUES (?, ?)
            ''', (scan_id, json.dumps(features)))
            print(f"扫描 {scan_id}: 特征数据已保存")
        except Exception as e:
            print(f"扫描 {scan_id}: 保存特征数据失败: {e}")
        
        conn.commit()
        conn.close()
        
        # 更新任务状态
        scan_tasks[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'current_task': '检测完成'
        }
        
        print(f"扫描 {scan_id}: 任务完成，总耗时: {scan_time:.2f}秒")
        
        # 清理临时文件
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"扫描 {scan_id}: 临时文件已清理")
            
    except Exception as e:
        import traceback
        print(f"扫描任务 {scan_id} 错误: {e}")
        print(traceback.format_exc())
        
        # 更新数据库中的状态为失败
        try:
            conn = sqlite3.connect(Config.DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('UPDATE scan_records SET scan_status = "failed" WHERE id = ?', (scan_id,))
            conn.commit()
            conn.close()
            print(f"扫描 {scan_id}: 已将数据库状态更新为失败")
        except Exception as db_error:
            print(f"扫描 {scan_id}: 更新数据库失败状态时出错: {db_error}")
        
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

def execute_immediate_scan():
    """立即执行一次批量抓取和检测任务"""
    from app.services.fetcher import package_fetcher
    
    try:
        print("开始执行立即批量抓取任务...")
        packages = package_fetcher.fetch_latest_packages(limit=20)  # 抓取20个包
        
        if packages:
            print(f"立即任务完成: 抓取并检测了 {len(packages)} 个包")
            return len(packages)
        else:
            print("立即任务完成: 没有抓取到新包")
            return 0
    except Exception as e:
        print(f"立即抓取任务出错: {e}")
        return 0
