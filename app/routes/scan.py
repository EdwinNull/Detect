from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
import threading
import hashlib
import json
import sqlite3
from app.utils import login_required
from app.tasks import background_scan, scan_tasks
from config.config import Config
from app.utils.helpers import detect_package_type
from app.models.db_models import ScanRecord, FeatureData
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import requests
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import joblib
from xgboost import XGBClassifier
import warnings
import subprocess
<<<<<<< HEAD
import sys
=======
>>>>>>> 7f1897f (latest)
warnings.filterwarnings('ignore')

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

@scan_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
<<<<<<< HEAD
    try:
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
            
        if file:
            # 确保上传目录存在
            os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            
            # 检查文件后缀是否合法
            allowed_extensions = ['.zip', '.tar.gz', '.tgz', '.whl', '.jar', '.npm']
            file_ext = os.path.splitext(filename)[1].lower()
            if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
                return jsonify({'error': f'不支持的文件类型。请上传 {", ".join(allowed_extensions)} 格式的文件'}), 400
            
            # 保存文件
            try:
                file.save(file_path)
            except Exception as e:
                print(f"文件保存失败: {str(e)}")
                return jsonify({'error': '文件保存失败，请重试'}), 500
                
            # 计算文件哈希
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                file_size = os.path.getsize(file_path)
            except Exception as e:
                print(f"文件处理失败: {str(e)}")
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify({'error': '文件处理失败，请重试'}), 500
            
            # 检测包类型
            try:
                package_type = detect_package_type(file_path)
            except Exception as e:
                print(f"包类型检测失败: {str(e)}")
                package_type = 'unknown'
            
            # 创建扫描记录
            try:
                conn = sqlite3.connect(Config.DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_records (user_id, filename, file_size, file_hash, scan_status, package_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session['user_id'], filename, file_size, file_hash, 'pending', package_type))
                scan_id = cursor.lastrowid
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"数据库操作失败: {str(e)}")
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify({'error': '创建扫描记录失败，请重试'}), 500
            
            # 初始化任务状态
            scan_tasks[scan_id] = {
                'status': 'pending',
                'progress': 0,
                'current_task': '开始检测'
            }
            
            # 启动后台扫描任务
            try:
                thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
                thread.daemon = True
                thread.start()
            except Exception as e:
                print(f"启动扫描线程失败: {str(e)}")
                # 更新任务状态为失败
                conn = sqlite3.connect(Config.DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE scan_records SET scan_status = "failed", error_message = ? WHERE id = ?', 
                            (str(e), scan_id))
                conn.commit()
                conn.close()
                return jsonify({'error': '启动扫描失败，请重试'}), 500
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': '文件上传成功，开始检测'
            })
    except Exception as e:
        print(f"上传处理过程中发生未捕获的错误: {str(e)}")
        return jsonify({'error': '上传过程中发生错误，请重试'}), 500
=======
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        file.save(file_path)
        # 计算文件哈希
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        file_size = os.path.getsize(file_path)
        # 检测包类型
        package_type = detect_package_type(file_path)
        # 创建扫描记录
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_records (user_id, filename, file_size, file_hash, scan_status, package_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], filename, file_size, file_hash, 'pending', package_type))
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
        thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
        thread.daemon = True
        thread.start()
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '文件上传成功，开始检测'
        })
>>>>>>> 7f1897f (latest)

@scan_bp.route('/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    # 从内存中获取实时状态
    if scan_id in scan_tasks:
        task_status = scan_tasks[scan_id]
    else:
        # 从数据库获取状态
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT scan_status FROM scan_records WHERE id = ? AND user_id = ?', 
                      (scan_id, session['user_id']))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            status = result[0]
            task_status = {
                'status': status,
                'progress': 100 if status == 'completed' else 0,
                'current_task': '检测完成' if status == 'completed' else '检测中'
            }
        else:
            return jsonify({'error': '扫描记录不存在'}), 404
    
    return jsonify(task_status)

@scan_bp.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    """显示扫描结果页面"""
    # 获取扫描记录
    scan_record = ScanRecord.get_by_id(scan_id)
    if not scan_record:
        flash('扫描记录不存在')
        return redirect(url_for('user.index'))
    
    # 获取特征数据
    feature_data = FeatureData.get_by_scan_id(scan_id)
    
    # 解析xgboost_result和llm_result
    xgboost_result = {}
    llm_result = {}

    try:
        xgboost_result = json.loads(scan_record.xgboost_result) if scan_record.xgboost_result else {}
    except json.JSONDecodeError:
        print(f"Error decoding xgboost_result for scan_id {scan_id}")

    try:
        llm_result = json.loads(scan_record.llm_result) if scan_record.llm_result else {}
    except json.JSONDecodeError:
        print(f"Error decoding llm_result for scan_id {scan_id}")
        flash('AI分析结果存在格式问题，部分信息可能无法展示。', 'warning')
    
    # 确保llm_result包含所有必要字段
    if llm_result:
        llm_result = {
            'risk_level': llm_result.get('risk_level', 'unknown'),
            'confidence': llm_result.get('confidence', 0.0),
            'type': llm_result.get('type', '未知'),
            'reason': llm_result.get('reason', '无'),
            'top_features': llm_result.get('top_features', []),
            'risk_points': llm_result.get('risk_points', '无'),
            'advice_list': llm_result.get('advice_list', []),
            'raw_analysis': llm_result.get('raw_analysis', '')
        }
    else:
        llm_result = {
            'risk_level': 'unknown',
            'confidence': 0.0,
            'type': '未知',
            'reason': '无',
            'top_features': [],
            'risk_points': '无',
            'advice_list': [],
            'raw_analysis': ''
        }
    
    # 准备数据
    scan_data = {
        'id': scan_record.id,
        'filename': scan_record.filename,
        'file_size': scan_record.file_size,
        'scan_time': scan_record.scan_time,
        'risk_level': scan_record.risk_level,
        'confidence': scan_record.confidence,
        'features': json.loads(feature_data.feature_data) if feature_data and feature_data.feature_data else {},
        'xgboost_result': {
            'prediction': xgboost_result.get('prediction', 0),
            'confidence': xgboost_result.get('confidence', 0.0),
            'risk_score': xgboost_result.get('risk_score', 0.0),
            'risk_level': xgboost_result.get('risk_level', 'unknown'),
            'feature_importance': xgboost_result.get('feature_importance', {})
        },
        'llm_result': llm_result,
        'malicious_code_snippet': scan_record.malicious_code_snippet,
        'code_location': scan_record.code_location,
        'malicious_action': scan_record.malicious_action,
        'technical_details': scan_record.technical_details
    }
    
    return render_template('results.html', scan_data=scan_data)

@scan_bp.route('/progress/<int:scan_id>')
@login_required
def progress(scan_id):
    return render_template('progress.html', scan_id=scan_id)

@scan_bp.route('/cancel_scan/<int:scan_id>', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 更新扫描状态为已取消
    cursor.execute('UPDATE scan_records SET scan_status = "cancelled" WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    
    # 从活动扫描任务中移除
    if scan_id in scan_tasks:
        del scan_tasks[scan_id]
    
    return jsonify({'success': True, 'message': '扫描已取消'})

@scan_bp.route('/retry_scan/<int:scan_id>', methods=['POST'])
@login_required
def retry_scan(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id, file_hash FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 更新扫描状态为待处理
    cursor.execute('UPDATE scan_records SET scan_status = "pending", risk_level = NULL, confidence = NULL, scan_result = NULL, llm_result = NULL, risk_explanation = NULL, scan_time = NULL WHERE id = ?', (scan_id,))
    conn.commit()
    
    # 查找文件路径
    file_hash = record[1]
    upload_dir = Config.UPLOAD_FOLDER
    
    # 查找可能的文件路径
    potential_files = []
    for root, dirs, files in os.walk(upload_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    current_hash = hashlib.md5(f.read()).hexdigest()
                    if current_hash == file_hash:
                        potential_files.append(file_path)
            except:
                continue
    
    conn.close()
    
    if not potential_files:
        return jsonify({'error': '找不到原始文件，无法重新检测'}), 404
    
    # 使用找到的第一个匹配文件进行重新检测
    file_path = potential_files[0]
    
    # 初始化任务状态
    scan_tasks[scan_id] = {
        'status': 'pending',
        'progress': 0,
        'current_task': '开始检测'
    }
    
    # 启动后台扫描任务
    thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': '已开始重新检测'})

@scan_bp.route('/delete_record/<int:scan_id>', methods=['POST'])
@login_required
def delete_record(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id, scan_status FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 如果扫描正在进行中，先取消扫描
    if record[1] == 'pending' and scan_id in scan_tasks:
        del scan_tasks[scan_id]
    
    # 删除扫描记录
    cursor.execute('DELETE FROM scan_records WHERE id = ?', (scan_id,))
    
    # 删除特征数据
    cursor.execute('DELETE FROM features WHERE scan_id = ?', (scan_id,))
    
    conn.commit()
    conn.close()
    
    # 删除相关报告文件
    report_paths = [
        f'static/reports/report_{scan_id}.json',
        f'static/reports/report_{scan_id}.pdf'
    ]
    
    for path in report_paths:
        if os.path.exists(path):
            try:
                os.remove(path)
            except:
                pass
    
    return jsonify({'success': True, 'message': '记录已删除'})

<<<<<<< HEAD
@scan_bp.route('/crawl_packages', methods=['GET', 'POST'])
@login_required
def crawl_packages():
    # 检查用户是否有管理员权限
    if session.get('role') != 'admin':
        flash('需要管理员权限来访问此功能', 'error')
        return redirect(url_for('user.index'))
        
    result = None
    if request.method == 'POST':
        pkg_type = request.form.get('pkg_type', 'npm')
        limit = request.form.get('limit', 5)
        try:
            limit = int(limit)
        except Exception:
            limit = 5
        # 构造命令
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'scripts', 'package_crawler.py')
        if pkg_type not in ['npm', 'pypi']:
            pkg_type = 'npm'
        cmd = [sys.executable, script_path, pkg_type, str(limit)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            result = proc.stdout + '\n' + proc.stderr
        except Exception as e:
            result = f'抓取失败: {e}'
    return render_template('crawl_packages.html', result=result)
=======
# 辅助函数：下载包并返回路径
def download_package(pkg_name, pkg_version, pkg_type):
    download_dir = Config.UPLOAD_FOLDER
    
    if pkg_type == 'pypi':
        cmd = f"pip download {pkg_name}=={pkg_version} --no-deps --no-binary=:all: -d {download_dir}"
    elif pkg_type == 'npm':
        cmd = f"npm pack {pkg_name}@{pkg_version}"
    else:
        return None, "不支持的包类型"

    try:
        # 使用 subprocess 运行命令
        # 注意：在生产环境中，需要更严格的输入验证和错误处理
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=download_dir, timeout=300)
        
        if result.returncode != 0:
            return None, result.stderr or "下载失败"

        # 查找下载的文件
        if pkg_type == 'pypi':
            # pip download a.b.c 会下载 a-b-c.tar.gz
            safe_name = pkg_name.replace('-', '_')
            files = list(Path(download_dir).glob(f"{safe_name}-{pkg_version}*.tar.gz"))
            if not files:
                 files = list(Path(download_dir).glob(f"{pkg_name}-{pkg_version}*.tar.gz"))
        else: # npm
            # npm pack a-b-c 会下载 a-b-c-1.2.3.tgz
            # npm pack @a/b-c 会下载 a-b-c-1.2.3.tgz
            safe_name = pkg_name.replace('/', '-')
            files = list(Path(download_dir).glob(f"{safe_name}-{pkg_version}.tgz"))

        if files:
            return str(files[0]), None
        else:
            return None, "未找到下载的包文件"
            
    except Exception as e:
        return None, str(e)

@scan_bp.route('/crawl_and_scan', methods=['POST'])
@login_required
def crawl_and_scan():
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401

    pkg_name = request.form.get('pkg_name')
    pkg_version = request.form.get('pkg_version', 'latest')
    pkg_type = request.form.get('pkg_type')

    if not all([pkg_name, pkg_version, pkg_type]):
        return jsonify({'error': '缺少必要参数'}), 400

    # 下载包
    file_path, error = download_package(pkg_name, pkg_version, pkg_type)

    if error:
        return jsonify({'error': f'抓取失败: {error}'}), 500
    
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    with open(file_path, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()

    # 创建扫描记录
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_records (user_id, filename, file_size, file_hash, scan_status, package_type)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (session['user_id'], filename, file_size, file_hash, 'pending', pkg_type))
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
    thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': '包抓取成功，已加入扫描队列'
    })
>>>>>>> 7f1897f (latest)
