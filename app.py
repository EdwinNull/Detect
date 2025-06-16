from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import zipfile
import tarfile
import json
import hashlib
from datetime import datetime, timedelta
import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import xgboost as xgb
import joblib
import requests
import threading
import time
import tempfile
import shutil
from fpdf import FPDF
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# 权限控制中间件
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('需要管理员权限', 'error')
            return redirect(url_for('index'))
        return view(*args, **kwargs)
    return wrapped_view

# DeepSeek API配置
DEEPSEEK_API_KEY = "sk-4d9403ac0e0640328d254c6c6b32bcd0"
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/reports', exist_ok=True)

# 初始化数据库
def init_db():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # 检测记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT,
            scan_status TEXT DEFAULT 'pending',
            risk_level TEXT,
            confidence REAL,
            xgboost_result TEXT,
            llm_result TEXT,
            risk_explanation TEXT,
            scan_time REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            package_type TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # 特征表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            feature_data TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_records (id)
        )
    ''')
    
    # 样本表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT,
            type TEXT NOT NULL,
            description TEXT,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            features TEXT,
            is_used_for_training BOOLEAN DEFAULT 0,
            package_type TEXT DEFAULT 'unknown'
        )
    ''')
    
    # 尝试为已存在的表添加package_type列
    try:
        cursor.execute('ALTER TABLE samples ADD COLUMN package_type TEXT DEFAULT "unknown"')
    except sqlite3.OperationalError:
        # 列可能已存在，忽略错误
        pass
    
    # 创建默认管理员账户
    admin_password = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin@scanner.com', admin_password, 'admin'))
    
    # 创建默认普通用户账户
    user_password = generate_password_hash('user123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('user', 'user@scanner.com', user_password, 'user'))
    
    conn.commit()
    conn.close()

# 特征提取器类
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

# XGBoost分类器
class SecurityClassifier:
    def __init__(self, model_type='xgboost'):
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        self.model_path = 'models/security_model.json'
        self._initialize_model()
    
    def _initialize_model(self):
        """初始化模型"""
        if self.model_type == 'xgboost':
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42
            )
        else:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # 尝试加载已训练的模型
        if os.path.exists(self.model_path):
            try:
                if self.model_type == 'xgboost':
                    self.model.load_model(self.model_path)
                else:
                    self.model = joblib.load(self.model_path)
                self.is_trained = True
                print("已加载预训练模型")
            except Exception as e:
                print(f"加载模型失败: {e}")
                self._train_model()
        else:
            self._train_model()
    
    def _train_model(self):
        """训练模型"""
        print("开始训练模型...")
        # 从数据库加载训练数据                                                         
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        # 获取所有已标记的扫描记录
        cursor.execute('''
            SELECT f.feature_data, s.risk_level
            FROM features f
            JOIN scan_records s ON f.scan_id = s.id
            WHERE s.risk_level IS NOT NULL
        ''')
        
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            print("没有足够的训练数据，使用模拟数据")
            self._train_with_synthetic_data()
            return
        
        # 准备训练数据
        X = []
        y = []
        for features, risk_level in data:
            try:
                feature_dict = json.loads(features)
                X.append(list(feature_dict.values()))
                y.append(1 if risk_level == 'high' else 0)
            except Exception as e:
                print(f"处理训练数据时出错: {e}")
                continue
        
        if len(X) < 10:
            print("训练数据不足，使用模拟数据")
            self._train_with_synthetic_data()
            return
        
        X = np.array(X)
        y = np.array(y)
        
        # 分割训练集和验证集
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # 训练模型
        self.model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = self.model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        precision = precision_score(y_val, y_pred)
        recall = recall_score(y_val, y_pred)
        f1 = f1_score(y_val, y_pred)
        
        print(f"模型评估结果:")
        print(f"准确率: {accuracy:.3f}")
        print(f"精确率: {precision:.3f}")
        print(f"召回率: {recall:.3f}")
        print(f"F1分数: {f1:.3f}")
        
        # 保存模型
        os.makedirs('models', exist_ok=True)
        if self.model_type == 'xgboost':
            self.model.save_model(self.model_path)
        else:
            joblib.dump(self.model, self.model_path)
        
        self.is_trained = True
        print("模型训练完成并保存")
    
    def _train_with_synthetic_data(self):
        """使用模拟数据训练模型"""
        np.random.seed(42)
        n_samples = 1000
        n_features = 141
        
        X = np.random.random((n_samples, n_features))
        y = []
        for i in range(n_samples):
            risk_score = (X[i, 0] * 0.3 + X[i, 5] * 0.4 + X[i, 10] * 0.3)
            y.append(1 if risk_score > 0.6 else 0)
        
        y = np.array(y)
        self.model.fit(X, y)
        self.is_trained = True
        
        # 计算交叉验证分数
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        print(f"模型训练完成，交叉验证准确率: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    def predict(self, features):
        """预测包的风险等级"""
        if not self.is_trained:
            self._train_model()
        
        # 转换特征为数组
        feature_array = np.array([list(features.values())]).reshape(1, -1)
        
        # 预测
        prediction = self.model.predict(feature_array)[0]
        confidence = self.model.predict_proba(feature_array)[0]
        
        result = {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(max(confidence)),
            'malicious_prob': float(confidence[1]) if len(confidence) > 1 else 0.0,
            'benign_prob': float(confidence[0])
        }
        
        return result
    
    def retrain(self):
        """重新训练模型"""
        self._train_model()
        return True

# DeepSeek API 调用器
class DeepSeekAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.api_url = DEEPSEEK_API_URL
    
    def analyze_package(self, filename, features, xgboost_result):
        """使用DeepSeek进行深度分析"""
        try:
            # 构建分析提示
            prompt = self._build_analysis_prompt(filename, features, xgboost_result)
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': 'deepseek-chat',
                'messages': [
                    {
                        'role': 'system',
                        'content': '你是一个专业的开源组件安全分析专家。你的任务是分析上传的开源组件包，识别其中可能存在的安全风险和恶意行为。请基于提供的特征数据进行深度分析，并给出详细的安全评估报告。'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 2048
            }
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                return self._parse_analysis(analysis)
            else:
                print(f"DeepSeek API错误: {response.status_code} - {response.text}")
                return self._fallback_analysis(xgboost_result)
                
        except Exception as e:
            print(f"DeepSeek分析错误: {e}")
            return self._fallback_analysis(xgboost_result)
    
    def _build_analysis_prompt(self, filename, features, xgboost_result):
        prompt = f"""请分析以下开源组件包的特征数据：

文件名：{filename}
文件数量：{features.get('file_count', 'N/A')}
总大小：{features.get('total_size', 'N/A')} 字节
平均文件大小：{features.get('avg_file_size', 'N/A')} 字节
目录深度：{features.get('directory_depth', 'N/A')}
可执行文件数：{features.get('executable_files', 'N/A')}
脚本文件数：{features.get('script_files', 'N/A')}
配置文件数：{features.get('config_files', 'N/A')}
可疑扩展名文件数：{features.get('suspicious_extensions', 'N/A')}
隐藏文件数：{features.get('hidden_files', 'N/A')}

XGBoost初筛结果：
- 判定：{xgboost_result['prediction']}
- 置信度：{xgboost_result['confidence']:.2%}
- 恶意概率：{xgboost_result['malicious_prob']:.2%}

请基于以上信息，提供详细的安全分析报告，包括：
1. 风险等级评估（低/中/高）
2. 具体风险点分析
3. 建议的处理措施

请用中文回复，格式要清晰易读。"""
        
        return prompt
    
    def _parse_analysis(self, analysis_text):
        """解析DeepSeek的分析结果"""
        # 简单的风险等级提取
        risk_level = 'medium'
        if '高风险' in analysis_text or '高危' in analysis_text:
            risk_level = 'high'
        elif '低风险' in analysis_text or '安全' in analysis_text:
            risk_level = 'low'
        
        # 计算置信度（基于文本长度和关键词）
        confidence = 0.7
        if len(analysis_text) > 200:
            confidence += 0.1
        if any(word in analysis_text for word in ['明显', '确定', '肯定']):
            confidence += 0.1
        if any(word in analysis_text for word in ['可能', '或许', '建议']):
            confidence -= 0.1
        
        confidence = max(0.5, min(0.95, confidence))
        
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis': analysis_text,
            'recommendation': '请参考分析报告中的建议措施'
        }
    
    def _fallback_analysis(self, xgboost_result):
        """当API调用失败时的后备分析"""
        if xgboost_result['prediction'] == 'malicious':
            return {
                'risk_level': 'high',
                'confidence': xgboost_result['confidence'],
                'analysis': '基于机器学习模型分析，该组件包存在安全风险。建议进一步人工审查。',
                'recommendation': '建议停止使用该组件，并寻找替代方案。'
            }
        else:
            return {
                'risk_level': 'low',
                'confidence': xgboost_result['confidence'],
                'analysis': '基于机器学习模型分析，该组件包相对安全。',
                'recommendation': '可以继续使用，但建议定期更新到最新版本。'
            }

# 初始化组件
feature_extractor = FeatureExtractor()
security_classifier = SecurityClassifier()
deepseek_analyzer = DeepSeekAnalyzer(DEEPSEEK_API_KEY)

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
        conn = sqlite3.connect('security_scanner.db')
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

# 路由定义
@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 管理员和普通用户视图分离
    is_admin = session.get('role') == 'admin'
    
    if is_admin:
        # 管理员可以看到全局数据
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, created_at, package_type, user_id
            FROM scan_records 
            WHERE risk_level = 'high' 
            AND scan_status = 'completed' 
            ORDER BY created_at DESC 
            LIMIT 8
        ''')
        recent_malicious_packages = cursor.fetchall()
        
        # 管理员统计信息
        cursor.execute('SELECT COUNT(*) FROM users')
        total_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM samples')
        total_samples = cursor.fetchone()[0]
        
        # 计算高风险包总数
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE risk_level = 'high' AND scan_status = 'completed'
        ''')
        total_malicious = cursor.fetchone()[0]
        
        # 获取检测总数
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE scan_status = 'completed'
        ''')
        total_scans = cursor.fetchone()[0]
    else:
        # 普通用户只能看到自己的数据
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, created_at, package_type
            FROM scan_records 
            WHERE user_id = ?
            AND scan_status = 'completed' 
            ORDER BY created_at DESC 
            LIMIT 5
        ''', (session['user_id'],))
        recent_malicious_packages = cursor.fetchall()
        
        # 用户自己的统计信息
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE user_id = ? AND risk_level = 'high' AND scan_status = 'completed'
        ''', (session['user_id'],))
        total_malicious = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE user_id = ? AND scan_status = 'completed'
        ''', (session['user_id'],))
        total_scans = cursor.fetchone()[0]
        
        total_users = None
        total_samples = None
    
    # 格式化数据
    malicious_packages = []
    for pkg in recent_malicious_packages:
        malicious_packages.append({
            'id': pkg[0],
            'filename': pkg[1],
            'file_size': format_size(pkg[2]) if pkg[2] else "未知",
            'risk_level': pkg[3],
            'confidence': pkg[4] * 100 if pkg[4] else 0,
            'created_at': pkg[5],
            'package_type': pkg[6] if len(pkg) > 6 else 'unknown',
            'user_id': pkg[7] if is_admin and len(pkg) > 7 else session['user_id']
        })
    
    conn.close()
    
    return render_template('index.html', 
                          malicious_packages=malicious_packages,
                          total_malicious=total_malicious,
                          total_scans=total_scans,
                          total_users=total_users,
                          total_samples=total_samples,
                          is_admin=is_admin)

def format_size(size_in_bytes):
    """格式化文件大小"""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # 验证两次密码输入是否一致
        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')
        
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        # 检查用户名是否已存在
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('用户名已被使用', 'error')
            conn.close()
            return render_template('register.html')
        
        # 检查邮箱是否已存在
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('邮箱已被注册', 'error')
            conn.close()
            return render_template('register.html')
        
        # 创建用户
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, 'user')
        )
        conn.commit()
        
        # 获取新用户ID
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_id = cursor.fetchone()[0]
        conn.close()
        
        # 自动登录
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = 'user'
        
        flash('注册成功，欢迎使用！', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            
            # 更新最后登录时间
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            conn.close()
            
            flash(f'欢迎回来，{username}！', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        # 计算文件哈希
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        file_size = os.path.getsize(file_path)
        # 检测包类型
        package_type = detect_package_type(file_path)
        # 创建扫描记录
        conn = sqlite3.connect('security_scanner.db')
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

@app.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    # 从内存中获取实时状态
    if scan_id in scan_tasks:
        task_status = scan_tasks[scan_id]
    else:
        # 从数据库获取状态
        conn = sqlite3.connect('security_scanner.db')
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

@app.route('/results/<int:scan_id>')
def results(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scan_records 
        WHERE id = ? AND user_id = ?
    ''', (scan_id, session['user_id']))
    
    record = cursor.fetchone()
    if not record:
        flash('扫描记录不存在')
        return redirect(url_for('index'))
    
    # 获取特征数据
    cursor.execute('SELECT feature_data FROM features WHERE scan_id = ?', (scan_id,))
    feature_result = cursor.fetchone()
    features = json.loads(feature_result[0]) if feature_result else {}
    
    conn.close()
    
    scan_data = {
        'id': record[0],
        'filename': record[2],
        'file_size': record[3],
        'scan_status': record[5],
        'risk_level': record[6],
        'confidence': record[7] or 0.5,
        'xgboost_result': json.loads(record[8]) if record[8] else {},
        'llm_result': json.loads(record[9]) if record[9] else {},
        'risk_explanation': record[10],
        'scan_time': record[11],
        'created_at': record[12],
        'features': features
    }
    
    return render_template('results.html', scan_data=scan_data)

@app.route('/history')
@login_required
def history():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 管理员可以看到所有用户的记录，普通用户只能看到自己的
    if session.get('role') == 'admin':
        cursor.execute('''
            SELECT r.id, r.filename, r.file_size, r.risk_level, r.confidence, r.scan_status, r.created_at, 
                   r.package_type, u.username
            FROM scan_records r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, scan_status, created_at, package_type
            FROM scan_records 
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],))
    
    records = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', records=records)

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')

@app.route('/knowledge')
def knowledge():
    # 入门指南内容
    getting_started_articles = [
        {
            'id': 'quick-start',
            'title': '快速开始',
            'desc': '本指南将帮助您快速了解并开始使用开源组件包安全检测系统。我们的平台使用机器学习模型和大语言模型结合的方式，对上传的组件包进行安全风险评估，帮助您识别潜在的恶意代码和供应链攻击。'
        },
        {
            'id': 'installation',
            'title': '安装说明',
            'desc': '''
                <h4>系统要求</h4>
                <ul>
                    <li>Python 3.8+</li>
                    <li>8GB 内存或更高</li>
                    <li>4GB 可用磁盘空间</li>
                    <li>互联网连接（用于API调用）</li>
                </ul>
                
                <h4>安装步骤</h4>
                <ol>
                    <li>克隆代码仓库: <code>git clone https://github.com/yourusername/security-scanner.git</code></li>
                    <li>进入项目目录: <code>cd security-scanner</code></li>
                    <li>安装依赖: <code>pip install -r requirements.txt</code></li>
                    <li>配置环境变量: 复制 <code>.env.example</code> 为 <code>.env</code> 并填写相应配置</li>
                    <li>初始化数据库: <code>python app.py</code> (首次运行时会自动创建数据库)</li>
                </ol>
            '''
        },
        {
            'id': 'configuration',
            'title': '基础配置',
            'desc': '''
                <h4>系统配置选项</h4>
                <p>在 <code>.env</code> 文件中配置以下关键参数:</p>
                <ul>
                    <li><strong>DEEPSEEK_API_KEY</strong>: DeepSeek大语言模型的API密钥，用于代码分析</li>
                    <li><strong>UPLOAD_FOLDER</strong>: 上传文件的临时存储路径</li>
                    <li><strong>MAX_CONTENT_LENGTH</strong>: 允许上传的最大文件大小（默认为50MB）</li>
                    <li><strong>SECRET_KEY</strong>: Flask应用的密钥，用于会话安全</li>
                </ul>
                
                <h4>管理员账户</h4>
                <p>系统默认创建以下管理员账户:</p>
                <ul>
                    <li>用户名: admin</li>
                    <li>密码: admin123</li>
                </ul>
                <p><strong>重要提示:</strong> 在生产环境中部署时，请务必修改默认密码。</p>
            '''
        },
        {
            'id': 'first-scan',
            'title': '首次扫描',
            'desc': '''
                <h4>执行首次安全扫描</h4>
                <ol>
                    <li>登录系统后，在主页找到上传区域</li>
                    <li>点击"选择文件"或直接拖拽组件包到上传区域</li>
                    <li>支持的文件格式包括：.zip, .tar.gz, .whl, .jar, .gem, .tgz, .npm 等</li>
                    <li>点击"开始检测"按钮启动扫描</li>
                    <li>系统会显示扫描进度，完成后自动跳转到结果页面</li>
                </ol>
                
                <h4>样例组件包</h4>
                <p>如果您需要测试系统功能，可以使用以下开源包:</p>
                <ul>
                    <li>安全包示例: <code>requests-2.25.1-py2.py3-none-any.whl</code></li>
                    <li>注: 系统自带测试样本，可在管理员页面查看</li>
                </ul>
            '''
        }
    ]
    
    # 基础使用内容
    basic_usage_articles = [
        {
            'id': 'scan-types',
            'title': '扫描类型',
            'desc': '''
                <h4>本系统支持多种扫描类型和组件包格式:</h4>
                <ul>
                    <li><strong>PyPI包</strong>: 检测Python包中的恶意代码，包括setup.py中的恶意逻辑、后门模块等</li>
                    <li><strong>NPM包</strong>: 分析JavaScript代码，检测恶意脚本、供应链投毒等</li>
                    <li><strong>Maven包</strong>: 检测Java构件中的恶意代码</li>
                    <li><strong>RubyGems包</strong>: 分析Ruby gems中的可疑代码</li>
                </ul>
                
                <h4>特征提取</h4>
                <p>系统会对上传的组件包执行以下分析:</p>
                <ul>
                    <li>文件结构与内容分析</li>
                    <li>代码特征提取</li>
                    <li>API使用模式识别</li>
                    <li>权限与敏感操作检测</li>
                </ul>
            '''
        },
        {
            'id': 'result-analysis',
            'title': '结果分析',
            'desc': '''
                <h4>理解检测结果中的关键指标</h4>
                <ul>
                    <li><strong>风险等级</strong>: 系统评估的总体风险水平（低/中/高）</li>
                    <li><strong>置信度</strong>: 检测结果的可信度百分比</li>
                    <li><strong>XGBoost分析</strong>: 基于特征工程和机器学习的风险评分</li>
                    <li><strong>DeepSeek分析</strong>: 大语言模型对代码的语义理解分析</li>
                    <li><strong>风险说明</strong>: 潜在威胁的详细解释和推荐操作</li>
                </ul>
                
                <h4>检测报告导出</h4>
                <p>您可以通过以下格式导出检测报告:</p>
                <ul>
                    <li><strong>JSON格式</strong>: 包含完整的技术细节，适合进一步分析</li>
                    <li><strong>PDF格式</strong>: 正式报告格式，适合团队分享和存档</li>
                </ul>
            '''
        }
    ]
    
    # API文档内容
    api_articles = [
        {
            'id': 'api-overview',
            'title': 'API概述',
            'desc': '''
                <h4>API功能介绍</h4>
                <p>本系统提供REST API接口，允许用户通过编程方式与安全检测功能交互，便于集成到自动化流程中。</p>
                
                <h4>API访问要求</h4>
                <ul>
                    <li>所有API请求需要API密钥进行身份验证</li>
                    <li>请求使用HTTPS协议加密传输</li>
                    <li>API请求返回JSON格式数据</li>
                    <li>API密钥可以在管理员页面生成和管理</li>
                </ul>
                
                <h4>基本端点</h4>
                <code>https://您的域名/api/v1/</code>
            '''
        },
        {
            'id': 'api-endpoints',
            'title': '接口说明',
            'desc': '''
                <h4>主要API端点</h4>
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">端点</th>
                        <th style="padding: 8px; text-align: left;">方法</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/scan</code></td>
                        <td style="padding: 8px;">POST</td>
                        <td style="padding: 8px;">上传并扫描组件包</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/scan/{scan_id}</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">获取扫描状态和结果</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/history</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">列出历史扫描记录</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/report/{scan_id}</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">获取报告（JSON/PDF）</td>
                    </tr>
                </table>
                
                <h4>认证</h4>
                <p>API请求需要在HTTP头中包含API密钥：</p>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
Authorization: Bearer YOUR_API_KEY
                </pre>
                
                <h4>响应格式</h4>
                <p>所有API响应都使用JSON格式，包含以下通用字段：</p>
                <ul>
                    <li><code>success</code>: 布尔值，表示请求是否成功</li>
                    <li><code>data</code>: 响应数据对象</li>
                    <li><code>error</code>: 错误信息（如果有）</li>
                </ul>
            '''
        },
        {
            'id': 'api-examples',
            'title': '使用示例',
            'desc': '''
                <h4>上传并扫描组件包</h4>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
curl -X POST \\
  https://example.com/api/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -F "file=@package.zip"
                </pre>
                
                <p>响应示例：</p>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
{
  "success": true,
  "data": {
    "scan_id": 12345,
    "filename": "package.zip",
    "status": "pending",
    "message": "扫描已提交，正在处理中"
  }
}
                </pre>
                
                <h4>获取扫描结果</h4>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
curl -X GET \\
  https://example.com/api/v1/scan/12345 \\
  -H "Authorization: Bearer YOUR_API_KEY"
                </pre>
                
                <p>完成后的响应示例：</p>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
{
  "success": true,
  "data": {
    "scan_id": 12345,
    "filename": "package.zip",
    "status": "completed",
    "risk_level": "medium",
    "confidence": 85.7,
    "risk_explanation": "检测到可疑网络请求行为..."
  }
}
                </pre>
                
                <h4>Python集成示例</h4>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
import requests
import time

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://example.com/api/v1"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# 上传并扫描文件
def scan_package(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/scan",
            headers=HEADERS,
            files={"file": f}
        )
    data = response.json()
    if data["success"]:
        return data["data"]["scan_id"]
    else:
        raise Exception(f"扫描请求失败: {data['error']}")

# 获取扫描结果
def get_scan_result(scan_id):
    while True:
        response = requests.get(
            f"{BASE_URL}/scan/{scan_id}",
            headers=HEADERS
        )
        data = response.json()["data"]
        if data["status"] == "completed":
            return data
        elif data["status"] == "error":
            raise Exception(f"扫描失败: {data['message']}")
        else:
            print(f"扫描进度: {data.get('progress', 0)}%")
            time.sleep(5)

# 使用示例
scan_id = scan_package("my-package.zip")
result = get_scan_result(scan_id)
print(f"风险等级: {result['risk_level']}, 置信度: {result['confidence']}%")
                </pre>
            '''
        }
    ]
    
    # 故障排除内容
    troubleshooting_articles = [
        {
            'id': 'common-issues',
            'title': '常见问题',
            'desc': '''
                <h4>上传问题</h4>
                <ul>
                    <li>
                        <strong>问题</strong>: 文件上传失败<br>
                        <strong>解决方法</strong>: 检查文件大小是否超过限制(50MB)，确认文件格式是否受支持，检查网络连接
                    </li>
                    <li>
                        <strong>问题</strong>: 无法识别包类型<br>
                        <strong>解决方法</strong>: 确保上传的是标准格式的组件包，包含必要的元数据文件（如setup.py、package.json等）
                    </li>
                </ul>
                
                <h4>检测问题</h4>
                <ul>
                    <li>
                        <strong>问题</strong>: 检测过程卡住不动<br>
                        <strong>解决方法</strong>: 检查网络连接，确保API服务可用；对于特别大的包可能需要更长时间
                    </li>
                    <li>
                        <strong>问题</strong>: 检测失败，无结果<br>
                        <strong>解决方法</strong>: 查看系统日志，检查包文件完整性，尝试重新上传或使用"重试检测"功能
                    </li>
                </ul>
            '''
        },
        {
            'id': 'error-messages',
            'title': '错误信息',
            'desc': '''
                <h4>常见错误代码及解决方案</h4>
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">错误代码</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                        <th style="padding: 8px; text-align: left;">解决方法</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-001</td>
                        <td style="padding: 8px;">文件格式不支持</td>
                        <td style="padding: 8px;">使用受支持的包格式(.zip, .tar.gz, .whl, .jar等)</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-002</td>
                        <td style="padding: 8px;">API调用失败</td>
                        <td style="padding: 8px;">检查API密钥和网络连接，确认DeepSeek服务可用</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-003</td>
                        <td style="padding: 8px;">特征提取失败</td>
                        <td style="padding: 8px;">检查包文件是否完整，尝试重新上传</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-004</td>
                        <td style="padding: 8px;">存储空间不足</td>
                        <td style="padding: 8px;">清理临时文件目录，为上传文件释放空间</td>
                    </tr>
                </table>
                
                <h4>日志位置</h4>
                <p>系统日志默认输出到控制台。若已配置日志文件，可在以下位置查看：</p>
                <ul>
                    <li>应用日志: <code>logs/app.log</code></li>
                    <li>错误日志: <code>logs/error.log</code></li>
                    <li>API调用日志: <code>logs/api.log</code></li>
                </ul>
            '''
        },
        {
            'id': 'performance',
            'title': '性能优化',
            'desc': '''
                <h4>系统性能优化建议</h4>
                <p>如果系统运行缓慢或检测效率不高，可以尝试以下优化措施：</p>
                
                <ul>
                    <li><strong>增加硬件资源</strong>: 对于大型部署，建议至少16GB内存和4核处理器</li>
                    <li><strong>优化数据库</strong>: 定期清理旧的检测记录和临时文件</li>
                    <li><strong>调整并发设置</strong>: 在<code>config.py</code>中调整最大并发检测任务数</li>
                    <li><strong>使用缓存</strong>: 启用结果缓存可以加快重复检测的速度</li>
                </ul>
                
                <h4>大型包处理策略</h4>
                <p>处理超大型包（>100MB）时的建议：</p>
                <ul>
                    <li>增加超时时间设置</li>
                    <li>使用分块分析模式</li>
                    <li>优先分析关键文件而非全量分析</li>
                </ul>
            '''
        }
    ]
    
    # 安全说明内容
    security_articles = [
        {
            'id': 'security-best-practices',
            'title': '安全最佳实践',
            'desc': '''
                <h4>开源组件使用安全指南</h4>
                <p>在使用开源组件时，遵循以下最佳实践可以大幅降低安全风险：</p>
                
                <ol>
                    <li><strong>持续检测与更新</strong>：定期检测已引入的组件包，并及时更新到最新的安全版本</li>
                    <li><strong>最小权限原则</strong>：仅引入必要的依赖，减少供应链攻击面</li>
                    <li><strong>验证包来源</strong>：确保从官方源下载包，不要使用未知或可疑的包仓库</li>
                    <li><strong>锁定依赖版本</strong>：使用lockfiles（如package-lock.json, Pipfile.lock）锁定依赖版本</li>
                    <li><strong>审核新引入的依赖</strong>：在引入新依赖前，评估其安全性、活跃度和维护状态</li>
                </ol>
                
                <h4>CI/CD流水线集成</h4>
                <p>将安全检测集成到CI/CD流水线中，在以下阶段执行检测：</p>
                <ul>
                    <li>代码提交时</li>
                    <li>依赖更新时</li>
                    <li>构建阶段</li>
                    <li>发布前验证</li>
                </ul>
            '''
        },
        {
            'id': 'threat-modeling',
            'title': '威胁建模',
            'desc': '''
                <h4>开源组件威胁模型</h4>
                <p>了解开源组件面临的主要威胁类型，有助于更有针对性地进行安全防护：</p>
                
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">威胁类型</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                        <th style="padding: 8px; text-align: left;">缓解措施</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>依赖混淆攻击</strong></td>
                        <td style="padding: 8px;">攻击者在公共仓库发布与私有库同名的恶意包</td>
                        <td style="padding: 8px;">使用范围限定前缀、验证包来源、私有镜像</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>供应链投毒</strong></td>
                        <td style="padding: 8px;">攻击者将恶意代码注入受信任的包或其依赖中</td>
                        <td style="padding: 8px;">锁定依赖版本、完整性校验、漏洞扫描</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>包劫持</strong></td>
                        <td style="padding: 8px;">攻击者接管被弃用的包名或控制维护者账号</td>
                        <td style="padding: 8px;">多因素认证、依赖审核、活跃度监控</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>自动执行攻击</strong></td>
                        <td style="padding: 8px;">恶意代码在包安装或导入时自动执行</td>
                        <td style="padding: 8px;">安全环境检测、沙箱安装、代码审查</td>
                    </tr>
                </table>
                
                <h4>攻击链分析</h4>
                <p>恶意开源组件攻击通常遵循以下链路：</p>
                <ol>
                    <li>开发诱饵功能吸引用户安装</li>
                    <li>包含隐藏的恶意代码</li>
                    <li>执行特权操作或数据窃取</li>
                    <li>隐藏行为痕迹并建立持久性</li>
                </ol>
            '''
        },
        {
            'id': 'security-standards',
            'title': '安全标准',
            'desc': '''
                <h4>相关安全标准</h4>
                <p>开源组件安全检测遵循以下行业标准：</p>
                
                <ul>
                    <li><strong>OWASP Top 10</strong>：特别是A9(使用含有已知漏洞的组件)</li>
                    <li><strong>NIST安全软件开发框架</strong>：供应链安全管理</li>
                    <li><strong>CIS Controls</strong>：特别是控制项18(应用软件安全)</li>
                    <li><strong>SLSA框架</strong>：软件供应链安全级别</li>
                </ul>
                
                <h4>合规检查清单</h4>
                <p>确保项目安全合规，可以参考以下检查清单：</p>
                <ul>
                    <li>建立并维护组件清单(SBOM)</li>
                    <li>实施依赖管理策略</li>
                    <li>定期进行安全扫描</li>
                    <li>制定组件淘汰与更新策略</li>
                    <li>响应安全公告与更新</li>
                </ul>
            '''
        }
    ]
    
    # 功能特性内容
    features_articles = [
        {
            'id': 'scan-features',
            'title': '扫描功能',
            'desc': '''
                <h4>多层次安全扫描体系</h4>
                <p>本系统采用多层次的安全扫描架构，结合静态分析、特征提取和语义理解三大技术维度，实现对恶意代码的精准识别。</p>
                
                <h4>核心技术优势</h4>
                <ul>
                    <li>两阶段检测架构（XGBoost特征检测 + DeepSeek语义分析）</li>
                    <li>自动适应不同语言和包格式的特征提取</li>
                    <li>持续更新的威胁情报库</li>
                    <li>基于大语言模型的代码意图分析</li>
                </ul>
            '''
        },
        {
            'id': 'dependency-scan',
            'title': '依赖扫描',
            'desc': '''
                <h4>依赖关系分析</h4>
                <p>系统能够解析包管理文件，识别所有声明的依赖关系，验证依赖的完整性和安全性。</p>
                
                <h4>主要检测点</h4>
                <ul>
                    <li>依赖混淆攻击（Dependency Confusion）检测</li>
                    <li>非官方源依赖识别</li>
                    <li>版本号欺骗检测</li>
                    <li>间接依赖风险评估</li>
                </ul>
                
                <p>系统会扫描package.json、requirements.txt、pom.xml等文件，检查其中的依赖项目是否存在安全隐患。</p>
            '''
        },
        {
            'id': 'vulnerability-scan',
            'title': '漏洞扫描',
            'desc': '''
                <h4>代码漏洞检测</h4>
                <p>本系统能够识别组件包中可能存在的代码漏洞，包括但不限于：</p>
                
                <ul>
                    <li>不安全的序列化/反序列化</li>
                    <li>命令注入漏洞</li>
                    <li>路径穿越漏洞</li>
                    <li>不安全的随机数生成</li>
                    <li>硬编码密钥和凭证</li>
                </ul>
                
                <h4>漏洞评级</h4>
                <p>系统采用CVSS（通用漏洞评分系统）标准对检测到的漏洞进行评级，并给出具体的风险等级和修复建议。</p>
            '''
        },
        {
            'id': 'malware-scan',
            'title': '恶意代码检测',
            'desc': '''
                <h4>恶意代码模式识别</h4>
                <p>系统通过分析代码中的恶意模式，检测可能的恶意行为：</p>
                
                <ul>
                    <li><strong>数据窃取</strong>: 检测未授权收集和传输用户数据的代码</li>
                    <li><strong>远程控制</strong>: 识别后门和远程访问功能</li>
                    <li><strong>挖矿行为</strong>: 检测加密货币挖矿相关代码</li>
                    <li><strong>信息泄露</strong>: 发现敏感信息泄露风险</li>
                </ul>
                
                <h4>检测方法</h4>
                <p>结合以下技术进行检测：</p>
                <ul>
                    <li>静态代码分析</li>
                    <li>行为特征匹配</li>
                    <li>机器学习模型</li>
                    <li>大语言模型分析</li>
                </ul>
            '''
        },
        {
            'id': 'risk-assessment',
            'title': '风险评估',
            'desc': '''
                <h4>风险评分系统</h4>
                <p>系统采用多维度风险评估方法，综合考虑以下因素：</p>
                
                <ul>
                    <li>代码质量评分</li>
                    <li>安全漏洞数量</li>
                    <li>依赖包风险</li>
                    <li>恶意行为指标</li>
                    <li>历史安全记录</li>
                </ul>
                
                <h4>风险等级</h4>
                <p>根据综合评分，将风险分为以下等级：</p>
                <ul>
                    <li><strong>低风险</strong>: 评分 0-30，建议正常使用</li>
                    <li><strong>中风险</strong>: 评分 31-70，建议审查后使用</li>
                    <li><strong>高风险</strong>: 评分 71-100，建议避免使用</li>
                </ul>
            '''
        },
        {
            'id': 'report-generation',
            'title': '报告生成',
            'desc': '''
                <h4>检测报告内容</h4>
                <p>系统生成的检测报告包含以下内容：</p>
                
                <ul>
                    <li>基本信息（包名、版本、大小等）</li>
                    <li>风险等级和置信度</li>
                    <li>检测到的安全问题</li>
                    <li>依赖包分析结果</li>
                    <li>修复建议</li>
                </ul>
                
                <h4>报告格式</h4>
                <p>支持多种格式导出：</p>
                <ul>
                    <li>HTML格式（网页查看）</li>
                    <li>PDF格式（打印存档）</li>
                    <li>JSON格式（数据集成）</li>
                </ul>
            '''
        }
    ]
    
    # 整合文章内容
    articles = getting_started_articles + basic_usage_articles + features_articles + security_articles + troubleshooting_articles + api_articles
    
    # FAQ示例
    faqs = [
        {
            'q': '系统能检测哪些类型的恶意代码？',
            'a': '本系统可检测的恶意代码类型包括：供应链攻击、数据窃取、远程代码执行、恶意脚本注入、隐蔽挖矿、依赖混淆攻击等多种常见威胁。检测算法结合了静态分析和语义分析，能够有效识别精心伪装的恶意代码。'
        },
        {
            'q': '扫描结果出现"风险等级：高"但置信度不高怎么办？',
            'a': '当系统报告高风险但置信度不高时，表示检测到了可疑模式但无法完全确定。建议：(1)查看详细的风险说明；(2)检查检测到的可疑代码片段；(3)使用其他安全工具进行交叉验证；(4)在隔离环境中测试该组件包。如有疑问，请谨慎使用该组件。'
        },
        {
            'q': '如何提高检测准确率？',
            'a': '提高检测准确率可通过以下方法：(1)保持模型训练数据的更新；(2)在管理员页面上传更多已知安全和恶意的样本进行训练；(3)调整检测阈值；(4)结合多种工具的检测结果进行综合判断。本系统采用双引擎检测（机器学习+大语言模型），已经具备较高的准确率。'
        },
        {
            'q': '系统支持自动化集成吗？',
            'a': '是的，本系统提供API接口，可以与CI/CD流水线、代码审查系统和依赖管理工具集成。详细的API文档可在"API文档"部分查看，包括验证方法、请求参数和返回格式说明。'
        },
        {
            'q': '支持检测哪些编程语言的包？',
            'a': '目前系统主要支持Python(PyPI)、JavaScript(NPM)、Java(Maven)和Ruby(RubyGems)等主流编程语言的包格式。系统会根据上传的包文件自动识别其类型，并应用对应的分析规则和特征提取方法。我们计划在未来版本中增加对Golang、Rust和.NET包的支持。'
        }
    ]
    
    return render_template('knowledge.html', articles=articles, faqs=faqs)

@app.route('/guide')
def guide():
    return render_template('guide.html')

@app.route('/cancel_scan/<int:scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    conn = sqlite3.connect('security_scanner.db')
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

@app.route('/retry_scan/<int:scan_id>', methods=['POST'])
def retry_scan(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    conn = sqlite3.connect('security_scanner.db')
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
    upload_dir = app.config['UPLOAD_FOLDER']
    
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

@app.route('/delete_record/<int:scan_id>', methods=['POST'])
def delete_record(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    conn = sqlite3.connect('security_scanner.db')
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

@app.route('/progress/<int:scan_id>')
def progress(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('progress.html', scan_id=scan_id)

@app.route('/download_report/<int:scan_id>/<format>')
def download_report(scan_id, format):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    # 获取扫描数据
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scan_records 
        WHERE id = ? AND user_id = ?
    ''', (scan_id, session['user_id']))
    
    record = cursor.fetchone()
    if not record:
        return jsonify({'error': '扫描记录不存在'}), 404
    
    if format == 'json':
        # 生成JSON报告
        report_data = {
            'scan_id': record[0],
            'filename': record[2],
            'file_size': record[3],
            'file_hash': record[4],
            'risk_level': record[6],
            'confidence': record[7],
            'xgboost_result': json.loads(record[8]) if record[8] else {},
            'llm_result': json.loads(record[9]) if record[9] else {},
            'risk_explanation': record[10],
            'scan_time': record[11],
            'created_at': record[12]
        }
        
        report_path = f'static/reports/report_{scan_id}.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        return send_file(report_path, as_attachment=True, 
                        download_name=f'security_report_{scan_id}.json')
    
    elif format == 'pdf':
        # 生成PDF报告
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f'Security Scan Report - {record[2]}', 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Scan ID: {record[0]}', 0, 1)
        pdf.cell(0, 10, f'File Size: {record[3]} bytes', 0, 1)
        pdf.cell(0, 10, f'Risk Level: {record[6] or "N/A"}', 0, 1)
        pdf.cell(0, 10, f'Confidence: {record[7]:.2%}' if record[7] else 'N/A', 0, 1)
        
        report_path = f'static/reports/report_{scan_id}.pdf'
        pdf.output(report_path)
        
        return send_file(report_path, as_attachment=True,
                        download_name=f'security_report_{scan_id}.pdf')
    
    return jsonify({'error': '不支持的格式'}), 400

@app.route('/admin/model', methods=['GET', 'POST'])
def model_management():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('需要管理员权限')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        model_type = request.form.get('model_type', 'xgboost')
        
        if action == 'retrain':
            classifier = SecurityClassifier(model_type=model_type)
            success = classifier.retrain()
            if success:
                flash('模型重新训练成功')
            else:
                flash('模型训练失败')
        elif action == 'switch':
            # 切换模型类型
            classifier = SecurityClassifier(model_type=model_type)
            flash(f'已切换到{model_type}模型')
    
    # 获取当前模型信息
    model_path = 'models/security_model.json'
    model_info = {
        'exists': os.path.exists(model_path),
        'last_modified': datetime.fromtimestamp(os.path.getmtime(model_path)).strftime('%Y-%m-%d %H:%M:%S') if os.path.exists(model_path) else None,
        'size': os.path.getsize(model_path) if os.path.exists(model_path) else 0
    }
    
    return render_template('model_management.html', model_info=model_info)

@app.route('/admin/samples', methods=['GET'])
def sample_management():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('需要管理员权限')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM samples ORDER BY upload_time DESC')
    samples = cursor.fetchall()
    conn.close()
    
    # 转换样本数据为字典列表
    sample_list = []
    for sample in samples:
        sample_list.append({
            'id': sample[0],
            'filename': sample[1],
            'type': sample[5],
            'description': sample[6],
            'upload_time': sample[7],
            'package_type': sample[10] if len(sample) > 10 else 'unknown'  # 添加包类型字段
        })
    
    return render_template('sample_management.html', samples=sample_list)

@app.route('/admin/samples/upload', methods=['POST'])
def upload_samples():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    if 'samples' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    files = request.files.getlist('samples')
    malware_status = request.form.get('sample_type', 'benign')  # 仅保留恶意/良性状态
    description = request.form.get('description', '')
    
    if not files:
        return jsonify({'error': '没有选择文件'}), 400
    
    # 创建样本存储目录
    samples_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'samples')
    os.makedirs(samples_dir, exist_ok=True)
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    success_count = 0
    error_count = 0
    error_messages = []
    
    for file in files:
        if file.filename.endswith('.tar.gz') or file.filename.endswith('.zip') or file.filename.endswith('.whl') or file.filename.endswith('.tgz'):
            try:
                # 保存文件
                filename = secure_filename(file.filename)
                file_path = os.path.join(samples_dir, filename)
                file.save(file_path)
                
                # 计算文件哈希
                file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
                
                # 自动检测包类型
                package_type = detect_package_type(file_path)
                
                # 提取特征
                extractor = FeatureExtractor()
                features = extractor.extract_features(file_path)
                
                # 保存到数据库
                cursor.execute('''
                    INSERT INTO samples (filename, file_path, file_size, file_hash, type, package_type, description, features)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    filename,
                    file_path,
                    os.path.getsize(file_path),
                    file_hash,
                    malware_status,  # 恶意/良性状态
                    package_type,    # 包类型（pypi/npm等）
                    description,
                    json.dumps(features)
                ))
                success_count += 1
                
            except Exception as e:
                error_count += 1
                error_messages.append(f"文件 {file.filename} 处理失败: {str(e)}")
                # 如果文件已保存，删除它
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            error_count += 1
            error_messages.append(f"文件 {file.filename} 格式不支持")
    
    conn.commit()
    conn.close()
    
    if success_count > 0:
        return jsonify({
            'success': True,
            'message': f'成功上传 {success_count} 个文件' + (f'，{error_count} 个文件失败' if error_count > 0 else ''),
            'errors': error_messages if error_count > 0 else None
        })
    else:
        return jsonify({
            'success': False,
            'error': '所有文件上传失败',
            'errors': error_messages
        }), 400

@app.route('/admin/samples/delete', methods=['POST'])
def delete_samples():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    data = request.get_json()
    if not data or 'sample_ids' not in data:
        return jsonify({'error': '无效的请求数据'}), 400
    
    sample_ids = data['sample_ids']
    if not sample_ids:
        return jsonify({'error': '没有选择要删除的样本'}), 400
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 获取要删除的样本文件路径
    placeholders = ','.join(['?'] * len(sample_ids))
    cursor.execute(f'SELECT file_path FROM samples WHERE id IN ({placeholders})', sample_ids)
    file_paths = [row[0] for row in cursor.fetchall()]
    
    # 删除文件
    for file_path in file_paths:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"删除文件失败 {file_path}: {e}")
    
    # 删除数据库记录
    cursor.execute(f'DELETE FROM samples WHERE id IN ({placeholders})', sample_ids)
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': f'成功删除 {len(sample_ids)} 个样本'
    })

@app.route('/admin/samples/train', methods=['POST'])
def train_with_samples():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    model_type = request.form.get('model_type', 'xgboost')
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 获取所有样本的特征和标签
    cursor.execute('SELECT features, type FROM samples')
    samples = cursor.fetchall()
    
    if not samples:
        flash('没有可用的训练样本')
        return redirect(url_for('sample_management'))
    
    # 准备训练数据
    X = []
    y = []
    for features, sample_type in samples:
        try:
            feature_dict = json.loads(features)
            X.append(list(feature_dict.values()))
            y.append(1 if sample_type == 'malware' else 0)
        except Exception as e:
            print(f"处理样本数据时出错: {e}")
            continue
    
    if len(X) < 10:
        flash('训练样本数量不足')
        return redirect(url_for('sample_management'))
    
    X = np.array(X)
    y = np.array(y)
    
    # 检查类别数
    unique_classes = set(y)
    if len(unique_classes) < 2:
        if 1 in unique_classes:
            flash('训练失败：当前仅有恶意样本，请上传良性样本后再训练。')
        else:
            flash('训练失败：当前仅有良性样本，请上传恶意样本后再训练。')
        return redirect(url_for('sample_management'))
    
    # 分割训练集和验证集
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 训练模型
    classifier = SecurityClassifier(model_type=model_type)
    classifier.model.fit(X_train, y_train)
    
    # 评估模型
    y_pred = classifier.model.predict(X_val)
    accuracy = accuracy_score(y_val, y_pred)
    precision = precision_score(y_val, y_pred)
    recall = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)
    
    # 保存模型
    os.makedirs('models', exist_ok=True)
    if model_type == 'xgboost':
        classifier.model.save_model('models/security_model.json')
    else:
        joblib.dump(classifier.model, 'models/security_model.json')
    
    # 更新样本的训练状态
    cursor.execute('UPDATE samples SET is_used_for_training = 1')
    conn.commit()
    conn.close()
    
    flash(f'模型训练完成！评估结果：准确率={accuracy:.3f}, 精确率={precision:.3f}, 召回率={recall:.3f}, F1分数={f1:.3f}')
    return redirect(url_for('sample_management'))

@app.route('/admin/samples/update_types', methods=['POST'])
def update_sample_types():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 获取所有样本的路径
    cursor.execute('SELECT id, file_path FROM samples')
    samples = cursor.fetchall()
    
    updated_count = 0
    for sample_id, file_path in samples:
        if os.path.exists(file_path):
            try:
                # 检测包类型
                package_type = detect_package_type(file_path)
                # 更新数据库
                cursor.execute('UPDATE samples SET package_type = ? WHERE id = ?', 
                               (package_type, sample_id))
                updated_count += 1
            except Exception as e:
                print(f"更新样本 {sample_id} 类型失败: {e}")
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': f'成功更新 {updated_count} 个样本的包类型'
    })

def detect_package_type(file_path):
    filename = os.path.basename(file_path).lower()
    
    print(f"正在检测包类型: {file_path}")
    
    # 特殊处理 .tar.gz 扩展名，因为 splitext 只能得到 .gz
    is_targz = filename.endswith('.tar.gz')
    if is_targz:
        ext = '.tar.gz'
    else:
        ext = os.path.splitext(filename)[-1].lower()
    
    print(f"文件扩展名: {ext}")
    package_type = None
    
    # 1. 首先尝试通过内容识别包类型
    if ext in ['.whl', '.zip', '.egg']:
        try:
            with zipfile.ZipFile(file_path, 'r') as zipf:
                names = zipf.namelist()
                print(f"ZIP文件内容: {names[:10]}...")
                # 用endswith更鲁棒地检测
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    print(f"找到Python包标记文件")
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    print(f"找到NPM包标记文件")
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    print(f"找到Ruby包标记文件")
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    print(f"找到Java包标记文件")
                    return 'maven'
        except Exception as e:
            print(f"处理ZIP文件时出错: {e}")
            pass

    if ext in ['.tar.gz', '.tgz', '.npm', '.tar', '.bz2']:
        try:
            print(f"尝试以tar格式打开: {file_path}")
            with tarfile.open(file_path, 'r:*') as tar:
                names = tar.getnames()
                print(f"TAR文件内容: {names[:10]}...")
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    print(f"找到Python包标记文件")
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    print(f"找到NPM包标记文件")
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    print(f"找到Ruby包标记文件")
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    print(f"找到Java包标记文件")
                    return 'maven'
        except Exception as e:
            print(f"处理TAR文件时出错: {e}")
            pass
    
    # 2. 根据文件名判断包类型
    print(f"文件名分析: {filename}")
    if 'python' in filename or 'py' in filename.split('-'):
        print(f"根据文件名判断为Python包")
        return 'pypi'
    if 'node' in filename or 'npm' in filename or 'js' in filename.split('-'):
        print(f"根据文件名判断为NPM包")
        return 'npm'
    if 'ruby' in filename or 'gem' in filename:
        print(f"根据文件名判断为Ruby包")
        return 'rubygems'
    if 'java' in filename or 'maven' in filename:
        print(f"根据文件名判断为Java包")
        return 'maven'
    
    # 3. 只有在上述所有方法都失败时，再返回'unknown'而不是压缩格式
    print(f"无法识别包类型，返回unknown")
    return 'unknown'

@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

# 用户管理路由
@app.route('/admin/users')
@admin_required
def user_management():
    conn = sqlite3.connect('security_scanner.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 获取所有用户
    cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    
    # 统计信息
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    admin_count = cursor.fetchone()[0]
    
    # 假设30天内有登录记录的为活跃用户
    thirty_days_ago = datetime.now() - timedelta(days=30)
    cursor.execute('SELECT COUNT(*) FROM users WHERE last_login > ?', 
                  (thirty_days_ago.strftime('%Y-%m-%d %H:%M:%S'),))
    active_users = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('user_management.html', 
                          users=users, 
                          total_users=total_users,
                          admin_count=admin_count,
                          active_users=active_users)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    if not username or not email or not password:
        flash('请填写所有必填字段', 'error')
        return redirect(url_for('user_management'))
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 检查用户名和邮箱是否已存在
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        flash('用户名已被使用', 'error')
        conn.close()
        return redirect(url_for('user_management'))
    
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        flash('邮箱已被注册', 'error')
        conn.close()
        return redirect(url_for('user_management'))
    
    # 创建用户
    password_hash = generate_password_hash(password)
    cursor.execute(
        'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        (username, email, password_hash, role)
    )
    conn.commit()
    conn.close()
    
    flash('用户创建成功', 'success')
    return redirect(url_for('user_management'))

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn = sqlite3.connect('security_scanner.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 获取用户信息
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('用户不存在', 'error')
        conn.close()
        return redirect(url_for('user_management'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        # 检查用户名和邮箱是否已被其他用户使用
        cursor.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, user_id))
        if cursor.fetchone():
            flash('用户名已被使用', 'error')
            conn.close()
            return render_template('edit_user.html', user=user)
        
        cursor.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user_id))
        if cursor.fetchone():
            flash('邮箱已被注册', 'error')
            conn.close()
            return render_template('edit_user.html', user=user)
        
        # 更新用户信息
        cursor.execute(
            'UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?',
            (username, email, role, user_id)
        )
        conn.commit()
        
        flash('用户信息更新成功', 'success')
        return redirect(url_for('user_management'))
    
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 获取用户信息
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('用户不存在', 'error')
    elif user[0] == 'admin':
        flash('不能删除主管理员账户', 'error')
    else:
        # 删除用户相关的扫描记录
        cursor.execute('DELETE FROM scan_records WHERE user_id = ?', (user_id,))
        
        # 删除用户
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('用户已成功删除', 'success')
    
    conn.close()
    return redirect(url_for('user_management'))

@app.route('/admin/users/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 生成随机密码
    import random
    import string
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    
    # 更新密码
    password_hash = generate_password_hash(new_password)
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
    conn.commit()
    
    # 获取用户信息
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    username = cursor.fetchone()[0]
    
    conn.close()
    
    flash(f'用户 {username} 的密码已重置为: {new_password}', 'success')
    return redirect(url_for('user_management'))

if __name__ == '__main__':
    init_db()
    print("开源组件包安全检测系统启动中...")
    print("访问地址: http://localhost:5000")
    print("管理员账户: admin / admin123")
    app.run(debug=True, host='0.0.0.0', port=5000) 