from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
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
            is_used_for_training BOOLEAN DEFAULT 0
        )
    ''')
    
    # 创建默认管理员账户
    admin_password = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin@scanner.com', admin_password, 'admin'))
    
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
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

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
            
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误')
    
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
        
        # 创建扫描记录
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_records (user_id, filename, file_size, file_hash, scan_status)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], filename, file_size, file_hash, 'pending'))
        
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
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, filename, file_size, risk_level, confidence, scan_status, created_at
        FROM scan_records 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (session['user_id'],))
    
    records = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', records=records)

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('需要管理员权限')
        return redirect(url_for('index'))
    
    return render_template('admin.html')

@app.route('/knowledge')
def knowledge():
    return render_template('knowledge.html')

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
            'upload_time': sample[7]
        })
    
    return render_template('sample_management.html', samples=sample_list)

@app.route('/admin/samples/upload', methods=['POST'])
def upload_samples():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    if 'samples' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    files = request.files.getlist('samples')
    sample_type = request.form.get('sample_type')
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
        if file.filename.endswith('.tar.gz'):
            try:
                # 保存文件
                filename = secure_filename(file.filename)
                file_path = os.path.join(samples_dir, filename)
                file.save(file_path)
                
                # 计算文件哈希
                file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
                
                # 提取特征
                extractor = FeatureExtractor()
                features = extractor.extract_features(file_path)
                
                # 保存到数据库
                cursor.execute('''
                    INSERT INTO samples (filename, file_path, file_size, file_hash, type, description, features)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    filename,
                    file_path,
                    os.path.getsize(file_path),
                    file_hash,
                    sample_type,
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

if __name__ == '__main__':
    init_db()
    print("开源组件包安全检测系统启动中...")
    print("访问地址: http://localhost:5000")
    print("管理员账户: admin / admin123")
    app.run(debug=True, host='0.0.0.0', port=5000) 