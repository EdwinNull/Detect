from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import os
import json
import hashlib
import sqlite3
import numpy as np
from datetime import datetime, timedelta
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import joblib
from app.utils import admin_required
from app.services.extractor import FeatureExtractor
from app.services.classifier import SecurityClassifier
from config import Config
from app.utils.helpers import detect_package_type

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@admin_required
def admin():
    return render_template('admin.html')

@admin_bp.route('/model', methods=['GET', 'POST'])
@admin_required
def model_management():
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

@admin_bp.route('/samples', methods=['GET'])
@admin_required
def sample_management():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM samples ORDER BY upload_time DESC')
    samples = cursor.fetchall()
    conn.close()
    
    # 转换样本数据为字典列表
    sample_list = []
    for sample in samples:
        sample_list.append({
            'id': sample['id'],
            'filename': sample['filename'],
            'type': sample['type'],
            'description': sample['description'],
            'upload_time': sample['upload_time'],
            'package_type': sample['package_type'] if 'package_type' in sample.keys() else 'unknown'
        })
    
    return render_template('sample_management.html', samples=sample_list)

@admin_bp.route('/samples/upload', methods=['POST'])
@admin_required
def upload_samples():
    if 'samples' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    files = request.files.getlist('samples')
    malware_status = request.form.get('sample_type', 'benign')  # 仅保留恶意/良性状态
    description = request.form.get('description', '')
    
    if not files:
        return jsonify({'error': '没有选择文件'}), 400
    
    # 创建样本存储目录
    samples_dir = os.path.join(Config.UPLOAD_FOLDER, 'samples')
    os.makedirs(samples_dir, exist_ok=True)
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
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

@admin_bp.route('/samples/delete', methods=['POST'])
@admin_required
def delete_samples():
    data = request.get_json()
    if not data or 'sample_ids' not in data:
        return jsonify({'error': '无效的请求数据'}), 400
    
    sample_ids = data['sample_ids']
    if not sample_ids:
        return jsonify({'error': '没有选择要删除的样本'}), 400
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
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

@admin_bp.route('/samples/train', methods=['POST'])
@admin_required
def train_with_samples():
    model_type = request.form.get('model_type', 'xgboost')
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 获取所有样本的特征和标签
    cursor.execute('SELECT features, type FROM samples')
    samples = cursor.fetchall()
    
    if not samples:
        flash('没有可用的训练样本')
        return redirect(url_for('admin.sample_management'))
    
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
        return redirect(url_for('admin.sample_management'))
    
    X = np.array(X)
    y = np.array(y)
    
    # 检查类别数
    unique_classes = set(y)
    if len(unique_classes) < 2:
        if 1 in unique_classes:
            flash('训练失败：当前仅有恶意样本，请上传良性样本后再训练。')
        else:
            flash('训练失败：当前仅有良性样本，请上传恶意样本后再训练。')
        return redirect(url_for('admin.sample_management'))
    
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
    return redirect(url_for('admin.sample_management'))

@admin_bp.route('/users')
@admin_required
def user_management():
    conn = sqlite3.connect(Config.DATABASE_PATH)
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

@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    if not username or not email or not password:
        flash('请填写所有必填字段', 'error')
        return redirect(url_for('admin.user_management'))
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查用户名和邮箱是否已存在
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        flash('用户名已被使用', 'error')
        conn.close()
        return redirect(url_for('admin.user_management'))
    
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        flash('邮箱已被注册', 'error')
        conn.close()
        return redirect(url_for('admin.user_management'))
    
    # 创建用户
    password_hash = generate_password_hash(password)
    cursor.execute(
        'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        (username, email, password_hash, role)
    )
    conn.commit()
    conn.close()
    
    flash('用户创建成功', 'success')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 获取用户信息
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('用户不存在', 'error')
        conn.close()
        return redirect(url_for('admin.user_management'))
    
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
        return redirect(url_for('admin.user_management'))
    
    conn.close()
    return render_template('edit_user.html', user=user)

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
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
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
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
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/samples/update_types', methods=['POST'])
@admin_required
def update_sample_types():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
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

@admin_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if request.method == 'POST':
        # 更新设置
        for key in request.form:
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                value = request.form[key]
                cursor.execute('''
                    UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE key = ?
                ''', (value, setting_key))
        
        conn.commit()
        flash('设置已成功更新', 'success')
        
    # 获取所有设置
    cursor.execute('SELECT * FROM settings ORDER BY key')
    settings = cursor.fetchall()
    conn.close()
    
    return render_template('settings.html', settings=settings)