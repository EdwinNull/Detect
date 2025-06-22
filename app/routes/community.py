"""
社区功能路由
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.utils import login_required
from app.models.community_models import CommunityPost, CommunityComment, UserPoints
from app.models.db_models import ScanRecord, AnomalyReport
import sqlite3
import json
import os
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

community_bp = Blueprint('community', __name__, url_prefix='/community')

@community_bp.route('/')
def index():
    """社区首页"""
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', None)
    sort = request.args.get('sort', 'recent')
    
    # 排序方式映射
    sort_mapping = {
        'recent': 'created_at',
        'popular': 'views_count',
        'liked': 'likes_count',
        'commented': 'comments_count'
    }
    
    order_by = sort_mapping.get(sort, 'created_at')
    
    # 获取帖子列表
    posts = CommunityPost.get_posts(page=page, per_page=10, order_by=order_by, filter_type=category)
    
    # 获取统计数据
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 获取帖子总数
    cursor.execute('SELECT COUNT(*) as count FROM community_posts')
    posts_count = cursor.fetchone()['count']
    
    # 获取用户总数
    cursor.execute('SELECT COUNT(*) as count FROM users')
    users_count = cursor.fetchone()['count']
    
    # 获取总浏览量
    cursor.execute('SELECT SUM(views_count) as count FROM community_posts')
    result = cursor.fetchone()['count']
    views_count = result if result is not None else 0
    
    # 获取异常报告总数
    cursor.execute('SELECT COUNT(*) as count FROM anomaly_reports')
    anomaly_count = cursor.fetchone()['count']
    
    # 计算总页数
    total_pages = (posts_count + 9) // 10  # 向上取整
    
    # 如果用户已登录，检查用户点赞状态
    user_liked_posts = []
    if 'user_id' in session:
        cursor.execute('''
            SELECT post_id FROM post_likes 
            WHERE user_id = ? AND post_id IN (
                SELECT id FROM community_posts 
                ORDER BY is_pinned DESC, {} DESC 
                LIMIT ? OFFSET ?
            )
        '''.format(order_by), (session['user_id'], 10, (page - 1) * 10))
        user_liked_posts = [row['post_id'] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template(
        'community/index.html', 
        posts=posts, 
        page=page, 
        total_pages=total_pages,
        posts_count=posts_count,
        users_count=users_count,
        views_count=views_count,
        anomaly_count=anomaly_count,
        user_liked_posts=user_liked_posts
    )

@community_bp.route('/anomalies')
def anomaly_list():
    """异常报告中心"""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', None)
    per_page = 10
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 构建查询条件
    query = '''
        SELECT ar.*, u.username, sr.filename, sr.package_type, sr.risk_level
        FROM anomaly_reports ar
        LEFT JOIN users u ON ar.user_id = u.id
        LEFT JOIN scan_records sr ON ar.scan_record_id = sr.id
    '''
    params = []
    
    if status and status != 'all':
        query += ' WHERE ar.status = ?'
        params.append(status)
    
    # 计算总记录数
    count_query = f"SELECT COUNT(*) as count FROM ({query})"
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()['count']
    
    # 添加分页
    query += ' ORDER BY ar.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    reports_data = cursor.fetchall()
    
    # 构建报告对象列表
    reports = []
    for report in reports_data:
        # 创建一个包含用户和扫描记录信息的报告对象
        report_obj = {
            'id': report['id'],
            'reason': report['reason'],
            'description': report['description'],
            'status': report['status'],
            'created_at': datetime.fromisoformat(report['created_at']),
            'scan_record_id': report['scan_record_id'],
            'user': {'username': report['username']},
            'scan_record': {
                'filename': report['filename'],
                'package_type': report['package_type'],
                'risk_level': report['risk_level']
            } if report['filename'] else None
        }
        reports.append(report_obj)
    
    conn.close()
    
    # 计算总页数
    total_pages = (total_count + per_page - 1) // per_page
    
    return render_template(
        'community/anomaly_list.html', 
        reports=reports, 
        page=page, 
        total_pages=total_pages
    )

@community_bp.route('/post/<int:post_id>')
def post_detail(post_id):
    """帖子详情页"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    # 增加浏览次数
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE community_posts SET views_count = views_count + 1 WHERE id = ?',
        (post_id,)
    )
    conn.commit()
    
    comments = CommunityComment.get_comments_by_post_id(post_id)
    
    # 检查当前用户是否点赞过该帖子
    user_liked = False
    if 'user_id' in session:
        cursor.execute(
            'SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?',
            (session['user_id'], post_id)
        )
        user_liked = cursor.fetchone() is not None
    
    conn.close()
    
    return render_template(
        'community/post_detail.html', 
        post=post, 
        comments=comments,
        user_liked=user_liked
    )

@community_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    """发布新帖子"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        scan_id = request.form.get('scan_id', type=int)
        category = request.form.get('category', 'discovery')
        
        if not title or not content:
            flash('标题和内容不能为空')
            return render_template('community/create_post.html')
        
        # 如果关联了扫描记录，获取相关信息
        package_name = None
        package_type = None
        risk_level = None
        confidence = None
        
        if scan_id:
            scan_record = ScanRecord.get_by_id(scan_id)
            if scan_record:
                package_name = scan_record.filename
                package_type = scan_record.package_type
                risk_level = scan_record.risk_level
                confidence = scan_record.confidence
        
        post_id = CommunityPost.create_post(
            user_id=session['user_id'],
            title=title,
            content=content,
            package_name=package_name,
            package_type=package_type,
            risk_level=risk_level,
            confidence=confidence,
            scan_id=scan_id,
            category=category
        )
        
        flash('帖子发布成功！')
        return redirect(url_for('community.post_detail', post_id=post_id))
    
    # GET请求，显示发布表单
    scan_id = request.args.get('scan_id', type=int)
    scan_record = None
    if scan_id:
        scan_record = ScanRecord.get_by_id(scan_id)
    
    return render_template('community/create_post.html', scan_record=scan_record)

@community_bp.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    """添加评论"""
    content = request.form.get('content', '').strip()
    parent_id = request.form.get('parent_id', type=int)
    
    if not content:
        flash('评论内容不能为空')
        return redirect(url_for('community.post_detail', post_id=post_id))
    
    comment_id = CommunityComment.create_comment(
        user_id=session['user_id'],
        post_id=post_id,
        content=content,
        parent_id=parent_id
    )
    
    flash('评论发布成功！')
    return redirect(url_for('community.post_detail', post_id=post_id))

@community_bp.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    """点赞帖子"""
    success = CommunityPost.like_post(session['user_id'], post_id)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': success})
    
    if success:
        flash('点赞成功！')
    else:
        flash('您已经点赞过了')
    
    return redirect(url_for('community.post_detail', post_id=post_id))

@community_bp.route('/post/<int:post_id>/unlike', methods=['POST'])
@login_required
def unlike_post(post_id):
    """取消点赞"""
    success = CommunityPost.unlike_post(session['user_id'], post_id)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': success})
    
    flash('取消点赞成功！')
    return redirect(url_for('community.post_detail', post_id=post_id))

@community_bp.route('/profile')
@login_required
def profile():
    """用户个人资料"""
    user_points = UserPoints.get_user_points(session['user_id'])
    
    # 获取用户的帖子
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM community_posts 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ''', (session['user_id'],))
    
    user_posts = cursor.fetchall()
    conn.close()
    
    return render_template('community/profile.html', user_points=user_points, user_posts=user_posts)

@community_bp.route('/leaderboard')
def leaderboard():
    """积分排行榜"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT up.*, u.username, u.avatar
        FROM user_points up
        LEFT JOIN users u ON up.user_id = u.id
        ORDER BY up.points DESC
        LIMIT 20
    ''')
    
    leaderboard_data = cursor.fetchall()
    conn.close()
    
    return render_template('community/leaderboard.html', leaderboard_data=leaderboard_data)

@community_bp.route('/search')
def search():
    """搜索帖子"""
    keyword = request.args.get('q', '').strip()
    if not keyword:
        return redirect(url_for('community.index'))
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT p.*, u.username, u.avatar
        FROM community_posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.title LIKE ? OR p.content LIKE ? OR p.package_name LIKE ?
        ORDER BY p.created_at DESC
    ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
    
    search_results = cursor.fetchall()
    conn.close()
    
    return render_template('community/search.html', search_results=search_results, keyword=keyword)

@community_bp.route('/report_anomaly/<int:scan_id>')
@login_required
def report_anomaly(scan_id):
    """
    重定向到新的独立上报页面
    """
    return redirect(url_for('user.report_issue', scan_id=scan_id))

@community_bp.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """编辑帖子"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    # 检查权限
    if post['user_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('您没有权限编辑此帖子')
        return redirect(url_for('community.post_detail', post_id=post_id))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category', 'discovery')
        
        if not title or not content:
            flash('标题和内容不能为空')
            return render_template('community/edit_post.html', post=post)
        
        # 更新帖子
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE community_posts 
            SET title = ?, content = ?, category = ?, updated_at = ?
            WHERE id = ?
        ''', (title, content, category, datetime.now(), post_id))
        conn.commit()
        conn.close()
        
        flash('帖子更新成功！')
        return redirect(url_for('community.post_detail', post_id=post_id))
    
    return render_template('community/edit_post.html', post=post)

@community_bp.route('/post/<int:post_id>/delete')
@login_required
def delete_post(post_id):
    """删除帖子"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    # 检查权限
    if post['user_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('您没有权限删除此帖子')
        return redirect(url_for('community.post_detail', post_id=post_id))
    
    # 删除帖子
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 先删除相关评论
    cursor.execute('DELETE FROM community_comments WHERE post_id = ?', (post_id,))
    
    # 删除点赞记录
    cursor.execute('DELETE FROM post_likes WHERE post_id = ?', (post_id,))
    
    # 删除帖子
    cursor.execute('DELETE FROM community_posts WHERE id = ?', (post_id,))
    
    conn.commit()
    conn.close()
    
    flash('帖子已成功删除')
    return redirect(url_for('community.index'))

@community_bp.route('/post/<int:post_id>/report', methods=['GET', 'POST'])
@login_required
def report_post(post_id):
    """举报帖子"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    # 重定向到举报页面
    return render_template('community/report_post.html', post=post)

@community_bp.route('/post/<int:post_id>/submit_report', methods=['POST'])
@login_required
def submit_report(post_id):
    """提交帖子举报"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    reason = request.form.get('reason', '').strip()
    description = request.form.get('description', '').strip()
    
    if not reason or not description:
        flash('请填写举报原因和详细说明')
        return redirect(url_for('community.report_post', post_id=post_id))
    
    # 保存举报信息
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO post_reports (post_id, user_id, reason, description, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (post_id, session['user_id'], reason, description, 'pending', datetime.now()))
    
    conn.commit()
    conn.close()
    
    flash('举报已提交，管理员会尽快处理')
    return redirect(url_for('community.post_detail', post_id=post_id)) 