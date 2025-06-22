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
    filter_type = request.args.get('type', None)
    order_by = request.args.get('order', 'created_at')
    
    posts = CommunityPost.get_posts(page=page, per_page=10, order_by=order_by, filter_type=filter_type)
    
    return render_template('community/index.html', posts=posts, current_page=page, filter_type=filter_type)

@community_bp.route('/anomalies')
def anomaly_list():
    """异常报告中心"""
    reports = AnomalyReport.get_all()
    return render_template('community/anomaly_list.html', reports=reports)

@community_bp.route('/post/<int:post_id>')
def post_detail(post_id):
    """帖子详情页"""
    post = CommunityPost.get_post_by_id(post_id)
    if not post:
        flash('帖子不存在')
        return redirect(url_for('community.index'))
    
    comments = CommunityComment.get_comments_by_post_id(post_id)
    
    return render_template('community/post_detail.html', post=post, comments=comments)

@community_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    """发布新帖子"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        scan_id = request.form.get('scan_id', type=int)
        
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
            scan_id=scan_id
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