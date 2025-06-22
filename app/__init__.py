from flask import Flask
from config.config import Config
import os

# 全局变量
scan_tasks = {}

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('app/static/reports', exist_ok=True)
    
    # 初始化数据库
    from app.models.db_models import init_db
    init_db()
    
    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.scan import scan_bp
    from app.routes.user import user_bp
    from app.routes.community import community_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(community_bp)
    
    # 添加自定义过滤器
    @app.template_filter('nl2br')
    def nl2br_filter(text):
        """将换行符转换为HTML的<br>标签"""
        if text:
            return text.replace('\n', '<br>')
        return text
    
    return app