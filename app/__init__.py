from flask import Flask
from config import Config
import os
from flask_wtf.csrf import CSRFProtect

# 全局变量
scan_tasks = {}
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # 初始化CSRF保护
    csrf.init_app(app)
    
    # 添加CSRF令牌到模板全局变量
    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)
    
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('static/reports', exist_ok=True)
    
    # 初始化数据库
    from app.models.db_models import init_db
    init_db()
    
    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.scan import scan_bp
    from app.routes.user import user_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(user_bp)
    
    return app