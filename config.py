import os
import secrets

class Config:
    # 使用固定的SECRET_KEY进行测试
    SECRET_KEY = 'your-super-secret-key-for-testing-12345'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # DeepSeek API配置
    DEEPSEEK_API_KEY = ""
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    DATABASE_PATH = 'security_scanner.db'
    
    # 配置WTF_CSRF相关选项
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = 'csrf-secret-key-for-testing-67890'

class DevelopmentConfig(Config):
    DEBUG = True
    DATABASE = 'security_scanner.db'

class ProductionConfig(Config):
    DEBUG = False
    DATABASE = 'security_scanner.db'

# 根据环境变量选择配置
config_by_name = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig
}

# 默认使用开发配置
config = config_by_name[os.getenv('FLASK_ENV', 'dev')]