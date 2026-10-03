import os

class Config:
    SECRET_KEY = 'your-secret-key-here'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # DeepSeek API配置
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', '')
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_scanner.db')

    # 开发环境配置
    DEBUG = True

# 根据环境变量选择配置
config = Config