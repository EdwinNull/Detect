import os

class DevelopmentConfig:
    """开发环境配置"""
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'dev-secret-key-change-in-production'
    
class ProductionConfig:
    """生产环境配置"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    
class TestingConfig:
    """测试环境配置"""
    DEBUG = True
    TESTING = True
    SECRET_KEY = 'test-secret-key'

# 配置映射
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
} 