from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # 确保uploads目录存在
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    # 确保models目录存在
    if not os.path.exists('models'):
        os.makedirs('models')
    
    # 确保静态报告目录存在
    if not os.path.exists('static/reports'):
        os.makedirs('static/reports')
    
    print("开源组件包安全检测系统启动中...")
    print("访问地址: http://localhost:5000")
    print("管理员账户: admin / admin123")
    print("开始启动安全检测系统...")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)  # 禁用reloader避免任务重复启动
