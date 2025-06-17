from app import create_app

app = create_app()

if __name__ == '__main__':
    print("开源组件包安全检测系统启动中...")
    print("访问地址: http://localhost:5000")
    print("管理员账户: admin / admin123")
    app.run(debug=True, host='0.0.0.0', port=5000)
