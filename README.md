# 开源组件包安全检测平台

这是一个用于检测开源组件包安全风险的Web平台，可以识别和防范潜在的恶意开源组件包，保障软件供应链安全。

## 主要功能

- 自动检测上传的组件包是否含有恶意代码或安全漏洞
- 支持多种组件包格式（PyPI、npm、jar等）
- 详细的检测报告和风险评估
- 历史检测记录管理
- 恶意包知识库

## 技术栈

- 后端: Python + Flask
- 前端: HTML, CSS, JavaScript
- 数据库: SQLite
- 机器学习: XGBoost
- 深度分析: LLM技术

## 安装与运行

### 环境要求
- Python 3.8+
- 推荐使用虚拟环境

### 安装步骤

1. 克隆仓库
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. 创建并激活虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

<<<<<<< HEAD
### 3. 配置DeepSeek API
- 在 `app.py` 中更新 `DEEPSEEK_API_KEY` 为您的API密钥
- 当前使用的密钥: `************************`
=======
4. 初始化数据库
```bash
python init_db.py
```
>>>>>>> 4c1b433 (add a main page)

5. 运行应用
```bash
python app.py
```

6. 访问应用
在浏览器中打开 http://localhost:5000

## 使用指南

详细的使用指南可以在应用内通过点击"快速上手"按钮获取。

## 许可证

[MIT License](LICENSE)

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

<<<<<<< HEAD
### 历史记录
- 查看所有检测历史
- 支持按文件名、风险等级、状态筛选
- 快速重新检测或查看详细结果

### 系统管理
管理员可以：
- 配置XGBoost模型参数
- 管理DeepSeek API设置
- 自定义提示词模板
- 查看系统统计信息
- 管理用户权限

## 🔍 检测原理

### 特征提取
系统提取141项语言无关特征，包括：
- 文件结构特征（文件数量、目录深度等）
- 大小分布特征（总大小、平均大小、最大文件等）
- 文件类型特征（可执行文件、脚本文件、配置文件等）
- 安全特征（隐藏文件、可疑扩展名等）
- 熵值特征（数据随机性分析）

### 检测算法
1. **XGBoost初筛**: 基于历史数据训练的梯度提升模型，快速识别明显的恶意和良性样本
2. **大模型复筛**: 对于置信度较低的样本，使用DeepSeek进行语义分析和风险评估
3. **结果融合**: 综合两种算法的结果，给出最终的风险等级和置信度

## 📊 API接口

### 上传文件
```
POST /upload
Content-Type: multipart/form-data

Response:
{
  "success": true,
  "scan_id": 123,
  "message": "文件上传成功，开始检测"
}
```

### 查询状态
```
GET /scan_status/<scan_id>

Response:
{
  "status": "completed",
  "progress": 100,
  "current_task": "检测完成"
}
```

### 获取结果
```
GET /results/<scan_id>
返回HTML页面显示详细检测结果
```

## 🛡️ 安全考虑

- 所有上传文件在检测完成后自动删除
- 用户会话采用安全的密钥管理
- API调用使用HTTPS加密传输
- 数据库密码使用哈希存储
- 支持文件大小和格式限制

## 🔧 配置选项

### 系统配置
- `MAX_CONTENT_LENGTH`: 最大文件上传大小（默认100MB）
- `UPLOAD_FOLDER`: 临时文件存储目录
- `DEEPSEEK_API_KEY`: DeepSeek API密钥
- `SECRET_KEY`: Flask会话密钥

### 算法参数
- XGBoost模型置信度阈值
- DeepSeek温度参数
- 特征提取参数
- 并发检测数量

## 📝 开发说明

### 项目结构
```
security-scanner/
├── app.py                 # 主应用文件
├── requirements.txt       # 依赖包列表
├── templates/            # HTML模板
│   ├── base.html
│   ├── login.html
│   ├── index.html
│   ├── progress.html
│   ├── results.html
│   ├── history.html
│   ├── admin.html
│   └── knowledge.html
├── static/               # 静态文件
│   └── reports/         # 生成的报告
├── uploads/             # 临时上传文件
└── security_scanner.db  # SQLite数据库
```

### 扩展功能
- 可集成更多机器学习模型
- 支持更多文件格式检测
- 添加更多特征提取算法
- 集成更多大语言模型API
- 增加实时威胁情报

## 🐛 故障排除

### 常见问题
1. **DeepSeek API调用失败**: 检查API密钥是否正确，网络连接是否正常
2. **文件上传失败**: 检查文件大小是否超过限制，格式是否支持
3. **检测卡住**: 检查后台进程是否正常，重启系统尝试
4. **数据库错误**: 删除 `security_scanner.db` 文件重新初始化

### 日志查看
系统运行时会在控制台输出详细日志，包括：
- 特征提取过程
- 模型预测结果
- API调用状态
- 错误信息

---

**注意**: 这是一个演示系统，实际部署时请确保：
1. 更新所有默认密码和密钥
2. 配置适当的网络安全措施  
3. 定期备份数据库和配置文件
4. 监控系统资源使用情况 
=======
1. Fork 仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开一个 Pull Request
