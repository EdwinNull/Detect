# 开源组件包安全检测系统

## 项目结构

项目已经重新组织为更清晰的目录结构：

```
项目根/
├── app/               # 主应用程序代码
├── config/            # 配置文件
├── data/              # 数据文件
├── docs/              # 文档文件
├── models/            # 模型文件
├── scripts/           # 实用脚本
├── tests/             # 测试文件
├── uploads/           # 用户上传文件
├── venv/              # Python虚拟环境
├── run.py             # 应用程序启动脚本
└── run_scripts.py     # 脚本启动器
```

## 快速开始

### 安装依赖

```bash
pip install -r config/requirements_new.txt
pip install Flask-Login Flask-SQLAlchemy SQLAlchemy python-dotenv
```

### 启动应用

=======
# 软件包投毒检测系统

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0.1-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一个基于机器学习和人工智能技术的开源组件安全检测平台，能够自动识别和防范潜在的恶意开源组件包，保障软件供应链安全。

## 🚀 主要特性

- **🔍 智能检测**: 结合XGBoost机器学习模型和大语言模型进行双重检测
- **📦 多格式支持**: 支持PyPI、npm、jar等多种组件包格式
- **📊 详细报告**: 提供详细的检测报告和风险评估
- **👥 社区协作**: 支持用户交流和异常上报
- **📚 知识库管理**: 维护恶意包知识库和包百科
- **⚡ 实时分析**: 实时显示检测进度和结果

## 📋 系统要求

- **操作系统**: Windows 10/11, macOS 10.14+, Linux
- **Python**: 3.8或更高版本
- **内存**: 4GB及以上
- **存储**: 10GB可用空间
- **浏览器**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+

## 🛠️ 快速安装

### 1. 克隆项目
```bash
git clone https://github.com/yourusername/security-scanner.git
cd Detect
```

### 2. 创建虚拟环境
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. 安装依赖
```bash
pip install -r requirements.txt
```

### 4. 启动系统
```bash
python run.py
```

### 运行脚本

```bash
python run_scripts.py <脚本名>
```

可用的脚本：
- train_from_csv - 从CSV文件训练模型
- init_community_db - 初始化社区数据库
- update_db_schema - 更新数据库结构
- check_db - 检查数据库状态
- debug_package - 调试包分析
- ...等等

## 测试

```bash
python -m unittest discover tests
```

## 参考文档

完整的文档可在 `docs/` 目录中找到。

## 项目权限

开源组件包安全检测系统 
=======
### 5. 访问系统
打开浏览器访问：http://localhost:5000

**默认管理员账户**：
- 用户名：admin
- 密码：admin123

## 📖 文档

### 📚 用户文档
- **[用户手册](用户手册.md)** - 完整的系统使用指南
- **[快速入门指南](快速入门指南.md)** - 5分钟快速上手
- **[管理员手册](管理员手册.md)** - 管理员专用手册

### 🔧 技术文档
- **[API文档](docs/api/)** - 系统API接口文档
- **[设计文档](docs/design/)** - 系统设计文档
- **[需求文档](docs/requirements/)** - 项目需求规格说明书

### 📝 使用说明
- **[包抓取使用说明](docs/包抓取使用说明.md)** - 包抓取功能使用指南
- **[包百科功能说明](docs/包百科功能说明.md)** - 包百科功能详细说明

## 🏗️ 系统架构

```
Detect/
├── app/                    # 应用主目录
│   ├── models/            # 数据模型
│   ├── routes/            # 路由控制器
│   ├── services/          # 业务服务
│   ├── templates/         # HTML模板
│   ├── static/            # 静态文件
│   └── utils/             # 工具函数
├── config/                # 配置文件
├── data/                  # 数据目录
│   ├── datasets/          # 数据集
│   ├── samples/           # 样本文件
│   └── vicious/           # 恶意样本
├── docs/                  # 文档目录
├── models/                # 机器学习模型
├── scripts/               # 脚本文件
├── tests/                 # 测试文件
└── logs/                  # 日志文件
```

## 🔍 检测原理

### 特征提取
系统提取141项语言无关特征，包括：
- **文件结构特征**（30项）：文件数量、目录深度、文件分布
- **大小分布特征**（25项）：总大小、平均大小、最大文件
- **文件类型特征**（40项）：可执行文件、脚本文件、配置文件
- **安全特征**（30项）：隐藏文件、可疑扩展名、权限设置
- **熵值特征**（16项）：数据随机性分析

### 检测算法
1. **XGBoost初筛**: 基于历史数据训练的梯度提升模型，快速识别明显的恶意和良性样本
2. **大模型复筛**: 对于置信度较低的样本，使用大语言模型进行语义分析和风险评估
3. **结果融合**: 综合两种算法的结果，给出最终的风险等级和置信度

### 风险等级
- **🟢 低风险**: 置信度≥80%，无明显恶意特征
- **🟡 中风险**: 置信度60-80%，存在可疑特征
- **🔴 高风险**: 置信度<60%，存在明显恶意特征

## 🎯 主要功能

### 🔍 软件包检测
- 支持多种包格式上传
- 实时检测进度显示
- 详细的风险分析报告
- PDF格式报告下载

### 📚 包百科
- 软件包信息管理
- 历史检测记录
- 版本追踪
- 社区评价

### 👥 社区功能
- 用户交流讨论
- 异常上报
- 积分系统
- 知识分享

### ⚙️ 管理功能
- 用户管理
- 模型管理
- 样本管理
- 系统配置

## 🛡️ 安全特性

- **文件安全**: 所有上传文件在检测完成后自动删除
- **用户认证**: 安全的用户登录和会话管理
- **权限控制**: 基于角色的访问控制
- **数据保护**: 敏感数据加密存储
- **审计日志**: 完整的操作日志记录

## 🔧 配置选项

### 系统配置
- `MAX_CONTENT_LENGTH`: 最大文件上传大小（默认100MB）
- `UPLOAD_FOLDER`: 临时文件存储目录
- `SECRET_KEY`: Flask会话密钥
- `DATABASE_PATH`: 数据库文件路径

### 算法参数
- XGBoost模型置信度阈值
- 大语言模型温度参数
- 特征提取参数
- 并发检测数量

## 🐛 故障排除

### 常见问题
1. **系统无法启动**: 检查Python版本和依赖包安装
2. **文件上传失败**: 检查文件格式和大小限制
3. **检测卡住**: 检查后台进程和系统资源
4. **数据库错误**: 备份数据后重新初始化

### 获取帮助
- 查看[用户手册](用户手册.md)中的常见问题章节
- 在社区中提问交流
- 联系系统管理员

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出改进建议！

### 贡献方式
1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

### 开发环境
```bash
# 安装开发依赖
pip install -r requirements.txt

# 运行测试
python -m pytest tests/

# 代码格式化
black app/
```

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📞 联系我们

- **项目主页**: [GitHub Repository](https://github.com/yourusername/security-scanner)
- **问题反馈**: [Issues](https://github.com/yourusername/security-scanner/issues)
- **技术支持**: 通过系统内置反馈功能

## 🙏 致谢

感谢所有为这个项目做出贡献的开发者和用户！

---

**版本**: 1.0  
**更新日期**: 2024年12月  
**维护团队**: 软件包投毒检测系统开发团队 
