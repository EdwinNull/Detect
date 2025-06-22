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
