from flask import Blueprint, render_template, redirect, url_for, session, flash, send_file, jsonify
import sqlite3
import json
from app.utils import login_required
from app.utils.helpers import format_size
from config import Config
from fpdf import FPDF

user_bp = Blueprint('user', __name__)

@user_bp.route('/')
@login_required
def index():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 管理员和普通用户视图分离
    is_admin = session.get('role') == 'admin'
    
    if is_admin:
        # 管理员可以看到全局数据
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, created_at, package_type, user_id
            FROM scan_records 
            WHERE risk_level = 'high' 
            AND scan_status = 'completed' 
            ORDER BY created_at DESC 
            LIMIT 8
        ''')
        recent_malicious_packages = cursor.fetchall()
        
        # 管理员统计信息
        cursor.execute('SELECT COUNT(*) FROM users')
        total_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM samples')
        total_samples = cursor.fetchone()[0]
        
        # 计算高风险包总数
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE risk_level = 'high' AND scan_status = 'completed'
        ''')
        total_malicious = cursor.fetchone()[0]
        
        # 获取检测总数
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE scan_status = 'completed'
        ''')
        total_scans = cursor.fetchone()[0]
    else:
        # 普通用户只能看到自己的数据
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, created_at, package_type
            FROM scan_records 
            WHERE user_id = ?
            AND scan_status = 'completed' 
            ORDER BY created_at DESC 
            LIMIT 5
        ''', (session['user_id'],))
        recent_malicious_packages = cursor.fetchall()
        
        # 用户自己的统计信息
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE user_id = ? AND risk_level = 'high' AND scan_status = 'completed'
        ''', (session['user_id'],))
        total_malicious = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM scan_records 
            WHERE user_id = ? AND scan_status = 'completed'
        ''', (session['user_id'],))
        total_scans = cursor.fetchone()[0]
        
        total_users = None
        total_samples = None
    
    # 格式化数据
    malicious_packages = []
    for pkg in recent_malicious_packages:
        malicious_packages.append({
            'id': pkg['id'],
            'filename': pkg['filename'],
            'file_size': format_size(pkg['file_size']) if pkg['file_size'] else "未知",
            'risk_level': pkg['risk_level'],
            'confidence': pkg['confidence'] * 100 if pkg['confidence'] else 0,
            'created_at': pkg['created_at'],
            'package_type': pkg['package_type'] if 'package_type' in pkg.keys() else 'unknown',
            'user_id': pkg['user_id'] if is_admin and 'user_id' in pkg.keys() else session['user_id']
        })
    
    conn.close()
    
    return render_template('index.html', 
                          malicious_packages=malicious_packages,
                          total_malicious=total_malicious,
                          total_scans=total_scans,
                          total_users=total_users,
                          total_samples=total_samples,
                          is_admin=is_admin)

@user_bp.route('/history')
@login_required
def history():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 管理员可以看到所有用户的记录，普通用户只能看到自己的
    if session.get('role') == 'admin':
        cursor.execute('''
            SELECT r.id, r.filename, r.file_size, r.risk_level, r.confidence, r.scan_status, r.created_at, 
                   r.package_type, u.username
            FROM scan_records r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT id, filename, file_size, risk_level, confidence, scan_status, created_at, package_type
            FROM scan_records 
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],))
    
    records = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', records=records)

@user_bp.route('/guide')
def guide():
    return render_template('guide.html')

@user_bp.route('/knowledge')
def knowledge():
    # 入门指南内容
    getting_started_articles = [
        {
            'id': 'quick-start',
            'title': '快速开始',
            'desc': '本指南将帮助您快速了解并开始使用开源组件包安全检测系统。我们的平台使用机器学习模型和大语言模型结合的方式，对上传的组件包进行安全风险评估，帮助您识别潜在的恶意代码和供应链攻击。'
        },
        {
            'id': 'installation',
            'title': '安装说明',
            'desc': '''
                <h4>系统要求</h4>
                <ul>
                    <li>Python 3.8+</li>
                    <li>8GB 内存或更高</li>
                    <li>4GB 可用磁盘空间</li>
                    <li>互联网连接（用于API调用）</li>
                </ul>
                
                <h4>安装步骤</h4>
                <ol>
                    <li>克隆代码仓库: <code>git clone https://github.com/yourusername/security-scanner.git</code></li>
                    <li>进入项目目录: <code>cd security-scanner</code></li>
                    <li>安装依赖: <code>pip install -r requirements.txt</code></li>
                    <li>配置环境变量: 复制 <code>.env.example</code> 为 <code>.env</code> 并填写相应配置</li>
                    <li>初始化数据库: <code>python run.py</code> (首次运行时会自动创建数据库)</li>
                </ol>
            '''
        },
        {
            'id': 'configuration',
            'title': '基础配置',
            'desc': '''
                <h4>系统配置选项</h4>
                <p>在 <code>.env</code> 文件中配置以下关键参数:</p>
                <ul>
                    <li><strong>DEEPSEEK_API_KEY</strong>: DeepSeek大语言模型的API密钥，用于代码分析</li>
                    <li><strong>UPLOAD_FOLDER</strong>: 上传文件的临时存储路径</li>
                    <li><strong>MAX_CONTENT_LENGTH</strong>: 允许上传的最大文件大小（默认为50MB）</li>
                    <li><strong>SECRET_KEY</strong>: Flask应用的密钥，用于会话安全</li>
                </ul>
                
                <h4>管理员账户</h4>
                <p>系统默认创建以下管理员账户:</p>
                <ul>
                    <li>用户名: admin</li>
                    <li>密码: admin123</li>
                </ul>
                <p><strong>重要提示:</strong> 在生产环境中部署时，请务必修改默认密码。</p>
            '''
        },
        {
            'id': 'first-scan',
            'title': '首次扫描',
            'desc': '''
                <h4>执行首次安全扫描</h4>
                <ol>
                    <li>登录系统后，在主页找到上传区域</li>
                    <li>点击"选择文件"或直接拖拽组件包到上传区域</li>
                    <li>支持的文件格式包括：.zip, .tar.gz, .whl, .jar, .gem, .tgz, .npm 等</li>
                    <li>点击"开始检测"按钮启动扫描</li>
                    <li>系统会显示扫描进度，完成后自动跳转到结果页面</li>
                </ol>
                
                <h4>样例组件包</h4>
                <p>如果您需要测试系统功能，可以使用以下开源包:</p>
                <ul>
                    <li>安全包示例: <code>requests-2.25.1-py2.py3-none-any.whl</code></li>
                    <li>注: 系统自带测试样本，可在管理员页面查看</li>
                </ul>
            '''
        }
    ]
    
    # 基础使用内容
    basic_usage_articles = [
        {
            'id': 'scan-types',
            'title': '扫描类型',
            'desc': '''
                <h4>本系统支持多种扫描类型和组件包格式:</h4>
                <ul>
                    <li><strong>PyPI包</strong>: 检测Python包中的恶意代码，包括setup.py中的恶意逻辑、后门模块等</li>
                    <li><strong>NPM包</strong>: 分析JavaScript代码，检测恶意脚本、供应链投毒等</li>
                    <li><strong>Maven包</strong>: 检测Java构件中的恶意代码</li>
                    <li><strong>RubyGems包</strong>: 分析Ruby gems中的可疑代码</li>
                </ul>
                
                <h4>特征提取</h4>
                <p>系统会对上传的组件包执行以下分析:</p>
                <ul>
                    <li>文件结构与内容分析</li>
                    <li>代码特征提取</li>
                    <li>API使用模式识别</li>
                    <li>权限与敏感操作检测</li>
                </ul>
            '''
        },
        {
            'id': 'result-analysis',
            'title': '结果分析',
            'desc': '''
                <h4>理解检测结果中的关键指标</h4>
                <ul>
                    <li><strong>风险等级</strong>: 系统评估的总体风险水平（低/中/高）</li>
                    <li><strong>置信度</strong>: 检测结果的可信度百分比</li>
                    <li><strong>XGBoost分析</strong>: 基于特征工程和机器学习的风险评分</li>
                    <li><strong>DeepSeek分析</strong>: 大语言模型对代码的语义理解分析</li>
                    <li><strong>风险说明</strong>: 潜在威胁的详细解释和推荐操作</li>
                </ul>
                
                <h4>检测报告导出</h4>
                <p>您可以通过以下格式导出检测报告:</p>
                <ul>
                    <li><strong>JSON格式</strong>: 包含完整的技术细节，适合进一步分析</li>
                    <li><strong>PDF格式</strong>: 正式报告格式，适合团队分享和存档</li>
                </ul>
            '''
        }
    ]
    
    # API文档内容
    api_articles = [
        {
            'id': 'api-overview',
            'title': 'API概述',
            'desc': '''
                <h4>API功能介绍</h4>
                <p>本系统提供REST API接口，允许用户通过编程方式与安全检测功能交互，便于集成到自动化流程中。</p>
                
                <h4>API访问要求</h4>
                <ul>
                    <li>所有API请求需要API密钥进行身份验证</li>
                    <li>请求使用HTTPS协议加密传输</li>
                    <li>API请求返回JSON格式数据</li>
                    <li>API密钥可以在管理员页面生成和管理</li>
                </ul>
                
                <h4>基本端点</h4>
                <code>https://您的域名/api/v1/</code>
            '''
        },
        {
            'id': 'api-endpoints',
            'title': '接口说明',
            'desc': '''
                <h4>主要API端点</h4>
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">端点</th>
                        <th style="padding: 8px; text-align: left;">方法</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/scan</code></td>
                        <td style="padding: 8px;">POST</td>
                        <td style="padding: 8px;">上传并扫描组件包</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/scan/{scan_id}</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">获取扫描状态和结果</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/history</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">列出历史扫描记录</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><code>/api/v1/report/{scan_id}</code></td>
                        <td style="padding: 8px;">GET</td>
                        <td style="padding: 8px;">获取报告（JSON/PDF）</td>
                    </tr>
                </table>
            '''
        },
        {
            'id': 'api-examples',
            'title': '使用示例',
            'desc': '''
                <h4>上传并扫描组件包</h4>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
curl -X POST \\
  https://example.com/api/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -F "file=@package.zip"
                </pre>
                
                <h4>Python集成示例</h4>
                <pre style="background-color: #f6f8fa; padding: 10px; border-radius: 5px; overflow-x: auto;">
import requests
import time

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://example.com/api/v1"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# 上传并扫描文件
def scan_package(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/scan",
            headers=HEADERS,
            files={"file": f}
        )
    data = response.json()
    if data["success"]:
        return data["data"]["scan_id"]
    else:
        raise Exception(f"扫描请求失败: {data['error']}")

# 获取扫描结果
def get_scan_result(scan_id):
    while True:
        response = requests.get(
            f"{BASE_URL}/scan/{scan_id}",
            headers=HEADERS
        )
        data = response.json()["data"]
        if data["status"] == "completed":
            return data
        elif data["status"] == "error":
            raise Exception(f"扫描失败: {data['message']}")
        else:
            print(f"扫描进度: {data.get('progress', 0)}%")
            time.sleep(5)
                </pre>
            '''
        }
    ]
    
    # 故障排除内容
    troubleshooting_articles = [
        {
            'id': 'common-issues',
            'title': '常见问题',
            'desc': '''
                <h4>上传问题</h4>
                <ul>
                    <li>
                        <strong>问题</strong>: 文件上传失败<br>
                        <strong>解决方法</strong>: 检查文件大小是否超过限制(50MB)，确认文件格式是否受支持，检查网络连接
                    </li>
                    <li>
                        <strong>问题</strong>: 无法识别包类型<br>
                        <strong>解决方法</strong>: 确保上传的是标准格式的组件包，包含必要的元数据文件（如setup.py、package.json等）
                    </li>
                </ul>
                
                <h4>检测问题</h4>
                <ul>
                    <li>
                        <strong>问题</strong>: 检测过程卡住不动<br>
                        <strong>解决方法</strong>: 检查网络连接，确保API服务可用；对于特别大的包可能需要更长时间
                    </li>
                    <li>
                        <strong>问题</strong>: 检测失败，无结果<br>
                        <strong>解决方法</strong>: 查看系统日志，检查包文件完整性，尝试重新上传或使用"重试检测"功能
                    </li>
                </ul>
            '''
        },
        {
            'id': 'error-messages',
            'title': '错误信息',
            'desc': '''
                <h4>常见错误代码及解决方案</h4>
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">错误代码</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                        <th style="padding: 8px; text-align: left;">解决方法</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-001</td>
                        <td style="padding: 8px;">文件格式不支持</td>
                        <td style="padding: 8px;">使用受支持的包格式(.zip, .tar.gz, .whl, .jar等)</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-002</td>
                        <td style="padding: 8px;">API调用失败</td>
                        <td style="padding: 8px;">检查API密钥和网络连接，确认DeepSeek服务可用</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-003</td>
                        <td style="padding: 8px;">特征提取失败</td>
                        <td style="padding: 8px;">检查包文件是否完整，尝试重新上传</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;">ERR-004</td>
                        <td style="padding: 8px;">存储空间不足</td>
                        <td style="padding: 8px;">清理临时文件目录，为上传文件释放空间</td>
                    </tr>
                </table>
            '''
        },
        {
            'id': 'performance',
            'title': '性能优化',
            'desc': '''
                <h4>系统性能优化建议</h4>
                <p>如果系统运行缓慢或检测效率不高，可以尝试以下优化措施：</p>
                
                <ul>
                    <li><strong>增加硬件资源</strong>: 对于大型部署，建议至少16GB内存和4核处理器</li>
                    <li><strong>优化数据库</strong>: 定期清理旧的检测记录和临时文件</li>
                    <li><strong>调整并发设置</strong>: 在<code>config.py</code>中调整最大并发检测任务数</li>
                    <li><strong>使用缓存</strong>: 启用结果缓存可以加快重复检测的速度</li>
                </ul>
                
                <h4>大型包处理策略</h4>
                <p>处理超大型包（>100MB）时的建议：</p>
                <ul>
                    <li>增加超时时间设置</li>
                    <li>使用分块分析模式</li>
                    <li>优先分析关键文件而非全量分析</li>
                </ul>
            '''
        }
    ]
    
    # 安全说明内容
    security_articles = [
        {
            'id': 'security-best-practices',
            'title': '安全最佳实践',
            'desc': '''
                <h4>开源组件使用安全指南</h4>
                <p>在使用开源组件时，遵循以下最佳实践可以大幅降低安全风险：</p>
                
                <ol>
                    <li><strong>持续检测与更新</strong>：定期检测已引入的组件包，并及时更新到最新的安全版本</li>
                    <li><strong>最小权限原则</strong>：仅引入必要的依赖，减少供应链攻击面</li>
                    <li><strong>验证包来源</strong>：确保从官方源下载包，不要使用未知或可疑的包仓库</li>
                    <li><strong>锁定依赖版本</strong>：使用lockfiles（如package-lock.json, Pipfile.lock）锁定依赖版本</li>
                    <li><strong>审核新引入的依赖</strong>：在引入新依赖前，评估其安全性、活跃度和维护状态</li>
                </ol>
                
                <h4>CI/CD流水线集成</h4>
                <p>将安全检测集成到CI/CD流水线中，在以下阶段执行检测：</p>
                <ul>
                    <li>代码提交时</li>
                    <li>依赖更新时</li>
                    <li>构建阶段</li>
                    <li>发布前验证</li>
                </ul>
            '''
        },
        {
            'id': 'threat-modeling',
            'title': '威胁建模',
            'desc': '''
                <h4>开源组件威胁模型</h4>
                <p>了解开源组件面临的主要威胁类型，有助于更有针对性地进行安全防护：</p>
                
                <table border="1" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f3f4f6;">
                        <th style="padding: 8px; text-align: left;">威胁类型</th>
                        <th style="padding: 8px; text-align: left;">描述</th>
                        <th style="padding: 8px; text-align: left;">缓解措施</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>依赖混淆攻击</strong></td>
                        <td style="padding: 8px;">攻击者在公共仓库发布与私有库同名的恶意包</td>
                        <td style="padding: 8px;">使用范围限定前缀、验证包来源、私有镜像</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>供应链投毒</strong></td>
                        <td style="padding: 8px;">攻击者将恶意代码注入受信任的包或其依赖中</td>
                        <td style="padding: 8px;">锁定依赖版本、完整性校验、漏洞扫描</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>包劫持</strong></td>
                        <td style="padding: 8px;">攻击者接管被弃用的包名或控制维护者账号</td>
                        <td style="padding: 8px;">多因素认证、依赖审核、活跃度监控</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>自动执行攻击</strong></td>
                        <td style="padding: 8px;">恶意代码在包安装或导入时自动执行</td>
                        <td style="padding: 8px;">安全环境检测、沙箱安装、代码审查</td>
                    </tr>
                </table>
            '''
        },
        {
            'id': 'security-standards',
            'title': '安全标准',
            'desc': '''
                <h4>相关安全标准</h4>
                <p>开源组件安全检测遵循以下行业标准：</p>
                
                <ul>
                    <li><strong>OWASP Top 10</strong>：特别是A9(使用含有已知漏洞的组件)</li>
                    <li><strong>NIST安全软件开发框架</strong>：供应链安全管理</li>
                    <li><strong>CIS Controls</strong>：特别是控制项18(应用软件安全)</li>
                    <li><strong>SLSA框架</strong>：软件供应链安全级别</li>
                </ul>
                
                <h4>合规检查清单</h4>
                <p>确保项目安全合规，可以参考以下检查清单：</p>
                <ul>
                    <li>建立并维护组件清单(SBOM)</li>
                    <li>实施依赖管理策略</li>
                    <li>定期进行安全扫描</li>
                    <li>制定组件淘汰与更新策略</li>
                    <li>响应安全公告与更新</li>
                </ul>
            '''
        }
    ]
    
    # 功能特性内容
    features_articles = [
        {
            'id': 'scan-features',
            'title': '扫描功能',
            'desc': '''
                <h4>多层次安全扫描体系</h4>
                <p>本系统采用多层次的安全扫描架构，结合静态分析、特征提取和语义理解三大技术维度，实现对恶意代码的精准识别。</p>
                
                <h4>核心技术优势</h4>
                <ul>
                    <li>两阶段检测架构（XGBoost特征检测 + DeepSeek语义分析）</li>
                    <li>自动适应不同语言和包格式的特征提取</li>
                    <li>持续更新的威胁情报库</li>
                    <li>基于大语言模型的代码意图分析</li>
                </ul>
            '''
        },
        {
            'id': 'dependency-scan',
            'title': '依赖扫描',
            'desc': '''
                <h4>依赖关系分析</h4>
                <p>系统能够解析包管理文件，识别所有声明的依赖关系，验证依赖的完整性和安全性。</p>
                
                <h4>主要检测点</h4>
                <ul>
                    <li>依赖混淆攻击（Dependency Confusion）检测</li>
                    <li>非官方源依赖识别</li>
                    <li>版本号欺骗检测</li>
                    <li>间接依赖风险评估</li>
                </ul>
                
                <p>系统会扫描package.json、requirements.txt、pom.xml等文件，检查其中的依赖项目是否存在安全隐患。</p>
            '''
        },
        {
            'id': 'vulnerability-scan',
            'title': '漏洞扫描',
            'desc': '''
                <h4>代码漏洞检测</h4>
                <p>本系统能够识别组件包中可能存在的代码漏洞，包括但不限于：</p>
                
                <ul>
                    <li>不安全的序列化/反序列化</li>
                    <li>命令注入漏洞</li>
                    <li>路径穿越漏洞</li>
                    <li>不安全的随机数生成</li>
                    <li>硬编码密钥和凭证</li>
                </ul>
                
                <h4>漏洞评级</h4>
                <p>系统采用CVSS（通用漏洞评分系统）标准对检测到的漏洞进行评级，并给出具体的风险等级和修复建议。</p>
            '''
        },
        {
            'id': 'malware-scan',
            'title': '恶意代码检测',
            'desc': '''
                <h4>恶意代码模式识别</h4>
                <p>系统通过分析代码中的恶意模式，检测可能的恶意行为：</p>
                
                <ul>
                    <li><strong>数据窃取</strong>: 检测未授权收集和传输用户数据的代码</li>
                    <li><strong>远程控制</strong>: 识别后门和远程访问功能</li>
                    <li><strong>挖矿行为</strong>: 检测加密货币挖矿相关代码</li>
                    <li><strong>信息泄露</strong>: 发现敏感信息泄露风险</li>
                </ul>
                
                <h4>检测方法</h4>
                <p>结合以下技术进行检测：</p>
                <ul>
                    <li>静态代码分析</li>
                    <li>行为特征匹配</li>
                    <li>机器学习模型</li>
                    <li>大语言模型分析</li>
                </ul>
            '''
        },
        {
            'id': 'risk-assessment',
            'title': '风险评估',
            'desc': '''
                <h4>风险评分系统</h4>
                <p>系统采用多维度风险评估方法，综合考虑以下因素：</p>
                
                <ul>
                    <li>代码质量评分</li>
                    <li>安全漏洞数量</li>
                    <li>依赖包风险</li>
                    <li>恶意行为指标</li>
                    <li>历史安全记录</li>
                </ul>
                
                <h4>风险等级</h4>
                <p>根据综合评分，将风险分为以下等级：</p>
                <ul>
                    <li><strong>低风险</strong>: 评分 0-30，建议正常使用</li>
                    <li><strong>中风险</strong>: 评分 31-70，建议审查后使用</li>
                    <li><strong>高风险</strong>: 评分 71-100，建议避免使用</li>
                </ul>
            '''
        },
        {
            'id': 'report-generation',
            'title': '报告生成',
            'desc': '''
                <h4>检测报告内容</h4>
                <p>系统生成的检测报告包含以下内容：</p>
                
                <ul>
                    <li>基本信息（包名、版本、大小等）</li>
                    <li>风险等级和置信度</li>
                    <li>检测到的安全问题</li>
                    <li>依赖包分析结果</li>
                    <li>修复建议</li>
                </ul>
                
                <h4>报告格式</h4>
                <p>支持多种格式导出：</p>
                <ul>
                    <li>HTML格式（网页查看）</li>
                    <li>PDF格式（打印存档）</li>
                    <li>JSON格式（数据集成）</li>
                </ul>
            '''
        }
    ]
    
    # 整合文章内容
    articles = getting_started_articles + basic_usage_articles + features_articles + security_articles + troubleshooting_articles + api_articles
    
    # FAQ示例
    faqs = [
        {
            'q': '系统能检测哪些类型的恶意代码？',
            'a': '本系统可检测的恶意代码类型包括：供应链攻击、数据窃取、远程代码执行、恶意脚本注入、隐蔽挖矿、依赖混淆攻击等多种常见威胁。检测算法结合了静态分析和语义分析，能够有效识别精心伪装的恶意代码。'
        },
        {
            'q': '扫描结果出现"风险等级：高"但置信度不高怎么办？',
            'a': '当系统报告高风险但置信度不高时，表示检测到了可疑模式但无法完全确定。建议：(1)查看详细的风险说明；(2)检查检测到的可疑代码片段；(3)使用其他安全工具进行交叉验证；(4)在隔离环境中测试该组件包。如有疑问，请谨慎使用该组件。'
        },
        {
            'q': '如何提高检测准确率？',
            'a': '提高检测准确率可通过以下方法：(1)保持模型训练数据的更新；(2)在管理员页面上传更多已知安全和恶意的样本进行训练；(3)调整检测阈值；(4)结合多种工具的检测结果进行综合判断。本系统采用双引擎检测（机器学习+大语言模型），已经具备较高的准确率。'
        },
        {
            'q': '系统支持自动化集成吗？',
            'a': '是的，本系统提供API接口，可以与CI/CD流水线、代码审查系统和依赖管理工具集成。详细的API文档可在"API文档"部分查看，包括验证方法、请求参数和返回格式说明。'
        },
        {
            'q': '支持检测哪些编程语言的包？',
            'a': '目前系统主要支持Python(PyPI)、JavaScript(NPM)、Java(Maven)和Ruby(RubyGems)等主流编程语言的包格式。系统会根据上传的包文件自动识别其类型，并应用对应的分析规则和特征提取方法。我们计划在未来版本中增加对Golang、Rust和.NET包的支持。'
        },
        {
            'q': '如果检测出恶意包，我该怎么做？',
            'a': '如果检测到恶意包，建议采取以下措施：(1)立即停止使用该组件；(2)检查已部署的应用是否受影响；(3)寻找安全的替代组件；(4)将该组件报告给相应的包管理平台；(5)检查您的开发环境是否受到感染。如果是企业环境，还应当通知安全团队进行进一步调查。'
        },
        {
            'q': '我可以自定义检测规则吗？',
            'a': '当前版本支持有限的规则自定义功能。管理员用户可以通过上传已知的安全和恶意样本来训练模型，从而影响检测规则。未来版本将提供更完善的规则自定义功能，允许用户定义特定的检测阈值、忽略某些类型的警告，以及创建组织专属的检测规则。'
        },
        {
            'q': '系统是如何区分误报和真实威胁的？',
            'a': '本系统通过多层次验证来减少误报：首先使用XGBoost模型进行初筛，然后使用DeepSeek大语言模型进行深度语义分析，两者结合形成最终判断。系统会计算置信度分数，表明结果的可靠性。此外，系统还会提供详细的风险解释，帮助用户理解检测结果的依据，便于人工判断是否为误报。'
        },
        {
            'q': '是否支持批量扫描多个包？',
            'a': '是的，系统支持批量扫描功能。在Web界面上，您可以一次性上传多个文件进行批量检测。如果使用API接口，可以编写脚本循环调用扫描接口，处理多个包文件。对于企业用户，我们建议使用API集成到CI/CD管道中，实现依赖包的自动化扫描和审计。'
        },
        {
            'q': '检测结果会保存多久？',
            'a': '默认情况下，系统会永久保存所有的扫描结果记录，以便用户查看历史数据和趋势分析。如果您希望自动清理旧的扫描记录，可以配置数据保留策略（需要管理员权限）。同时，用户可以随时手动删除不需要的扫描记录。出于安全考虑，上传的原始包文件在扫描完成后会被自动删除，仅保留扫描结果和提取的特征数据。'
        }
    ]
    
    return render_template('knowledge.html', articles=articles, faqs=faqs)

@user_bp.route('/download_report/<int:scan_id>/<format>')
@login_required
def download_report(scan_id, format):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    # 获取扫描数据
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scan_records 
        WHERE id = ? AND user_id = ?
    ''', (scan_id, session['user_id']))
    
    record = cursor.fetchone()
    if not record:
        return jsonify({'error': '扫描记录不存在'}), 404
    
    if format == 'json':
        # 生成JSON报告
        report_data = {
            'scan_id': record[0],
            'filename': record[2],
            'file_size': record[3],
            'file_hash': record[4],
            'risk_level': record[6],
            'confidence': record[7],
            'xgboost_result': json.loads(record[8]) if record[8] else {},
            'llm_result': json.loads(record[9]) if record[9] else {},
            'risk_explanation': record[10],
            'scan_time': record[11],
            'created_at': record[12]
        }
        
        report_path = f'static/reports/report_{scan_id}.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        return send_file(report_path, as_attachment=True, 
                        download_name=f'security_report_{scan_id}.json')
    
    elif format == 'pdf':
        # 生成PDF报告
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f'Security Scan Report - {record[2]}', 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Scan ID: {record[0]}', 0, 1)
        pdf.cell(0, 10, f'File Size: {record[3]} bytes', 0, 1)
        pdf.cell(0, 10, f'Risk Level: {record[6] or "N/A"}', 0, 1)
        pdf.cell(0, 10, f'Confidence: {record[7]:.2%}' if record[7] else 'N/A', 0, 1)
        
        report_path = f'static/reports/report_{scan_id}.pdf'
        pdf.output(report_path)
        
        return send_file(report_path, as_attachment=True,
                        download_name=f'security_report_{scan_id}.pdf')
    
    return jsonify({'error': '不支持的格式'}), 400
