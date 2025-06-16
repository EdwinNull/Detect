import os
import tarfile
import zipfile

def detect_package_type_debug(file_path):
    """详细调试包类型检测过程"""
    ext = os.path.splitext(file_path)[-1].lower()
    package_type = None
    
    print(f"测试文件: {file_path}")
    print(f"文件扩展名: {ext}")
    
    if ext in ['.tar.gz', '.tgz', '.npm', '.tar', '.bz2']:
        try:
            print(f"尝试以tar格式打开文件...")
            with tarfile.open(file_path, 'r:*') as tar:
                names = tar.getnames()
                print(f"TAR文件内容列表:")
                for name in names:
                    print(f"  - {name}")
                
                print("\n检查Python包特征文件:")
                for marker in ['setup.py', 'pyproject.toml', 'setup.cfg', 'PKG-INFO']:
                    matching = [n for n in names if n.endswith(marker)]
                    if matching:
                        print(f"  找到 {marker}: {matching}")
                    else:
                        print(f"  未找到 {marker}")
                
                # 检查PyPI包
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    print("==> 检测为PyPI包")
                    package_type = 'pypi'
                # 检查NPM包
                elif any(n.endswith('package.json') for n in names):
                    print("==> 检测为NPM包")
                    package_type = 'npm'
                else:
                    print("==> 未检测到特定包类型标记")
        except Exception as e:
            print(f"处理文件时出错: {e}")
    
    # 根据文件名判断
    filename = os.path.basename(file_path).lower()
    print(f"\n分析文件名: {filename}")
    if 'python' in filename or 'py' in filename.split('-'):
        print("根据文件名判断为Python包")
        return 'pypi' if not package_type else package_type
    
    print(f"\n最终检测结果: {package_type or 'unknown'}")
    return package_type or 'unknown'

# 测试10Cent11-999.0.4.tar.gz
sample_dir = os.path.join('uploads', 'samples')
file_path = os.path.join(sample_dir, '10Cent11-999.0.4.tar.gz')
if os.path.exists(file_path):
    result = detect_package_type_debug(file_path)
    print(f"\n包类型检测结果: {result}")
else:
    print(f"文件不存在: {file_path}")
    # 尝试寻找文件
    for root, dirs, files in os.walk('uploads'):
        for file in files:
            if '10Cent11' in file:
                print(f"找到类似文件: {os.path.join(root, file)}")
                # 尝试检测这个文件
                alt_path = os.path.join(root, file)
                if os.path.exists(alt_path):
                    result = detect_package_type_debug(alt_path)
                    print(f"\n替代文件包类型检测结果: {result}")
                    break 