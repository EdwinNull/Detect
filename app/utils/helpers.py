import os
import zipfile
import tarfile

def format_size(size_in_bytes):
    """格式化文件大小"""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

def detect_package_type(file_path):
    filename = os.path.basename(file_path).lower()
    
    print(f"正在检测包类型: {file_path}")
    
    # 特殊处理 .tar.gz 扩展名，因为 splitext 只能得到 .gz
    is_targz = filename.endswith('.tar.gz')
    if is_targz:
        ext = '.tar.gz'
    else:
        ext = os.path.splitext(filename)[-1].lower()
    
    print(f"文件扩展名: {ext}")
    package_type = None
    
    # 1. 首先尝试通过内容识别包类型
    if ext in ['.whl', '.zip', '.egg']:
        try:
            with zipfile.ZipFile(file_path, 'r') as zipf:
                names = zipf.namelist()
                print(f"ZIP文件内容: {names[:10]}...")
                # 用endswith更鲁棒地检测
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    print(f"找到Python包标记文件")
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    print(f"找到NPM包标记文件")
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    print(f"找到Ruby包标记文件")
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    print(f"找到Java包标记文件")
                    return 'maven'
        except Exception as e:
            print(f"处理ZIP文件时出错: {e}")
            pass

    if ext in ['.tar.gz', '.tgz', '.npm', '.tar', '.bz2']:
        try:
            print(f"尝试以tar格式打开: {file_path}")
            with tarfile.open(file_path, 'r:*') as tar:
                names = tar.getnames()
                print(f"TAR文件内容: {names[:10]}...")
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    print(f"找到Python包标记文件")
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    print(f"找到NPM包标记文件")
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    print(f"找到Ruby包标记文件")
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    print(f"找到Java包标记文件")
                    return 'maven'
        except Exception as e:
            print(f"处理TAR文件时出错: {e}")
            pass
    
    # 2. 根据文件名判断包类型
    print(f"文件名分析: {filename}")
    if 'python' in filename or 'py' in filename.split('-'):
        print(f"根据文件名判断为Python包")
        return 'pypi'
    if 'node' in filename or 'npm' in filename or 'js' in filename.split('-'):
        print(f"根据文件名判断为NPM包")
        return 'npm'
    if 'ruby' in filename or 'gem' in filename:
        print(f"根据文件名判断为Ruby包")
        return 'rubygems'
    if 'java' in filename or 'maven' in filename:
        print(f"根据文件名判断为Java包")
        return 'maven'
    
    # 3. 只有在上述所有方法都失败时，再返回'unknown'而不是压缩格式
    print(f"无法识别包类型，返回unknown")
    return 'unknown'
