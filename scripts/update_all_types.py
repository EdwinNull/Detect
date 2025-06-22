import os
import sqlite3
import tarfile
import zipfile

def detect_package_type(file_path):
    """更准确的包类型检测函数"""
    filename = os.path.basename(file_path).lower()
    
    # 特殊处理 .tar.gz 扩展名，因为 splitext 只能得到 .gz
    is_targz = filename.endswith('.tar.gz')
    if is_targz:
        ext = '.tar.gz'
    else:
        ext = os.path.splitext(filename)[-1].lower()
    
    # 1. 首先尝试通过内容识别包类型
    if ext in ['.whl', '.zip', '.egg']:
        try:
            with zipfile.ZipFile(file_path, 'r') as zipf:
                names = zipf.namelist()
                # 用endswith更鲁棒地检测
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    return 'maven'
        except Exception:
            pass

    if ext in ['.tar.gz', '.tgz', '.npm', '.tar', '.bz2']:
        try:
            with tarfile.open(file_path, 'r:*') as tar:
                names = tar.getnames()
                if any(n.endswith('setup.py') or n.endswith('pyproject.toml') or n.endswith('setup.cfg') or n.endswith('PKG-INFO') for n in names):
                    return 'pypi'
                if any(n.endswith('package.json') for n in names):
                    return 'npm'
                if any(n.endswith('.gemspec') for n in names):
                    return 'rubygems'
                if any(n.endswith('pom.xml') or n.endswith('build.gradle') for n in names):
                    return 'maven'
        except Exception:
            pass
    
    # 2. 根据文件名判断包类型
    if 'python' in filename or 'py' in filename.split('-'):
        return 'pypi'
    if 'node' in filename or 'npm' in filename or 'js' in filename.split('-'):
        return 'npm'
    if 'ruby' in filename or 'gem' in filename:
        return 'rubygems'
    if 'java' in filename or 'maven' in filename:
        return 'maven'
    
    # 3. 只有在上述所有方法都失败时，再返回'unknown'
    return 'unknown'

def update_all_package_types():
    """更新数据库中所有样本的包类型"""
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 获取所有样本的路径
    cursor.execute('SELECT id, file_path FROM samples')
    samples = cursor.fetchall()
    
    total = len(samples)
    updated_count = 0
    package_types = {}
    
    print(f"开始更新 {total} 个样本的包类型...")
    
    for i, (sample_id, file_path) in enumerate(samples, 1):
        if os.path.exists(file_path):
            try:
                # 检测包类型
                package_type = detect_package_type(file_path)
                
                # 统计包类型数量
                package_types[package_type] = package_types.get(package_type, 0) + 1
                
                # 更新数据库
                cursor.execute('UPDATE samples SET package_type = ? WHERE id = ?', 
                              (package_type, sample_id))
                updated_count += 1
                
                if i % 10 == 0 or i == total:
                    print(f"进度: {i}/{total} ({i/total*100:.1f}%) - 更新: {updated_count}")
                
            except Exception as e:
                print(f"更新样本 {sample_id} 类型失败: {e}")
        else:
            print(f"文件不存在: {file_path}")
    
    conn.commit()
    conn.close()
    
    print(f"\n更新完成! 总共更新 {updated_count}/{total} 个样本")
    print("\n包类型统计:")
    for pkg_type, count in package_types.items():
        print(f"  {pkg_type}: {count} 个样本")

if __name__ == "__main__":
    update_all_package_types() 