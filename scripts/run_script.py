#!/usr/bin/env python3
"""
脚本启动器 - 可以从根目录运行scripts目录下的任何脚本
用法: python run_script.py <脚本名> [参数]
示例: python run_script.py train_from_csv
"""

import os
import sys
import importlib.util
import subprocess

# 添加项目根目录到系统路径
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

def list_available_scripts():
    """列出可用的脚本"""
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = []
    
    for file in os.listdir(scripts_dir):
        if file.endswith(".py") and file != "run_script.py" and file != "__init__.py":
            scripts.append(os.path.splitext(file)[0])
    
    return sorted(scripts)

def run_script(script_name, args=None):
    """运行指定的脚本"""
    if args is None:
        args = []
        
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{script_name}.py")
    
    if not os.path.exists(script_path):
        print(f"错误: 找不到脚本 '{script_name}'")
        print("可用的脚本:")
        for script in list_available_scripts():
            print(f"  - {script}")
        return 1
    
    # 使用子进程运行脚本
    cmd = [sys.executable, script_path] + args
    print(f"正在运行: {' '.join(cmd)}")
    return subprocess.call(cmd)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("错误: 请指定要运行的脚本名")
        print("用法: python run_script.py <脚本名> [参数]")
        print("可用的脚本:")
        for script in list_available_scripts():
            print(f"  - {script}")
        sys.exit(1)
    
    script_name = sys.argv[1]
    script_args = sys.argv[2:]
    
    sys.exit(run_script(script_name, script_args)) 