#!/usr/bin/env python3
"""
脚本启动器快捷方式
用法: python run_scripts.py <脚本名> [参数]
示例: python run_scripts.py train_from_csv
"""

import os
import sys
import importlib.util
import subprocess

# 直接执行scripts/run_script.py
script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts', 'run_script.py')

if __name__ == "__main__":
    cmd = [sys.executable, script_path] + sys.argv[1:]
    sys.exit(subprocess.call(cmd)) 