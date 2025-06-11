import os
import subprocess

packages = ['requests', 'flask', 'numpy', 'pandas', 'scipy', 'matplotlib', 'scikit-learn']
os.makedirs('benign_samples', exist_ok=True)
for pkg in packages:
    subprocess.run(['pip', 'download', '--no-binary', ':all:', '--no-deps', pkg, '-d', 'benign_samples'])