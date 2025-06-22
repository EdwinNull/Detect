import pandas as pd

# 读取csv文件
csv_path = 'npm_feature_extracted.csv'
df = pd.read_csv(csv_path)

print("=== CSV文件信息 ===")
print(f"总行数: {len(df)}")
print(f"总列数: {len(df.columns)}")
print(f"列名列表:")
for i, col in enumerate(df.columns):
    print(f"  {i+1:3d}. {col}")

print(f"\n=== 前3行数据预览 ===")
print(df.head(3))

print(f"\n=== 检查是否有缺失值 ===")
missing_counts = df.isnull().sum()
if missing_counts.sum() > 0:
    print("有缺失值的列:")
    for col, count in missing_counts[missing_counts > 0].items():
        print(f"  {col}: {count}个缺失值")
else:
    print("没有缺失值")

print(f"\n=== 数据类型统计 ===")
print(df.dtypes.value_counts()) 