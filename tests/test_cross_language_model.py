import pandas as pd
from app.services.classifier import SecurityClassifier

# 读取csv
csv_path = 'npm_feature_extracted.csv'
df = pd.read_csv(csv_path)

# 排除第一列（Package Name），只使用特征列
feature_columns = df.columns[1:]  # 从第二列开始
print(f"特征列数量: {len(feature_columns)}")

# 测试cross_language模型
print("\n=== 测试cross_language模型 ===")
clf_cross = SecurityClassifier(model_type='cross_language')

# 只取前5个恶意包做测试
for idx, row in df.head(5).iterrows():
    # 只取特征列，排除包名
    features = row[feature_columns].to_dict()
    print(f'\n==== 测试第{idx+1}个csv恶意包: {row["Package Name"]} ===')
    
    # 打印一些关键特征值
    key_features = [
        'Number of Words in source code',
        'Number of lines in source code', 
        'Number of base64 chunks in source code',
        'Number of IP adress in source code',
        'Number of sospicious token in source code',
        'shannon mean ID source code',
        'shannon max ID source code'
    ]
    print("关键特征值:")
    for feature in key_features:
        print(f"  {feature}: {features.get(feature, 0)}")
    
    result = clf_cross.predict(features)
    print('cross_language模型预测结果:', result)

# 测试js_model
print("\n=== 测试js_model ===")
clf_js = SecurityClassifier(model_type='js_model')

for idx, row in df.head(3).iterrows():
    features = row[feature_columns].to_dict()
    print(f'\n==== 测试第{idx+1}个csv恶意包: {row["Package Name"]} ===')
    result = clf_js.predict(features)
    print('js_model预测结果:', result)

# 测试py_model
print("\n=== 测试py_model ===")
clf_py = SecurityClassifier(model_type='py_model')

for idx, row in df.head(3).iterrows():
    features = row[feature_columns].to_dict()
    print(f'\n==== 测试第{idx+1}个csv恶意包: {row["Package Name"]} ===')
    result = clf_py.predict(features)
    print('py_model预测结果:', result) 