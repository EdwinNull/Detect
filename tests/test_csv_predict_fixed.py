import pandas as pd
from app.services.classifier import SecurityClassifier

# 读取csv
csv_path = 'npm_feature_extracted.csv'
df = pd.read_csv(csv_path)

# 排除第一列（Package Name），只使用特征列
feature_columns = df.columns[1:]  # 从第二列开始
print(f"特征列数量: {len(feature_columns)}")

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
    
    clf = SecurityClassifier(model_type='xgboost')
    result = clf.predict(features)
    print('预测结果:', result) 