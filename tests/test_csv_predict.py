import pandas as pd
from app.services.classifier import SecurityClassifier

# 读取csv
csv_path = 'npm_feature_extracted.csv'
df = pd.read_csv(csv_path)

# 只取前5个恶意包做测试
for idx, row in df.head(5).iterrows():
    features = row.to_dict()
    print(f'\n==== 测试第{idx+1}个csv恶意包 ===')
    clf = SecurityClassifier(model_type='xgboost')
    result = clf.predict(features)
    print('预测结果:', result) 