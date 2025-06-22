import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import xgboost as xgb
from sklearn.preprocessing import StandardScaler

def train_models_from_csv():
    """从CSV文件训练模型（恶意+非恶意）"""
    print("开始从CSV文件训练模型...")

    # 修正csv路径
    csv_path_mal = 'Detect-main/npm_feature_extracted.csv'
    if not os.path.exists(csv_path_mal):
        csv_path_mal = 'Detect-main/Detect-main/npm_feature_extracted.csv'
    if not os.path.exists(csv_path_mal):
        print(f"错误：找不到文件 {csv_path_mal}")
        return
    df_mal = pd.read_csv(csv_path_mal)
    df_mal['label'] = 1  # 全部标记为恶意

    csv_path_mix = 'Detect-main/Labelled_Dataset.csv'
    if not os.path.exists(csv_path_mix):
        csv_path_mix = 'Detect-main/Detect-main/Labelled_Dataset.csv'
    if not os.path.exists(csv_path_mix):
        print(f"错误：找不到文件 {csv_path_mix}")
        return
    df_mix = pd.read_csv(csv_path_mix)
    if 'Malicious' in df_mix.columns:
        df_mix['label'] = df_mix['Malicious']
    elif 'label' not in df_mix.columns:
        print("错误：Labelled_Dataset.csv中找不到Malicious或label字段")
        return

    ignore_cols = ['Package Name', 'Malicious', 'label']
    feature_cols = [col for col in df_mal.columns if col not in ignore_cols and col in df_mix.columns]
    print(f"共有特征数量: {len(feature_cols)}")

    df_mal = df_mal[feature_cols + ['label']]
    df_mix = df_mix[feature_cols + ['label']]

    df_all = pd.concat([df_mal, df_mix], ignore_index=True)
    print(f"合并后总样本数: {len(df_all)}，恶意样本: {df_all['label'].sum()}，非恶意样本: {(df_all['label']==0).sum()}")

    X = df_all[feature_cols].values
    y = df_all['label'].values.astype(int)

    print(f"特征数量: {X.shape[1]}")
    print(f"样本数量: {X.shape[0]}")
    print(f"标签分布: {np.bincount(y)}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"训练集大小: {X_train.shape}")
    print(f"测试集大小: {X_test.shape}")

    os.makedirs('models', exist_ok=True)

    print("\n=== 训练XGBoost模型 ===")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=1.0,
        random_state=42
    )
    xgb_model.fit(X_train, y_train)
    y_pred_xgb = xgb_model.predict(X_test)
    print("XGBoost模型评估:")
    print(f"准确率: {accuracy_score(y_test, y_pred_xgb):.3f}")
    print(f"精确率: {precision_score(y_test, y_pred_xgb):.3f}")
    print(f"召回率: {recall_score(y_test, y_pred_xgb):.3f}")
    print(f"F1分数: {f1_score(y_test, y_pred_xgb):.3f}")
    print("\n分类报告:")
    print(classification_report(y_test, y_pred_xgb))
    xgb_path = 'models/xgboost_model.pkl'
    joblib.dump(xgb_model, xgb_path)
    print(f"XGBoost模型已保存到: {xgb_path}")

    print("\n=== 训练Random Forest模型 ===")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight='balanced',
        random_state=42
    )
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)
    print("Random Forest模型评估:")
    print(f"准确率: {accuracy_score(y_test, y_pred_rf):.3f}")
    print(f"精确率: {precision_score(y_test, y_pred_rf):.3f}")
    print(f"召回率: {recall_score(y_test, y_pred_rf):.3f}")
    print(f"F1分数: {f1_score(y_test, y_pred_rf):.3f}")
    print("\n分类报告:")
    print(classification_report(y_test, y_pred_rf))
    rf_path = 'models/random_forest_model.pkl'
    joblib.dump(rf_model, rf_path)
    print(f"Random Forest模型已保存到: {rf_path}")

    model_info = {
        'feature_names': feature_cols,
        'scaler': scaler,
        'n_features': len(feature_cols)
    }
    info_path = 'models/model_info.pkl'
    joblib.dump(model_info, info_path)
    print(f"模型信息已保存到: {info_path}")

    print("\n=== 创建模型副本 ===")
    js_model_path = 'models/js_model.pkl'
    joblib.dump(xgb_model, js_model_path)
    print(f"JavaScript模型已保存到: {js_model_path}")
    py_model_path = 'models/py_model.pkl'
    joblib.dump(xgb_model, py_model_path)
    print(f"Python模型已保存到: {py_model_path}")
    cross_language_path = 'models/cross_language_model.pkl'
    joblib.dump(xgb_model, cross_language_path)
    print(f"跨语言模型已保存到: {cross_language_path}")
    print("\n=== 训练完成 ===")
    print("所有模型已保存到models目录")
    print("现在可以重新测试模型加载和预测功能了")

if __name__ == "__main__":
    train_models_from_csv() 