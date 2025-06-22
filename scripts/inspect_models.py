import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb

def inspect_model(model_path, model_type):
    """检查模型文件的内容"""
    print(f"\n=== 检查 {model_path} ===")
    
    try:
        if model_path.endswith('.pkl'):
            model = joblib.load(model_path)
            print(f"模型类型: {type(model)}")
            
            if hasattr(model, 'feature_importances_'):
                print(f"特征重要性数量: {len(model.feature_importances_)}")
                print(f"前10个特征重要性: {model.feature_importances_[:10]}")
                
            if hasattr(model, 'n_features_in_'):
                print(f"输入特征数量: {model.n_features_in_}")
                
            if hasattr(model, 'classes_'):
                print(f"类别: {model.classes_}")
                
        elif model_path.endswith('.json'):
            model = xgb.XGBClassifier()
            model.load_model(model_path)
            print(f"模型类型: XGBoost")
            
            if hasattr(model, 'feature_importances_'):
                print(f"特征重要性数量: {len(model.feature_importances_)}")
                print(f"前10个特征重要性: {model.feature_importances_[:10]}")
                
            if hasattr(model, 'n_features_in_'):
                print(f"输入特征数量: {model.n_features_in_}")
                
            if hasattr(model, 'classes_'):
                print(f"类别: {model.classes_}")
                
    except Exception as e:
        print(f"加载模型时出错: {e}")

def analyze_csv_features():
    """分析CSV文件中的特征"""
    print("\n=== 分析 npm_feature_extracted.csv ===")
    
    try:
        df = pd.read_csv('npm_feature_extracted.csv')
        print(f"数据形状: {df.shape}")
        print(f"列名: {list(df.columns)}")
        
        # 检查是否有标签列
        if 'Package Name' in df.columns:
            print(f"包数量: {len(df)}")
            
        # 检查数值特征
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        print(f"数值特征数量: {len(numeric_cols)}")
        print(f"数值特征: {list(numeric_cols)}")
        
        # 检查是否有风险标签
        risk_indicators = [col for col in df.columns if 'risk' in col.lower() or 'malicious' in col.lower()]
        print(f"风险相关列: {risk_indicators}")
        
        # 显示前几行数据
        print("\n前3行数据:")
        print(df.head(3))
        
    except Exception as e:
        print(f"读取CSV文件时出错: {e}")

if __name__ == "__main__":
    # 检查所有模型文件
    model_files = [
        ('models/JS_monolanguage_model.pkl', 'JS模型'),
        ('models/Py_monolanguage_model.pkl', 'Python模型'),
        ('models/Crosslanguage_model.pkl', '跨语言模型'),
        ('models/xgboost_model.json', 'XGBoost模型')
    ]
    
    for model_path, model_type in model_files:
        inspect_model(model_path, model_type)
    
    # 分析CSV特征
    analyze_csv_features() 