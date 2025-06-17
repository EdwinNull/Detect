import os
import numpy as np
import xgboost as xgb
import joblib
import sqlite3
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from config import Config

class SecurityClassifier:
    def __init__(self, model_type='xgboost'):
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        self.model_path = 'models/security_model.json'
        self._initialize_model()
    
    def _initialize_model(self):
        """初始化模型"""
        if self.model_type == 'xgboost':
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42
            )
        else:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # 尝试加载已训练的模型
        if os.path.exists(self.model_path):
            try:
                if self.model_type == 'xgboost':
                    self.model.load_model(self.model_path)
                else:
                    self.model = joblib.load(self.model_path)
                self.is_trained = True
                print("已加载预训练模型")
            except Exception as e:
                print(f"加载模型失败: {e}")
                self._train_model()
        else:
            self._train_model()
    
    def _train_model(self):
        """训练模型"""
        print("开始训练模型...")
        # 从数据库加载训练数据                                                         
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # 获取所有已标记的扫描记录
        cursor.execute('''
            SELECT f.feature_data, s.risk_level
            FROM features f
            JOIN scan_records s ON f.scan_id = s.id
            WHERE s.risk_level IS NOT NULL
        ''')
        
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            print("没有足够的训练数据，使用模拟数据")
            self._train_with_synthetic_data()
            return
        
        # 准备训练数据
        X = []
        y = []
        for features, risk_level in data:
            try:
                feature_dict = json.loads(features)
                X.append(list(feature_dict.values()))
                y.append(1 if risk_level == 'high' else 0)
            except Exception as e:
                print(f"处理训练数据时出错: {e}")
                continue
        
        if len(X) < 10:
            print("训练数据不足，使用模拟数据")
            self._train_with_synthetic_data()
            return
        
        X = np.array(X)
        y = np.array(y)
        
        # 分割训练集和验证集
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # 训练模型
        self.model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = self.model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        precision = precision_score(y_val, y_pred)
        recall = recall_score(y_val, y_pred)
        f1 = f1_score(y_val, y_pred)
        
        print(f"模型评估结果:")
        print(f"准确率: {accuracy:.3f}")
        print(f"精确率: {precision:.3f}")
        print(f"召回率: {recall:.3f}")
        print(f"F1分数: {f1:.3f}")
        
        # 保存模型
        os.makedirs('models', exist_ok=True)
        if self.model_type == 'xgboost':
            self.model.save_model(self.model_path)
        else:
            joblib.dump(self.model, self.model_path)
        
        self.is_trained = True
        print("模型训练完成并保存")
    
    def _train_with_synthetic_data(self):
        """使用模拟数据训练模型"""
        np.random.seed(42)
        n_samples = 1000
        n_features = 141
        
        X = np.random.random((n_samples, n_features))
        y = []
        for i in range(n_samples):
            risk_score = (X[i, 0] * 0.3 + X[i, 5] * 0.4 + X[i, 10] * 0.3)
            y.append(1 if risk_score > 0.6 else 0)
        
        y = np.array(y)
        self.model.fit(X, y)
        self.is_trained = True
        
        # 计算交叉验证分数
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        print(f"模型训练完成，交叉验证准确率: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    def predict(self, features):
        """预测包的风险等级"""
        if not self.is_trained:
            self._train_model()
        
        # 转换特征为数组
        feature_array = np.array([list(features.values())]).reshape(1, -1)
        
        # 预测
        prediction = self.model.predict(feature_array)[0]
        confidence = self.model.predict_proba(feature_array)[0]
        
        result = {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(max(confidence)),
            'malicious_prob': float(confidence[1]) if len(confidence) > 1 else 0.0,
            'benign_prob': float(confidence[0])
        }
        
        return result
    
    def retrain(self):
        """重新训练模型"""
        self._train_model()
        return True