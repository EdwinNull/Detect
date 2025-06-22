import os
import json
import sqlite3
import hashlib
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from flask import current_app, g
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import joblib
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

# 导入配置
from config.config import Config

class SecurityClassifier:
    def __init__(self, model_type='xgboost'):
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        # 修正模型文件名拼接
        self.model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'models', f'{model_type}.pkl')
        
        # 基于CSV数据的特征名称列表 (对应npm_feature_extracted.csv的列名)
        self.feature_names = [
            'Number of Words in source code', 'Number of lines in source code',
            'plus ratio mean', 'plus ratio max', 'plus ratio std', 'plus ratio q3',
            'eq ratio mean', 'eq ratio max', 'eq ratio std', 'eq ratio q3',
            'bracket ratio mean', 'bracket ratio max', 'bracket ratio std', 'bracket ratio q3',
            'Number of base64 chunks in source code', 'Number of IP adress in source code', 'Number of sospicious token in source code',
            'Number of Words in metadata', 'Number of lines in metadata', 'Number of base64 chunks in metadata', 'Number of IP adress in metadata', 'Number of sospicious token in metadata',
            '.bat', '.bz2', '.c', '.cert', '.conf', '.cpp', '.crt', '.css', '.csv', '.deb', '.erb', '.gemspec', '.gif', '.gz', '.h', '.html', '.ico', '.ini', '.jar', '.java', '.jpg', '.js', '.json', '.key', '.m4v', '.markdown', '.md', '.pdf', '.pem', '.png', '.ps', '.py', '.rb', '.rpm', '.rst', '.sh', '.svg', '.toml', '.ttf', '.txt', '.xml', '.yaml', '.yml', '.eot', '.exe', '.jpeg', '.properties', '.sql', '.swf', '.tar', '.woff', '.woff2', '.aac', '.bmp', '.cfg', '.dcm', '.dll', '.doc', '.flac', '.flv', '.ipynb', '.m4a', '.mid', '.mkv', '.mp3', '.mp4', '.mpg', '.ogg', '.otf', '.pickle', '.pkl', '.psd', '.pxd', '.pxi', '.pyc', '.pyx', '.r', '.rtf', '.so', '.sqlite', '.tif', '.tp', '.wav', '.webp', '.whl', '.xcf', '.xz', '.zip', '.mov', '.wasm', '.webm',
            'repository', 'presence of installation script',
            'shannon mean ID source code', 'shannon std ID source code', 'shannon max ID source code', 'shannon q3 ID source code',
            'shannon mean string source code', 'shannon std string source code', 'shannon max string source code', 'shannon q3 string source code',
            'homogeneous identifiers in source code', 'homogeneous strings in source code', 'heteregeneous identifiers in source code', 'heterogeneous strings in source code', 'URLs in source code',
            'shannon mean ID metadata', 'shannon std ID metadata', 'shannon max ID metadata', 'shannon q3 ID metadata',
            'shannon mean string metadata', 'shannon std string metadata', 'shannon max string metadata', 'shannon q3 string metadata',
            'homogeneous identifiers in metadata', 'homogeneous strings in metadata', 'heterogeneous strings in metadata', 'URLs in metadata', 'heteregeneous identifiers in metadata'
        ]
        
        self.feature_groups = {}
        # 初始化特征权重
        self.feature_weights = {
            'security': 0.3,
            'entropy': 0.2,
            'structure': 0.15,
            'content': 0.15,
            'dependencies': 0.1,
            'metadata': 0.1
        }
        # 初始化风险阈值
        self.risk_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
        
        print(f"特征总数: {len(self.feature_names)}")
        self._initialize_model()
    
    def _initialize_model(self):
        """初始化模型"""
        print(f"正在初始化{self.model_type}模型...")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"模型加载路径: {self.model_path}")
        if self.model_type in ['js_model', 'py_model', 'cross_language', 'xgboost']:
            if os.path.exists(self.model_path):
                try:
                    self.model = joblib.load(self.model_path)
                    self.is_trained = True
                    print(f"成功加载{self.model_type}模型: {self.model_path}")
                    print(f"[DEBUG] 加载的模型对象: {self.model}")
                    return
                except Exception as e:
                    print(f"加载模型失败: {str(e)}")
            else:
                print(f"模型文件不存在: {self.model_path}")
            print(f"无法找到{self.model_type}模型文件，使用默认XGBoost模型")
            import xgboost as xgb
            self.model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                scale_pos_weight=2.0,
                random_state=42
            )
        else:
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=8,
                class_weight='balanced',
                random_state=42
            )
    
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
            print("没有足够的训练数据，使用基于规则的初始化数据")
            self._train_with_rule_based_data()
            return
        
        # 准备训练数据
        X = []
        y = []
        for features, risk_level in data:
            try:
                feature_dict = json.loads(features)
                # 确保特征向量的长度正确
                feature_vector = []
                for feature in self.feature_names:
                    value = feature_dict.get(feature, 0)
                    # 确保特征值为数值类型
                    try:
                        if isinstance(value, (int, float)):
                            feature_vector.append(float(value))
                        elif isinstance(value, bool):
                            feature_vector.append(1.0 if value else 0.0)
                        elif isinstance(value, str):
                            value_lower = value.lower() if value else ''
                            if value_lower in ['true', 'yes', 'on', 'enabled']:
                                feature_vector.append(1.0)
                            elif value_lower in ['false', 'no', 'off', 'disabled']:
                                feature_vector.append(0.0)
                            else:
                                feature_vector.append(float(len(value)) / 1000.0)
                        elif isinstance(value, (dict, list, tuple, set)):
                            feature_vector.append(float(len(value)) / 100.0)
                        else:
                            feature_vector.append(0.0)
                    except (ValueError, TypeError):
                        feature_vector.append(0.0)
                
                if len(feature_vector) == len(self.feature_names):
                    X.append(feature_vector)
                    y.append(1 if risk_level == 'high' else 0)
            except Exception as e:
                print(f"处理训练数据时出错: {e}")
                continue
        
        if len(X) < 10:
            print("训练数据不足，使用基于规则的初始化数据")
            self._train_with_rule_based_data()
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
    
    def _train_with_rule_based_data(self):
        """使用基于规则的数据训练模型"""
        n_samples = 1000
        n_features = len(self.feature_names)  # 使用实际的特征数量
        
        # 生成基于规则的训练数据
        X = []
        y = []
        
        for _ in range(n_samples):
            features = np.zeros(n_features)
            feature_dict = {}
            
            # 基本文件特征
            features[0] = np.random.randint(1, 100)  # file_count
            features[1] = np.random.randint(1000, 10000000)  # total_size
            features[2] = features[1] / features[0]  # avg_file_size
            features[3] = features[1]  # max_file_size
            features[4] = np.random.randint(1, 10)  # directory_depth
            features[5] = np.random.randint(0, 5)  # executable_files
            features[6] = np.random.randint(0, 10)  # script_files
            features[7] = np.random.randint(0, 5)  # config_files
            features[8] = np.random.uniform(0, 8)  # entropy_avg
            features[9] = np.random.uniform(0, 8)  # entropy_max
            features[10] = np.random.randint(0, 3)  # suspicious_extensions
            features[11] = np.random.randint(0, 3)  # hidden_files
            features[12] = np.random.randint(0, 5)  # large_files
            features[13] = np.random.randint(0, 3)  # compressed_files
            features[14] = np.random.randint(0, 5)  # binary_files
            features[15] = np.random.randint(0, 10)  # text_files
            
            # 项目结构特征
            for i in range(16, 36):  # 20个项目结构特征
                features[i] = np.random.randint(0, 2)  # 二元特征
            
            # 代码分析特征
            for i in range(36, 61):  # 25个代码分析特征
                if i < 46:  # 前10个特征可能有多个实例
                    features[i] = np.random.randint(0, 5)
                else:  # 后15个特征通常是二元的
                    features[i] = np.random.randint(0, 2)
            
            # 依赖分析特征
            for i in range(61, 81):  # 20个依赖特征
                if i < 71:  # 前10个特征是数值型
                    features[i] = np.random.randint(0, 10)
                else:  # 后10个特征是二元的
                    features[i] = np.random.randint(0, 2)
            
            # 文件内容特征
            for i in range(81, 111):  # 30个内容特征
                if i < 91:  # 前10个特征是比率或数值
                    features[i] = np.random.uniform(0, 1)
                elif i < 101:  # 中间10个特征是计数
                    features[i] = np.random.randint(0, 20)
                else:  # 后10个特征是二元的
                    features[i] = np.random.randint(0, 2)
            
            # 安全相关特征
            for i in range(111, 140):  # 29个安全特征
                if i < 121:  # 前10个特征可能有多个实例
                    features[i] = np.random.randint(0, 5)
                elif i < 131:  # 中间10个特征是风险评分
                    features[i] = np.random.uniform(0, 1)
                else:  # 后9个特征是二元的
                    features[i] = np.random.randint(0, 2)
            
            # 将特征数组转换为字典
            for i, name in enumerate(self.feature_names):
                feature_dict[name] = float(features[i])
            
            # 计算风险分数
            risk_score = self._calculate_risk_score(feature_dict)
            
            X.append(features)
            y.append(1 if risk_score > 0.6 else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # 训练模型
        self.model.fit(X, y)
        self.is_trained = True
        
        # 计算交叉验证分数
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        print(f"模型训练完成，交叉验证准确率: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    def predict(self, features):
        """预测包的风险等级 - 基于CSV数据优化"""
        print(f"[DEBUG] 当前模型类型: {self.model_type}, is_trained: {self.is_trained}, model: {self.model}")
        
        # 添加知名包白名单检查
        print(f"[DEBUG] 开始白名单检查...")
        if self._is_whitelisted_package(features):
            print("检测到知名包，直接标记为安全")
            return {
                'prediction': 0,
                'confidence': 0.9,
                'risk_score': 0.1,
                'risk_level': 'safe',
                'feature_importance': {}
            }
        
        print(f"[DEBUG] 白名单检查未通过，继续模型预测")
        
        if not self.is_trained:
            print("模型未训练，使用基于规则的风险评分")
            # 直接使用基于规则的风险评分，不依赖训练好的模型
            risk_score = self._calculate_csv_based_risk_score(features, 0.5)  # 默认置信度0.5
            risk_level = self._get_risk_level(risk_score)
            
            result = {
                'prediction': 1 if risk_score > 0.5 else 0,  # 基于风险分数判断
                'confidence': 0.5,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'feature_importance': {}
            }
            
            print(f"基于规则预测结果: 风险等级={risk_level}, 风险分数={risk_score:.3f}")
            # 只要risk_level为safe，prediction强制为0
            if result['risk_level'] == 'safe':
                result['prediction'] = 0
            return result
        
        try:
            # 提取特征向量
            feature_vector = []
            expected_features = len(self.feature_names)
            
            print(f"期望特征数量: {expected_features}")
            print(f"输入特征数量: {len(features)}")
            
            # 按特征名称顺序处理特征
            for feature in self.feature_names:
                value = features.get(feature, 0)
                try:
                    if isinstance(value, (int, float)):
                        feature_vector.append(float(value))
                    elif isinstance(value, bool):
                        feature_vector.append(1.0 if value else 0.0)
                    elif isinstance(value, str):
                        value_lower = value.lower() if value else ''
                        if value_lower in ['true', 'yes', 'on', 'enabled']:
                            feature_vector.append(1.0)
                        elif value_lower in ['false', 'no', 'off', 'disabled']:
                            feature_vector.append(0.0)
                        else:
                            feature_vector.append(float(len(value)) / 1000.0)
                    elif isinstance(value, (dict, list, tuple, set)):
                        feature_vector.append(float(len(value)) / 100.0)
                    else:
                        feature_vector.append(0.0)
                except (ValueError, TypeError):
                    feature_vector.append(0.0)
            
            if len(feature_vector) != expected_features:
                print(f"特征向量长度不匹配: 期望{expected_features}, 实际{len(feature_vector)}")
                # 补齐或截断特征向量
                if len(feature_vector) < expected_features:
                    feature_vector.extend([0.0] * (expected_features - len(feature_vector)))
                else:
                    feature_vector = feature_vector[:expected_features]
            
            # 使用模型进行预测
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba([feature_vector])[0]
                prediction = 1 if proba[1] > 0.5 else 0
                confidence = max(proba)
                risk_score = proba[1]  # 恶意类的概率
            else:
                prediction = self.model.predict([feature_vector])[0]
                confidence = 0.8  # 默认置信度
                risk_score = 0.8 if prediction == 1 else 0.2
            
            # 计算风险等级
            risk_level = self._get_risk_level(risk_score)
            
            # 获取特征重要性
            feature_importance = self._get_feature_importance(features)
            
            result = {
                'prediction': int(prediction),
                'confidence': float(confidence),
                'risk_score': float(risk_score),
                'risk_level': risk_level,
                'feature_importance': feature_importance
            }
            # 只要risk_level为safe，prediction强制为0
            if result['risk_level'] == 'safe':
                result['prediction'] = 0
            print(f"[DEBUG] 模型预测结果: {result}")
            return result
            
        except Exception as e:
            print(f"[DEBUG] 模型预测异常: {str(e)}")
            # 如果模型预测失败，使用基于规则的风险评分
            risk_score = self._calculate_csv_based_risk_score(features, 0.5)
            risk_level = self._get_risk_level(risk_score)
            
            result = {
                'prediction': 1 if risk_score > 0.5 else 0,
                'confidence': 0.5,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'feature_importance': {}
            }
            # 只要risk_level为safe，prediction强制为0
            if result['risk_level'] == 'safe':
                result['prediction'] = 0
            print(f"[DEBUG] 异常处理后的结果: {result}")
            return result
    
    def _calculate_csv_based_risk_score(self, features, model_proba):
        """基于CSV数据的风险评分计算"""
        try:
            # 检查是否为大型知名包
            py_files = features.get('.py', 0)
            total_lines = features.get('Number of lines in source code', 0)
            base64_chunks = features.get('Number of base64 chunks in source code', 0)
            suspicious_tokens = features.get('Number of sospicious token in source code', 0)
            
            # 如果是大型Python项目（如pandas），使用更宽松的评分
            is_large_python_project = (py_files > 1000 and total_lines > 500000)
            
            # 基础风险分数
            base_score = model_proba
            
            # 安全特征权重
            security_score = 0.0
            security_features = [
                'Number of base64 chunks in source code',
                'Number of IP adress in source code',
                'Number of sospicious token in source code',
                'Number of base64 chunks in metadata',
                'Number of IP adress in metadata',
                'Number of sospicious token in metadata'
            ]
            
            for feature in security_features:
                value = features.get(feature, 0)
                if isinstance(value, (int, float)) and value > 0:
                    # 对大型项目使用更宽松的阈值
                    if is_large_python_project:
                        security_score += min(value / 50.0, 1.0)  # 更宽松的归一化
                    else:
                        security_score += min(value / 10.0, 1.0)
            
            security_score = min(security_score / len(security_features), 1.0)
            
            # 熵特征权重
            entropy_score = 0.0
            entropy_features = [
                'shannon mean ID source code',
                'shannon max ID source code',
                'shannon mean string source code',
                'shannon max string source code'
            ]
            
            for feature in entropy_features:
                value = features.get(feature, 0)
                if isinstance(value, (int, float)) and value > 0:
                    # 对大型项目使用更宽松的阈值
                    if is_large_python_project:
                        entropy_score += min(value / 4.0, 1.0)  # 更宽松的归一化
                    else:
                        entropy_score += min(value / 2.0, 1.0)
            
            entropy_score = min(entropy_score / len(entropy_features), 1.0)
            
            # 可疑文件类型权重
            suspicious_file_score = 0.0
            suspicious_files = ['.exe', '.dll', '.so', '.bat', '.sh']  # 移除.pyc, .pkl, .pickle
            
            for file_type in suspicious_files:
                value = features.get(file_type, 0)
                if isinstance(value, (int, float)) and value > 0:
                    suspicious_file_score += min(value / 5.0, 1.0)
            
            suspicious_file_score = min(suspicious_file_score / len(suspicious_files), 1.0)
            
            # 字符比率异常权重
            ratio_score = 0.0
            ratio_features = [
                'plus ratio max', 'eq ratio max', 'bracket ratio max'
            ]
            
            for feature in ratio_features:
                value = features.get(feature, 0)
                if isinstance(value, (int, float)) and value > 0.01:  # 阈值0.01
                    ratio_score += min(value * 10, 1.0)
            
            ratio_score = min(ratio_score / len(ratio_features), 1.0)
            
            # 综合风险评分 - 对大型项目使用更宽松的权重
            if is_large_python_project:
                final_score = (
                    base_score * 0.3 +           # 降低模型预测权重
                    security_score * 0.2 +       # 降低安全特征权重
                    entropy_score * 0.05 +       # 大幅降低熵特征影响
                    suspicious_file_score * 0.1 + # 保持可疑文件权重
                    ratio_score * 0.0            # 移除字符比率影响
                )
                # 对大型项目应用更温和的非线性变换
                final_score = final_score ** 0.8
                # 进一步降低风险分数
                final_score = min(final_score * 0.7, 1.0)
            else:
                final_score = (
                    base_score * 0.5 +           # 从0.4提高到0.5，更依赖模型预测
                    security_score * 0.3 +       # 从0.25提高到0.3，更重视安全特征
                    entropy_score * 0.1 +        # 从0.15降低到0.1，减少熵特征影响
                    suspicious_file_score * 0.1 + # 保持0.1
                    ratio_score * 0.0            # 从0.1降低到0.0，移除字符比率影响
                )
                # 应用非线性变换来放大风险
                final_score = final_score ** 1.2
                # 进一步放大风险分数
                final_score = min(final_score * 1.5, 1.0)
            
            return min(final_score, 1.0)
            
        except Exception as e:
            print(f"风险评分计算错误: {str(e)}")
            return model_proba
    
    def _calculate_risk_score(self, features):
        """计算风险分数"""
        try:
            total_score = 0
            total_weight = 0
            
            # 遍历特征组
            for group, group_features in self.feature_groups.items():
                group_score = 0
                feature_count = 0
                
                # 计算组内特征的平均分数
                for feature in group_features:
                    if feature in features:
                        value = features[feature]
                        if isinstance(value, (int, float)):
                            # 归一化特征值到0-1范围
                            normalized_value = min(max(value, 0), 1)
                            group_score += normalized_value
                            feature_count += 1
                
                # 计算组内平均分数
                if feature_count > 0:
                    group_score /= feature_count
                    
                    # 对安全相关特征使用平方变换
                    if group == 'security':
                        group_score = group_score ** 2
                    
                    # 应用组权重
                    weight = self.feature_weights.get(group, 0.1)
                    total_score += group_score * weight
                    total_weight += weight
            
            # 计算最终分数
            if total_weight > 0:
                final_score = total_score / total_weight
                # 使用非线性变换放大风险分数
                final_score = final_score ** 1.5
                return min(final_score, 1.0)
            
            return 0.0
            
        except Exception as e:
            print(f"风险分数计算错误: {str(e)}")
            return 0.0

    def _get_risk_level(self, risk_score):
        """根据风险分数确定风险等级"""
        if risk_score >= self.risk_thresholds['high']:
            return 'high'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'medium'
        elif risk_score >= self.risk_thresholds['low']:
            return 'low'
        else:
            return 'safe'

    def _get_feature_importance(self, features):
        """获取特征重要性"""
        try:
            importance = {}
            
            # 简化版本：直接基于特征权重计算重要性
            for group, weight in self.feature_weights.items():
                # 计算该组特征的平均值
                group_features = []
                for feature_name in features.keys():
                    feature_name_str = str(feature_name).lower() if feature_name is not None else ''
                    if group in feature_name_str:  # 简单匹配
                        value = features.get(feature_name, 0)
                        if isinstance(value, (int, float)):
                            group_features.append(value)
                
                if group_features:
                    avg_value = sum(group_features) / len(group_features)
                    importance[group] = avg_value * weight
                else:
                    importance[group] = 0.0
            
            return importance
            
        except Exception as e:
            print(f"特征重要性计算错误: {str(e)}")
            return {}

    def retrain(self):
        """重新训练模型"""
        self._train_model()
        return True

    def _is_whitelisted_package(self, features):
        """检查是否为知名安全包"""
        print(f"[DEBUG] 开始白名单检查，特征数量: {len(features)}")
        
        # 知名开源包白名单
        whitelisted_packages = {
            'pandas', 'numpy', 'matplotlib', 'scipy', 'scikit-learn', 'tensorflow', 'pytorch',
            'requests', 'urllib3', 'beautifulsoup4', 'lxml', 'pillow', 'opencv-python',
            'flask', 'django', 'fastapi', 'sqlalchemy', 'pymongo', 'redis',
            'jupyter', 'ipython', 'notebook', 'pytest', 'unittest', 'coverage',
            'black', 'flake8', 'mypy', 'isort', 'pre-commit', 'tox',
            'setuptools', 'wheel', 'pip', 'virtualenv', 'conda', 'poetry'
        }
        
        # 检查包名特征（如果有的话）
        package_name_raw = features.get('package_name')
        package_name = str(package_name_raw).lower() if package_name_raw is not None else ''
        
        print(f"[DEBUG] 原始包名: {package_name_raw}")
        print(f"[DEBUG] 处理后的包名: {package_name}")
        
        if package_name:
            print(f"检查包名: {package_name}")
            # 完全匹配
            if package_name in whitelisted_packages:
                print(f"包 {package_name} 在白名单中")
                return True
            # 部分匹配（处理版本号等情况）
            for wp in whitelisted_packages:
                if package_name.startswith(wp + '-') or package_name == wp:
                    print(f"包 {package_name} 匹配白名单项 {wp}")
                    return True
        
        # 检查其他特征组合，判断是否为知名包
        # 例如：大量.py文件 + 高代码行数 + 低安全风险特征
        py_files = features.get('.py', 0)
        total_lines = features.get('Number of lines in source code', 0)
        base64_chunks = features.get('Number of base64 chunks in source code', 0)
        ip_addresses = features.get('Number of IP adress in source code', 0)
        suspicious_tokens = features.get('Number of sospicious token in source code', 0)
        
        print(f"[DEBUG] 特征统计: py_files={py_files}, total_lines={total_lines}")
        print(f"[DEBUG] 安全特征: base64={base64_chunks}, ip={ip_addresses}, suspicious={suspicious_tokens}")
        
        # 兜底：超大型Python项目直接判定为安全
        if py_files > 1000 and total_lines > 500000:
            print("超大型Python项目兜底判定为安全")
            return True
        
        print(f"不在白名单中: {package_name}")
        print(f"特征统计: py_files={py_files}, total_lines={total_lines}")
        print(f"安全特征: base64={base64_chunks}, ip={ip_addresses}, suspicious={suspicious_tokens}")
        return False