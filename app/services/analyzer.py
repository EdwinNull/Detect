import requests
from config import Config
from app.utils.helpers import get_setting
import markdown
import re
import random
import json

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key or get_setting('DEEPSEEK_API_KEY')
        self.api_url = get_setting('DEEPSEEK_API_URL', Config.DEEPSEEK_API_URL)
    
    def analyze_package(self, filename, features, xgboost_result):
        """使用DeepSeek进行深度分析"""
        # 确保xgboost_result包含所需的字段
        if 'prediction' not in xgboost_result:
            xgboost_result['prediction'] = 'benign'
        if 'confidence' not in xgboost_result:
            xgboost_result['confidence'] = 0.5
        if 'malicious_prob' not in xgboost_result:
            xgboost_result['malicious_prob'] = 0.0
        if 'risk_level' not in xgboost_result:
            xgboost_result['risk_level'] = 'medium'
        
        if not self.api_key:
            return self._fallback_analysis(xgboost_result)
        try:
            # 构建分析提示
            prompt = self._build_analysis_prompt(filename, features, xgboost_result)
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': 'deepseek-chat',
                'messages': [
                    {
                        'role': 'system',
                        'content': '你是一个专业的开源组件安全分析专家。你的任务是分析上传的开源组件包，识别其中可能存在的安全风险和恶意行为。请基于提供的特征数据进行深度分析，并给出详细的安全评估报告。'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 2048
            }
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                return self._parse_analysis(analysis)
            else:
                print(f"DeepSeek API错误: {response.status_code} - {response.text}")
                return self._fallback_analysis(xgboost_result)
                
        except Exception as e:
            print(f"DeepSeek分析错误: {e}")
            return self._fallback_analysis(xgboost_result)
    
    def _build_analysis_prompt(self, filename, features, xgboost_result):
        prompt = f"""请分析以下开源组件包的特征数据：

文件名：{filename}
文件数量：{features.get('file_count', 'N/A')}
总大小：{features.get('total_size', 'N/A')} 字节
平均文件大小：{features.get('avg_file_size', 'N/A')} 字节
目录深度：{features.get('directory_depth', 'N/A')}
可执行文件数：{features.get('executable_files', 'N/A')}
脚本文件数：{features.get('script_files', 'N/A')}
配置文件数：{features.get('config_files', 'N/A')}
可疑扩展名文件数：{features.get('suspicious_extensions', 'N/A')}
隐藏文件数：{features.get('hidden_files', 'N/A')}

XGBoost初筛结果：
- 判定：{xgboost_result['prediction']}
- 置信度：{xgboost_result['confidence']:.2%}
- 恶意概率：{xgboost_result['malicious_prob']:.2%}

请基于以上信息，提供详细的安全分析报告，包括：
1. 风险等级评估（低/中/高）
2. 具体风险点分析
3. 建议的处理措施

请用中文回复，格式要清晰易读。"""
        
        return prompt
    
    def _parse_analysis(self, analysis_text):
        """解析LLM返回的分析结果"""
        try:
            # 尝试提取风险级别
            risk_match = re.search(r'风险[级别评估]{0,2}[:：]\s*(高|中|低)', analysis_text)
            if risk_match:
                risk_level_map = {'高': 'high', '中': 'medium', '低': 'low'}
                risk_level = risk_level_map.get(risk_match.group(1), 'medium')
            else:
                # 如果没有直接提到风险级别，尝试基于关键词判断
                if re.search(r'严重|危险|恶意|高风险|critical', analysis_text, re.I):
                    risk_level = 'high'
                elif re.search(r'中等|警告|warning|可疑|潜在', analysis_text, re.I):
                    risk_level = 'medium'
                else:
                    risk_level = 'low'
            
            # 尝试提取置信度
            confidence_match = re.search(r'置信度[:：]?\s*(\d+\.?\d*)', analysis_text)
            confidence = float(confidence_match.group(1)) if confidence_match else 0.8
            
            # 确保置信度在0-1范围内
            confidence = max(0.0, min(1.0, confidence))
            
            # 尝试提取建议
            recommendation_match = re.search(r'建议[:：](.+?)(?=\n\n|\n#|\Z)', analysis_text, re.DOTALL)
            recommendation = recommendation_match.group(1).strip() if recommendation_match else '建议进行人工审查以确认安全性。'
            
            return {
                'risk_level': risk_level,
                'confidence': confidence,
                'analysis': self._format_analysis_text(analysis_text),
                'raw_analysis': analysis_text,
                'recommendation': recommendation
            }
        except Exception as e:
            print(f"解析分析结果错误: {e}")
            # 返回安全的默认值
            return {
                'risk_level': 'medium',
                'confidence': 0.5,
                'analysis': self._format_analysis_text(analysis_text),
                'raw_analysis': analysis_text,
                'recommendation': '建议进行人工审查以确认安全性。'
            }
    
    def _format_analysis_text(self, text):
        """格式化分析文本"""
        # 简单格式化，可以在这里添加更多HTML或Markdown格式化
        return text.replace('\n', '<br>')
    
    def _fallback_analysis(self, xgboost_result):
        """当API调用失败时的后备分析"""
        risk_level = xgboost_result.get('risk_level', 'medium')
        confidence = xgboost_result.get('confidence', 0.5)
        
        # 确保置信度在0-1范围内
        confidence = max(0.0, min(1.0, confidence))
        
        if xgboost_result.get('prediction') == 'malicious' or risk_level in ['high', 'medium']:
            analysis_text = '基于机器学习模型分析，该组件包存在安全风险。建议进行人工审查以确认潜在威胁。'
            if risk_level == 'high':
                analysis_text += '\n\n主要风险点包括：\n- 可能包含恶意代码\n- 可能执行未授权操作\n- 可能存在数据泄露风险'
                recommendation = '建议立即停止使用该组件，并寻找安全的替代方案。'
            else:
                analysis_text += '\n\n该包可能存在一些安全隐患，但风险程度有限。'
                recommendation = '建议在使用前进行详细的安全评估，并确保在受限环境中运行。'
        else:
            analysis_text = '基于机器学习模型分析，该组件包相对安全，未发现明显的恶意行为特征。'
            recommendation = '可以继续使用，但建议定期更新到最新版本以获取安全修复。'
        
        # 确保返回所有必要的字段
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis': self._format_analysis_text(analysis_text),
            'raw_analysis': analysis_text,
            'recommendation': recommendation
        }