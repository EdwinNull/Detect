import requests
from config import Config
from app.utils.helpers import get_setting
import markdown
import re

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key or get_setting('DEEPSEEK_API_KEY')
        self.api_url = get_setting('DEEPSEEK_API_URL', Config.DEEPSEEK_API_URL)
    
    def analyze_package(self, filename, features, xgboost_result):
        """使用DeepSeek进行深度分析"""
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
        """解析DeepSeek的分析结果"""
        # 简单的风险等级提取
        risk_level = 'medium'
        if '高风险' in analysis_text or '高危' in analysis_text:
            risk_level = 'high'
        elif '低风险' in analysis_text or '安全' in analysis_text:
            risk_level = 'low'
        
        # 计算置信度（基于文本长度和关键词）
        confidence = 0.7
        if len(analysis_text) > 200:
            confidence += 0.1
        if any(word in analysis_text for word in ['明显', '确定', '肯定']):
            confidence += 0.1
        if any(word in analysis_text for word in ['可能', '或许', '建议']):
            confidence -= 0.1
        
        confidence = max(0.5, min(0.95, confidence))
        
        # 转换分析文本格式
        formatted_analysis = self._format_analysis_text(analysis_text)
        
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis': formatted_analysis,  # 使用格式化后的HTML
            'raw_analysis': analysis_text,   # 保留原始文本
            'recommendation': '请参考分析报告中的建议措施'
        }
    
    def _format_analysis_text(self, analysis_text):
        """将分析文本从Markdown转换为HTML格式"""
        # 处理常见的分析格式问题
        # 确保标题格式正确
        analysis_text = re.sub(r'(?<!#)#(?!#)', '# ', analysis_text)
        
        # 确保列表项有空格
        analysis_text = re.sub(r'(?<!\n)\n-(?! )', '\n- ', analysis_text)
        
        try:
            # 转换Markdown为HTML
            html = markdown.markdown(analysis_text, extensions=['extra', 'nl2br'])
            
            # 添加CSS样式类
            html = html.replace('<h1>', '<h1 class="analysis-title">')
            html = html.replace('<h2>', '<h2 class="analysis-subtitle">')
            html = html.replace('<h3>', '<h3 class="analysis-section">')
            html = html.replace('<ul>', '<ul class="analysis-list">')
            html = html.replace('<p>', '<p class="analysis-paragraph">')
            
            # 添加高亮风险指示
            html = re.sub(r'(高风险|严重风险|Critical)', r'<span class="badge badge-danger">\1</span>', html)
            html = re.sub(r'(中风险|中等风险|Medium)', r'<span class="badge badge-warning">\1</span>', html)
            html = re.sub(r'(低风险|低危险|Low)', r'<span class="badge badge-info">\1</span>', html)
            
            return html
        except Exception as e:
            print(f"HTML格式化错误: {e}")
            # 如果转换出错，返回简单的格式化文本
            return f"<div>{analysis_text.replace('\n', '<br>')}</div>"
    
    def _fallback_analysis(self, xgboost_result):
        """当API调用失败时的后备分析"""
        if xgboost_result['prediction'] == 'malicious':
            return {
                'risk_level': 'high',
                'confidence': xgboost_result['confidence'],
                'analysis': '基于机器学习模型分析，该组件包存在安全风险。建议进一步人工审查。',
                'recommendation': '建议停止使用该组件，并寻找替代方案。'
            }
        else:
            return {
                'risk_level': 'low',
                'confidence': xgboost_result['confidence'],
                'analysis': '基于机器学习模型分析，该组件包相对安全。',
                'recommendation': '可以继续使用，但建议定期更新到最新版本。'
            }