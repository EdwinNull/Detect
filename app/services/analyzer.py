import requests
import json
import re
from config.config import Config
from app.utils.helpers import get_setting
from typing import Dict, Any

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        # 优先使用config.py中的API Key
        self.api_key = api_key or Config.DEEPSEEK_API_KEY
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        print(f"[DEBUG] DeepSeekAnalyzer initialization - API Key: {self.api_key}")
        print(f"[DEBUG] DeepSeekAnalyzer initialization - API URL: {self.api_url}")
    
    def analyze_package(self, filename, features, xgboost_result):
        """分析软件包的安全性"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            prompt = self._build_analysis_prompt(filename, features, xgboost_result)
            
            data = {
                'model': 'deepseek-chat',
                'messages': [
                    {'role': 'system', 'content': 'You are a professional open source component security analysis expert.'},
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0.3,
                'max_tokens': 2000
            }
            
            print(f"[DEBUG] about to send API request to: {self.api_url}")
            print(f"[DEBUG] headers: {headers}")
            print(f"[DEBUG] request data: {data}")
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            print(f"[DEBUG] API response status code: {response.status_code}")
            print(f"[DEBUG] API response headers: {dict(response.headers)}")
            print(f"[DEBUG] API response content: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"[DEBUG] API returned JSON: {result}")
                
                if 'choices' in result and len(result['choices']) > 0:
                    analysis = result['choices'][0]['message']['content']
                    print(f"[DEBUG] extracted analysis content: {analysis}")
                    
                    parsed_result = self._parse_analysis(analysis, xgboost_result)
                    print(f"[DEBUG] parsed result: {parsed_result}")
                    return parsed_result
                else:
                    print(f"[DEBUG] API returned format exception: {result}")
                    return self._fallback_analysis(xgboost_result)
            else:
                print(f"[DEBUG] DeepSeek API error: {response.status_code} - {response.text}")
                return self._fallback_analysis(xgboost_result)
                
        except requests.exceptions.Timeout:
            print("[DEBUG] API request timeout")
            return self._fallback_analysis(xgboost_result)
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] API request exception: {e}")
            return self._fallback_analysis(xgboost_result)
        except Exception as e:
            print(f"[DEBUG] DeepSeek analysis exception: {e}")
            import traceback
            print(f"[DEBUG] exception stack: {traceback.format_exc()}")
            return self._fallback_analysis(xgboost_result)
    
    def _convert_markdown_to_friendly_text(self, markdown_text):
        """将markdown格式的分析结果转换为友好的中文显示格式"""
        if not markdown_text:
            return "暂无分析结果"
        
        # 移除markdown分隔符
        text = re.sub(r'^---+$', '', markdown_text, flags=re.MULTILINE)
        
        # 转换标题
        text = re.sub(r'### 🛡️ (.+)', r'🔒 \1', text)
        text = re.sub(r'#### (\d+️⃣) (.+)', r'📋 \2', text)
        
        # 转换表格为更友好的格式
        def convert_table(match):
            table_content = match.group(0)
            # 移除表格标记
            table_content = re.sub(r'\|.*\|.*\|.*\|', '', table_content)
            table_content = re.sub(r'\|-+\|', '', table_content)
            # 提取表格内容并转换为列表
            lines = [line.strip() for line in table_content.split('\n') if line.strip() and '|' in line]
            result = []
            for line in lines:
                cells = [cell.strip() for cell in line.split('|') if cell.strip()]
                if len(cells) >= 3:
                    result.append(f"• {cells[0]}: {cells[1]} - {cells[2]}")
            return '\n'.join(result) if result else "暂无具体特征数据"
        
        text = re.sub(r'\|.*\|.*\|.*\|[\s\S]*?\|.*\|.*\|.*\|', convert_table, text)
        
        # 转换其他markdown格式
        text = re.sub(r'\*\*(.+?)\*\*', r'【\1】', text)  # 粗体
        text = re.sub(r'`(.+?)`', r'「\1」', text)  # 代码
        text = re.sub(r'> (.+)', r'💡 \1', text)  # 引用
        
        # 转换列表
        text = re.sub(r'^\s*-\s+(.+)$', r'• \1', text, flags=re.MULTILINE)
        text = re.sub(r'^\s*(\d+)\.\s+(.+)$', r'\1. \2', text, flags=re.MULTILINE)
        
        # 清理多余的空行
        text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
        
        # 添加中文说明
        text = text.replace('Judgment', '判断结果')
        text = text.replace('Confidence', '置信度')
        text = text.replace('Risk score', '风险分数')
        text = text.replace('Malicious', '恶意')
        text = text.replace('Benign', '良性')
        text = text.replace('High', '高风险')
        text = text.replace('Medium', '中风险')
        text = text.replace('Low', '低风险')
        text = text.replace('Risk level', '风险等级')
        text = text.replace('Main risk points', '主要风险点')
        text = text.replace('Security suggestions', '安全建议')
        text = text.replace('Suggestion', '建议')
        text = text.replace('Note', '注意')
        text = text.replace('This report is generated automatically by AI', '本报告由AI自动生成')
        text = text.replace('please combine manual security review', '请结合人工安全审查')
        
        return text.strip()
    
    def _build_analysis_prompt(self, filename, features, xgboost_result):
        # 提取关键特征用于分析
        key_features = {
            'file_size': features.get('file_size', 'N/A'),
            'Number of Words in source code': features.get('Number of Words in source code', 'N/A'),
            'Number of lines in source code': features.get('Number of lines in source code', 'N/A'),
            'Number of base64 chunks in source code': features.get('Number of base64 chunks in source code', 'N/A'),
            'Number of IP adress in source code': features.get('Number of IP adress in source code', 'N/A'),
            'Number of sospicious token in source code': features.get('Number of sospicious token in source code', 'N/A'),
            'shannon mean ID source code': features.get('shannon mean ID source code', 'N/A'),
            'shannon max ID source code': features.get('shannon max ID source code', 'N/A'),
            'plus ratio max': features.get('plus ratio max', 'N/A'),
            'eq ratio max': features.get('eq ratio max', 'N/A'),
            'bracket ratio max': features.get('bracket ratio max', 'N/A'),
        }
        # 修复：生成特征摘要
        feature_summary = '\n'.join([f'- {k}: {v}' for k, v in key_features.items()])

        prompt = f"""
请作为专业的开源组件安全分析专家，结合下方详细特征数据，分析该包可能存在的安全风险、恶意行为或可疑点，并说明理由：

- 文件名：{filename}
- 主要特征数据（仅展示部分）：
{feature_summary}

请严格按照以下结构输出：

### 1️⃣ 恶意类型判断
- **类型**：请根据特征和分析，判断该包最可能属于哪类恶意类型（如"信息窃取"、"远程控制"、"依赖混淆"、"挖矿脚本"、"后门木马"等），如无明显恶意可写"无明显恶意"
- **理由**：请用简明中文说明判断依据，需结合特征值（如"发现大量base64编码，且存在可疑网络请求，疑似信息窃取"）

### 2️⃣ 主要可疑特征（Top 5）
| 特征名称 | 数值 | 描述/风险点 |
|---|---|---|
| 示例：熵均值 | 0.72 | 代码混淆、变量名异常 |
| ... | ... | ... |

### 3️⃣ 风险等级评估
- **风险等级**：高/中/低
- **主要风险点**：1. ... 2. ...

### 4️⃣ 安全建议
- 建议1：...
- 建议2：...

> **注意**：所有内容请用中文输出，结构化展示，便于人工复核。

---
**【重要】** 如果你判断该包为恶意或存在高风险，请在下方额外提供一个JSON代码块，包含详细的恶意代码分析。如果无明显可疑代码则返回一个包含空字符串的JSON。格式如下：
```json
{{
  "code_location": "恶意代码所在的文件路径，例如 /lib/core.js",
  "malicious_action": "对恶意行为的总结，例如：通过异或运算解码base64内容并动态执行",
  "technical_details": "对采用的技术手法的总结，例如：采用多层混淆(base64+异或编码+动态执行)",
  "malicious_code_snippet": "最关键的可疑代码片段（5-10行）"
}}
```
"""

        # 追加结构化Markdown格式要求
        prompt += f'''
---
### 🛡️ 开源组件安全分析报告: {filename}

#### 1️⃣ XGBoost判断结果
- **判断结果**：{'恶意' if xgboost_result.get('prediction', 0) == 1 else '良性'}
- **置信度**：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
- **风险分数**：{xgboost_result.get('risk_score', 0.0):.3f}

#### 2️⃣ 主要可疑特征（Top 5）
请用下表展示最可疑的5个特征：

| 特征名称 | 数值 | 描述/风险点 |
|---|---|---|
| 示例：熵均值 | 0.72 | 代码混淆、变量名异常 |
| ... | ... | ... |

#### 3️⃣ 风险等级评估
- **风险等级**：高/中/低
- **主要风险点**：
  1. ...
  2. ...

#### 4️⃣ 安全建议
- 建议1：...
- 建议2：...

#### 5️⃣ 恶意包类型判断
- 类型：请根据特征和分析，判断该包最可能属于哪类恶意类型（如"信息窃取"、"远程控制"、"依赖混淆"、"挖矿脚本"、"后门木马"等），如无明显恶意可写"无明显恶意"
- 理由：请用一句话说明判断依据

---

> **注意**：本报告由AI自动生成，请结合人工安全审查。

请严格使用Markdown分级标题（###、####）、表格、列表、加粗等结构化格式，避免输出大段无结构文本。所有内容请用中文输出。'''
        return prompt
    
    def _parse_analysis(self, analysis_text, xgboost_result=None):
        """(Robustly)解析LLM的分析结果，并提取所有相关字段"""
        print("-" * 80)
        print("[RAW AI RESPONSE]:")
        print(analysis_text)
        print("-" * 80)

        # Initialize defaults
        malicious_code_info = {
            "code_location": "", "malicious_action": "", "technical_details": "", "malicious_code_snippet": ""
        }
        mal_type = '未知'
        mal_reason = '无'
        risk_level = '未知'
        risk_points = 'AI未提供详细风险点'
        advice_list = []
        top_features = []
        
        # 1. Extract JSON blob first
        try:
            match = re.search(r'```json\s*(\{.*?\})\s*```', analysis_text, re.DOTALL)
            if match:
                json_str = match.group(1)
                data = json.loads(json_str)
                malicious_code_info["code_location"] = data.get("code_location", "")
                malicious_code_info["malicious_action"] = data.get("malicious_action", "")
                malicious_code_info["technical_details"] = data.get("technical_details", "")
                malicious_code_info["malicious_code_snippet"] = data.get("malicious_code_snippet", "")
                analysis_text = analysis_text.replace(match.group(0), "")
        except (json.JSONDecodeError, IndexError) as e:
            print(f"[DEBUG] Failed to parse malicious code snippet JSON: {e}")

        # 2. Split analysis text into sections for robust parsing
        sections = re.split(r'###\s*', analysis_text)
        
        for section in sections:
            section_title = section.split('\n')[0].strip()

            # Parse "恶意类型判断" section
            if '恶意类型判断' in section_title:
                type_match = re.search(r'\*\*?类型\*\*?\s*[:：]\s*(.+)', section)
                if type_match: mal_type = type_match.group(1).strip()
                
                reason_match = re.search(r'\*\*?理由\*\*?\s*[:：]\s*(.+)', section)
                if reason_match: mal_reason = reason_match.group(1).strip()

            # Parse "主要可疑特征" section
            elif '主要可疑特征' in section_title:
                rows = re.findall(r'\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|', section)
                for name, value, desc in rows:
                    name, value, desc = name.strip(), value.strip(), desc.strip()
                    if '特征名称' not in name and '---' not in name and name:
                        top_features.append({'name': name, 'value': value, 'desc': desc})
            
            # Parse "风险等级评估" section
            elif '风险等级评估' in section_title:
                level_match = re.search(r'\*\*?风险等级\*\*?\s*[:：]\s*(高|中|低)', section)
                if level_match: 
                    chinese_level = level_match.group(1).strip()
                    # 将中文风险等级转换为英文
                    if chinese_level == '高':
                        risk_level = 'high'
                    elif chinese_level == '中':
                        risk_level = 'medium'
                    elif chinese_level == '低':
                        risk_level = 'low'
                    else:
                        risk_level = 'unknown'

                points_match = re.search(r'\*\*?主要风险点\*\*?\s*[:：]([\s\S]*)', section)
                if points_match: 
                    risk_points = points_match.group(1).strip()
            
            # Parse "安全建议" section
            elif '安全建议' in section_title:
                advice_text_match = re.search(r'安全建议\s*[:：]([\s\S]*)', section)
                if advice_text_match:
                    advice_text = advice_text_match.group(1).strip()
                    advice_list = [adv.strip('- ').strip() for adv in advice_text.split('\n') if adv.strip() and not adv.strip().isspace()]

        # Combine final result
        risk_explanation = f"风险等级: {risk_level}\n主要风险点:\n{risk_points}"

        final_result = {
            'risk_level': risk_level,
            'confidence': xgboost_result.get('confidence', 0.5),
            'type': mal_type,
            'reason': mal_reason,
            'top_features': top_features,
            'risk_points': risk_points,
            'advice_list': advice_list,
            'raw_analysis': analysis_text,
            'risk_explanation': risk_explanation,
            'llm_result': self._convert_markdown_to_friendly_text(analysis_text)
        }
        final_result.update(malicious_code_info)
        
        return final_result
    
    def _fallback_analysis(self, xgboost_result):
        """在API调用失败或超时的情况下，提供基于XGBoost的备用分析结果"""
        print("[DEBUG] using fallback analysis")
        
        # 根据XGBoost结果生成分析文本
        if xgboost_result.get('prediction', 0) == 1:
            analysis_text = f"""🔒 开源组件安全分析报告

📋 XGBoost判断结果
• 判断结果：恶意
• 置信度：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
• 风险分数：{xgboost_result.get('risk_score', 0.0):.3f}

📋 主要风险点
• 机器学习模型识别为高风险组件
• 建议进行进一步的人工审查以确认是否存在恶意代码或安全漏洞

📋 安全建议
• 立即停止使用该组件
• 检查已部署的应用是否受影响
• 寻找安全的替代组件
• 将该组件报告给相应的包管理平台

💡 注意：本报告由AI自动生成，请结合人工安全审查"""
            risk_level = 'high'
        else:
            analysis_text = f"""🔒 开源组件安全分析报告

📋 XGBoost判断结果
• 判断结果：良性
• 置信度：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
• 风险分数：{xgboost_result.get('risk_score', 0.0):.3f}

📋 安全评估
• 机器学习模型分析显示该组件包相对安全
• 未发现明显的恶意行为或安全漏洞

📋 安全建议
• 建议定期更新到最新版本以确保安全
• 保持对组件包的持续监控
• 关注官方安全公告

💡 注意：本报告由AI自动生成，请结合人工安全审查"""
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'confidence': xgboost_result.get('confidence', 0.5),
            'analysis': analysis_text,
            'raw_analysis': analysis_text,
            'recommendation': '建议结合人工审查和定期安全更新'
        }