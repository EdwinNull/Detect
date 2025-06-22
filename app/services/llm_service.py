import requests
import json
import logging
from config import Config
from app.utils.helpers import get_setting

class LLMService:
    """
    统一的大语言模型服务接口，支持多种LLM API
    """
    
    def __init__(self, provider=None, api_key=None):
        """
        初始化LLM服务
        provider: 'deepseek', 'claude', 'gpt', 'gemini' 其中之一
        api_key: 如果不提供，则从配置或数据库中获取
        """
        # 获取默认提供商，如果未指定则从数据库或配置获取
        self.provider = provider or get_setting('LLM_PROVIDER', 'deepseek')
        
        # API端点和认证配置
        self._init_provider_settings(api_key)
        
        logging.info(f"[LLM服务] 初始化 {self.provider} API")
    
    def _init_provider_settings(self, custom_api_key=None):
        """根据提供商配置API端点和认证信息"""
        if self.provider == 'deepseek':
            self.api_key = custom_api_key or get_setting('DEEPSEEK_API_KEY', Config.DEEPSEEK_API_KEY)
            self.api_url = get_setting('DEEPSEEK_API_URL', Config.DEEPSEEK_API_URL)
            self.model = get_setting('DEEPSEEK_MODEL', 'deepseek-chat')
            self.headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
        
        elif self.provider == 'claude':
            self.api_key = custom_api_key or get_setting('CLAUDE_API_KEY', Config.CLAUDE_API_KEY)
            self.api_url = get_setting('CLAUDE_API_URL', Config.CLAUDE_API_URL)
            self.model = get_setting('CLAUDE_MODEL', 'claude-3-opus-20240229')
            self.headers = {
                'Content-Type': 'application/json',
                'x-api-key': self.api_key,
                'anthropic-version': '2023-06-01'
            }
        
        elif self.provider == 'gpt':
            self.api_key = custom_api_key or get_setting('GPT_API_KEY', Config.GPT_API_KEY)
            self.api_url = get_setting('GPT_API_URL', Config.GPT_API_URL)
            self.model = get_setting('GPT_MODEL', 'gpt-4')
            self.headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
        elif self.provider == 'gemini':
            self.api_key = custom_api_key or get_setting('GEMINI_API_KEY', Config.GEMINI_API_KEY)
            self.api_url = get_setting('GEMINI_API_URL', Config.GEMINI_API_URL)
            self.model = get_setting('GEMINI_MODEL', 'gemini-pro')
            self.headers = {
                'Content-Type': 'application/json'
            }
            # Gemini API密钥通过URL参数传递
            if '?' not in self.api_url:
                self.api_url = f"{self.api_url}?key={self.api_key}"
        else:
            raise ValueError(f"不支持的LLM提供商: {self.provider}")
    
    def chat_completion(self, messages, temperature=0.3, max_tokens=2000):
        """
        统一的聊天完成接口，适配不同LLM提供商的API格式
        
        参数:
          - messages: 消息列表，格式为 [{'role': 'system'/'user'/'assistant', 'content': '内容'}, ...]
          - temperature: 生成多样性参数
          - max_tokens: 最大生成标记数
          
        返回:
          - 返回生成的文本内容
        """
        try:
            # 根据不同供应商构造请求数据
            if self.provider == 'deepseek':
                data = {
                    'model': self.model,
                    'messages': messages,
                    'temperature': temperature,
                    'max_tokens': max_tokens
                }
            
            elif self.provider == 'claude':
                data = {
                    'model': self.model,
                    'messages': messages,
                    'temperature': temperature,
                    'max_tokens': max_tokens
                }
                
            elif self.provider == 'gpt':
                data = {
                    'model': self.model,
                    'messages': messages,
                    'temperature': temperature,
                    'max_tokens': max_tokens
                }
                
            elif self.provider == 'gemini':
                # Gemini API有不同的请求格式
                data = {
                    'contents': [
                        {'role': msg['role'], 'parts': [{'text': msg['content']}]} 
                        for msg in messages
                    ],
                    'generationConfig': {
                        'temperature': temperature,
                        'maxOutputTokens': max_tokens
                    }
                }
            
            logging.info(f"[LLM服务] 向 {self.provider} API发送请求: {self.api_url}")
            response = requests.post(self.api_url, headers=self.headers, json=data, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                
                # 根据不同供应商解析响应
                if self.provider == 'deepseek':
                    if 'choices' in result and len(result['choices']) > 0:
                        return result['choices'][0]['message']['content']
                
                elif self.provider == 'claude':
                    if 'content' in result:
                        return result['content'][0]['text']
                    
                elif self.provider == 'gpt':
                    if 'choices' in result and len(result['choices']) > 0:
                        return result['choices'][0]['message']['content']
                
                elif self.provider == 'gemini':
                    if 'candidates' in result and len(result['candidates']) > 0:
                        return result['candidates'][0]['content']['parts'][0]['text']
                
                logging.error(f"[LLM服务] 无法从响应中提取内容: {result}")
                return None
            else:
                logging.error(f"[LLM服务] API响应错误 {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logging.error(f"[LLM服务] API请求超时")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"[LLM服务] API请求异常: {e}")
            return None
        except Exception as e:
            logging.error(f"[LLM服务] 处理异常: {e}")
            import traceback
            logging.error(f"[LLM服务] 异常堆栈: {traceback.format_exc()}")
            return None
    
    def get_provider_status(self):
        """检查API状态"""
        try:
            # 简单的测试请求
            test_messages = [
                {'role': 'system', 'content': 'You are an AI assistant.'},
                {'role': 'user', 'content': 'Hello, API test.'}
            ]
            
            # 使用较少的token进行测试
            result = self.chat_completion(
                messages=test_messages,
                temperature=0.1,
                max_tokens=5
            )
            
            if result:
                return {
                    'status': 'ok',
                    'provider': self.provider,
                    'model': self.model
                }
            else:
                return {
                    'status': 'error',
                    'message': 'API响应为空'
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            } 