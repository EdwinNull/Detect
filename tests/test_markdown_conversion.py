#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.analyzer import DeepSeekAnalyzer

def test_markdown_conversion():
    """测试markdown转换功能"""
    analyzer = DeepSeekAnalyzer()
    
    # 测试markdown文本
    test_markdown = """---
### 🛡️ Open source component security analysis report: test-package

#### 1️⃣ XGBoost judgment result
- **Judgment**：Malicious
- **Confidence**：85.50%
- **Risk score**：0.750

#### 2️⃣ Main suspicious features (Top 5)
| Feature name                | Value  | Description/Risk point                  |
|------------------------|--------|------------------------------|
| entropy mean    | 0.72   | Code obfuscation, variable name anomaly         |
| base64 chunks   | 15     | Possible data exfiltration or command injection |
| suspicious tokens | 8    | Malicious code patterns detected               |

#### 3️⃣ Risk level assessment
- **Risk level**：High
- **Main risk points**：
  1. High entropy indicates code obfuscation
  2. Multiple base64 encoded chunks found
  3. Suspicious token patterns detected

#### 4️⃣ Security suggestions
- Suggestion 1: Do not use this package
- Suggestion 2: Check for data exfiltration
- Suggestion 3: Review all dependencies

---

> **Note**：This report is generated automatically by AI, please combine manual security review.
"""
    
    print("原始Markdown文本:")
    print("=" * 50)
    print(test_markdown)
    print("\n" + "=" * 50)
    
    # 转换markdown
    friendly_text = analyzer._convert_markdown_to_friendly_text(test_markdown)
    
    print("转换后的友好中文格式:")
    print("=" * 50)
    print(friendly_text)
    print("=" * 50)

if __name__ == "__main__":
    test_markdown_conversion() 