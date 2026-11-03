"""静态分析引擎包。

模块划分：
- hashing           多算法哈希指纹（MD5/SHA1/SHA256/CRC32/SSDEEP/imphash）
- file_type         基于魔数的文件类型识别（防伪装）
- pe_parser         PE 结构解析与区段熵分析
- packer_detect     加壳/混淆检测
- imports_exports   导入导出表提取与可疑 API 注标
- strings_extract   恶意字符串与常量提取
- resources         资源、版本信息与数字签名
- yara_scanner      YARA 规则匹配
- suspicious_features 可疑特征聚合
- risk_score        风险评分模型
- engine            静态分析总编排
"""
