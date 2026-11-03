# MalScope · 恶意软件样本智能分析平台

> 面向恶意代码分析的 B/S 架构智能样本分析平台
> **静态分析引擎 + 动态沙箱分析引擎 + 威胁情报与 IOC 提取 + 样本库与 RBAC 权限审计**

<p align="left">
  <img alt="python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB">
  <img alt="fastapi" src="https://img.shields.io/badge/FastAPI-0.115-009688">
  <img alt="vue" src="https://img.shields.io/badge/Vue-3.5-42b883">
  <img alt="mysql" src="https://img.shields.io/badge/MySQL-8.0-4479A1">
  <img alt="license" src="https://img.shields.io/badge/用途-教学与安全研究-red">
</p>

---

## 一、项目定位

MalScope 是一个**纯网安方向**的恶意样本分析平台，四条主线贯穿始终：

| 主线 | 核心能力 |
| --- | --- |
| **静态分析引擎** | PE 结构解析、区段熵分析、加壳检测、导入导出表与可疑 API 注标、恶意字符串提取、资源/签名校验、YARA 匹配、风险评分 |
| **动态沙箱分析引擎** | 硬件级隔离沙箱编排、快照回滚（跑一次清一次）、进程/文件/注册表/网络四维行为采集、C2 外联与 DGA 捕获、MITRE ATT&CK 映射、**防沙箱逃逸设计** |
| **威胁情报与 IOC** | 自动提取 MD5/SHA256/IP/域名/URL/C2/注册表/路径/互斥体/证书等 IOC，CSV/JSON/STIX/OpenIOC 导出，MISP/VirusTotal 对接，多源融合威胁评分，一键生成 HTML/PDF 分析报告 |
| **样本库与权限** | AES-256-CTR+HMAC 加密落盘、哈希去重、家族关联、RBAC 权限、敏感操作审计、压缩炸弹校验、下载二次授权 |

> 平台**自身不具备直接执行样本的能力**：样本仅在隔离沙箱环境内、以受控方式运行；
> 静态分析在内存/临时隔离目录中完成，全程不调用样本入口点。

---

## 二、总体架构（B/S 四层）

```
┌──────────────────────────────────────────────────────────────────┐
│ 前端展示层  Vue3 + Element Plus + ECharts + Pinia + Vue Router    │
│  登录 / 总览 / 样本库 / 静态报告 / 动态时间线 / ATT&CK / IOC       │
└───────────────────────────────┬──────────────────────────────────┘
                                │ REST / JWT
┌───────────────────────────────▼──────────────────────────────────┐
│ 后端分析引擎层  FastAPI + SQLAlchemy + Celery/线程池              │
│  ├ 静态分析引擎   pefile / LIEF / capstone / yara-python          │
│  ├ 动态沙箱编排   驱动抽象（VirtualBox / libvirt-KVM / mock）      │
│  ├ 威胁情报引擎   IOC 提取 / 评分 / STIX·OpenIOC 导出 / MISP·VT   │
│  ├ 样本管理       加密存储 / 哈希去重 / 压缩炸弹防护               │
│  └ 权限与审计     RBAC / JWT / 审计日志                           │
└───────────────┬───────────────────────────────┬──────────────────┘
                │                               │
┌───────────────▼──────────────┐  ┌─────────────▼──────────────────┐
│ 沙箱执行层（隔离）            │  │ 数据存储层                      │
│ 虚拟化 VM + Guest Agent      │  │ MySQL 8.0（生产）/ SQLite（开发）│
│ 快照回滚 / INetSim 网络诱捕   │  │ Redis（队列/缓存）              │
│ 反逃逸：痕迹隐藏/时间加速     │  │ AES-256 加密样本库              │
└──────────────────────────────┘  └────────────────────────────────┘
```

---

## 三、目录结构

```
恶意软件样本智能分析平台/
├── backend/                     # 后端分析引擎（FastAPI）
│   ├── app/
│   │   ├── core/                # 配置、安全、加密、日志、知识库加载器
│   │   ├── db/                  # 数据模型、会话、初始化数据
│   │   ├── engines/
│   │   │   ├── static_analysis/ # 静态分析引擎（哈希/PE/壳/导入表/字符串/YARA/评分）
│   │   │   ├── sandbox/         # 沙箱编排 + 驱动（virtualbox/libvirt/mock）+ 行为分析
│   │   │   └── threat_intel/    # IOC 提取/评分/导出/情报源对接
│   │   ├── services/            # 样本库、分析任务、报告、存储、审计
│   │   ├── api/v1/              # REST 接口
│   │   ├── workers/             # Celery + 进程内线程池任务
│   │   ├── templates/           # 报告 HTML 模板
│   │   └── main.py              # 应用入口
│   ├── rules/
│   │   ├── knowledge_base.json  # 安全知识库（可疑 API/壳特征/字符串规则/ATT&CK）
│   │   └── yara/                # 内置 YARA 规则集
│   ├── tests/                   # 端到端与检测能力测试
│   └── requirements.txt
├── frontend/                    # 前端展示层（Vue3 + Element Plus + ECharts）
├── sandbox/guest_agent/         # 客户机行为采集 Agent（进程/文件/注册表/网络）
├── docs/                        # 设计文档、部署文档
├── diagrams/                    # 架构图/流程图/用例图/ER 图（Mermaid 源文件）
└── docker/                      # 容器化部署
```

---

## 四、快速开始

### 4.1 后端

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # Linux/macOS: cp .env.example .env

# 开发环境默认使用 SQLite，无需额外配置；生产环境在 .env 中配置 MySQL/Redis
.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

启动后访问：

- 接口文档：<http://127.0.0.1:8000/docs>
- 健康检查：<http://127.0.0.1:8000/health>

默认管理员账号：`admin / Admin@123456`

### 4.2 前端

```bash
cd frontend
npm install
npm run dev        # 开发模式，访问 http://localhost:5173
npm run build      # 构建产物输出到 frontend/dist，可由后端一并托管
```

### 4.3 一键验证（无需前端）

```bash
cd backend
.venv\Scripts\python tests\smoke_pipeline.py      # 上传→静态→动态→IOC→报告 全流水线
.venv\Scripts\python tests\synthetic_detect.py    # 合成恶意样本检测能力验证
```

---

## 五、核心能力速览

### 5.1 静态分析

- **哈希指纹**：MD5 / SHA1 / SHA256 / CRC32 / **SSDEEP**（原生库缺失时回退纯 Python spamsum 实现）/ **imphash**；
- **文件识别**：基于魔数识别 PE/ELF/Office/PDF/脚本/压缩包，识别双扩展名伪装与类型不符；
- **PE 解析**：DOS/NT/可选头、节表、数据目录、Rich 头、PDB、TLS 回调、编译时间戳异常；
- **区段分析**：各区段熵值、R/W/X 属性、**RWX 检测**、节区重叠、零填充大节、入口点异常；
- **加壳检测**：14 种壳特征签名（UPX/ASPack/FSG/Themida/VMProtect…）+ 多信号加权重启发式；
- **导入导出表**：16 类可疑 API 风险注标（进程注入/反调试/反虚拟机/网络 C2/持久化/勒索加密/凭据获取…），映射 MITRE ATT&CK；
- **字符串提取**：ASCII + UTF-16LE 双编码，15 类正则规则（URL/IP/域名/邮箱/路径/注册表/命令行/互斥体/Base64/比特币钱包/勒索信/加密常量…），白名单降噪；
- **资源与签名**：资源目录、版本信息、Authenticode PKCS#7 证书链解析 + Windows WinVerifyTrust 可信性校验；
- **YARA**：内置规则库 + 自定义规则热加载，支持按命名空间定位命中来源；
- **风险评分**：核心证据与"能力画像"分离加权，规避正常软件误报。

### 5.2 动态沙箱

- **驱动抽象**：`VirtualBoxDriver` / `LibvirtDriver`(KVM) / `MockDriver`，按宿主环境自动选择并可回退；
- **隔离与回滚**：快照回滚 + 运行后强制关机再回滚，实现"跑一次清一次"；
- **行为采集（Guest Agent）**：进程树/父子关系/命令行/模块、文件创建/修改/删除/重命名、注册表 Run/IP/IFEO 等关键键差分、网络连接，输出结构化 JSON 日志；
- **C2 与 DGA**：远控端口、C2 路径特征、可疑 UA、域名结构熵启发式判定；
- **ATT&CK 映射**：行为自动映射到 35 项 ATT&CK 技术；
- **反逃逸**：反调试/反虚拟机行为识别与标注，配合宿主机侧痕迹隐藏、时间加速、网络诱捕设计。

> 无虚拟化环境（如本机演示）时，`SANDBOX_DRIVER=mock` 会依据样本自身特征**确定性合成**
> 一份结构完整的行为日志，跑通全部上层分析逻辑；真实沙箱只需切换驱动配置。

### 5.3 威胁情报

- IOC 自动提取与去重，按类型/来源/上下文计算威胁分；
- **四种导出格式**：CSV / JSON / **STIX 2.1** / **OpenIOC 1.1**；
- 预留 **MISP** 推送与 **VirusTotal** 查询接口（配置 Key 即启用，无 Key 优雅降级）；
- 一键生成 **HTML / PDF / JSON** 安全分析报告（含样本信息、静态分析、动态行为、网络行为、IOC 清单、ATT&CK 矩阵、处置建议）。

---

## 六、安全设计要点

| 风险 | 对应措施 |
| --- | --- |
| 样本泄露/被窃取 | AES-256-CTR + HMAC-SHA256 加密落盘，磁盘无明文 |
| 平台误执行样本 | 平台自身不加载样本入口点；动态执行严格限定在隔离沙箱 |
| 压缩炸弹 | 上传时校验条目数、解压后总大小、压缩比与路径穿越 |
| 越权下载样本 | 二次授权确认 + `sample:download` 权限 + 审计留痕 |
| 沙箱被样本逃逸 | 快照回滚、网络隔离+INetSim 诱捕、痕迹隐藏、时间加速 |
| 操作不可追溯 | 全量审计日志（上传/下载/分析/删除/登录/导出） |
| 越权访问接口 | RBAC 权限码校验（14 项权限 / 4 类角色） |

---

## 七、免责声明

本项目仅用于**网络安全教学与合法安全研究**。所有样本分析必须在离线/隔离环境中进行，
严禁用于任何未授权的攻击行为。使用者须自行承担因不当使用产生的全部责任。

---

## 八、文档索引

| 文档 | 说明 |
| --- | --- |
| `docs/架构与系统设计.md` | 总体架构、模块设计、数据流、接口设计 |
| `docs/数据库设计.md` | 数据模型与表结构说明 |
| `docs/部署与运行.md` | 本机/生产/容器化部署 |
| `docs/沙箱环境搭建与反逃逸.md` | 虚拟机沙箱搭建、网络诱捕、反逃逸对抗 |
| `diagrams/设计图.md` | 架构图、流程图、用例图、ER 图（Mermaid） |
