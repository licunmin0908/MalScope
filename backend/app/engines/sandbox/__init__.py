"""动态沙箱分析引擎包。

- drivers/        可插拔虚拟化驱动（virtualbox / libvirt / mock）
- orchestrator    沙箱编排：快照回滚、样本投递、受控执行、日志回收
- behavior_analyzer 行为归一化、ATT&CK 映射、反逃逸事件识别与评分
- c2_detect       C2 心跳与 DGA 域名启发式检测
"""

from app.engines.sandbox.orchestrator import SandboxOrchestrator

__all__ = ["SandboxOrchestrator"]
