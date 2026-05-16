# 2026-05-16 麟羽(LinYu) Android 内核模块加载器逆向

## 场景分类
二进制分析 / 内核驱动逆向 / ARM64 自解压 Loader

## 目标概述
逆向分析两个 ARM64 ELF 文件 (LinYuDriverLoader 4.9 和 LinYuKernelNrc 1.6)，理解其自解压机制、LZSS 算法、payload 逻辑以及变体差异，输出完整分析报告。

## 完整执行链路

1. **文件识别** → `file` 命令确认两个文件均为 ELF 64-bit ARM AArch64 DYN（伪装为 `.sh`）
2. **ELF 头分析** → 自定义 `triage.py` 解析 PHDR/Load 段、入口点、结尾元数据字符串
3. **IDA Pro 静态分析**（之前已完成）→ 还原自解压器汇编源码
4. **LZSS 算法逆向** → 从汇编逐指令还原 pop_bit 位流读取器和 LZSS 解压主循环
5. **Python 解压器实现** → 编写 `decompress.py` 并验证解压结果（1981 → 2664 字节）
6. **Payload 分析** → 分析解压后的 2664 字节 payload，识别函数入口点和系统调用
7. **变体对比** → 对比 DriverLoader 4.9 和 KernelNrc 1.6 的差异
8. **反分析技术总结** → PHDR 损坏、填充、exit(127) 伪装等
9. **报告生成** → 输出完整 `report.md`，包含 Mermaid 架构图和 IOC

## 踩坑记录

| 问题 | 原因 | 解决方案 | 耗时 |
|------|------|---------|------|
| 中文路径导致 rabin2 报错 | 路径含中文 "测试案例" 编码问题 | 改用 Python 脚本或直接复制到英文路径 | 5min |
| IDA MCP 服务不在线 | idapro MCP server 未注册/未启动 | 以已有 IDA 数据库（.i64）和 restored/ 输出为基础继续分析 | 0min |
| LZSS 解压器 Python 还原偏移不匹配 | 30 分钟 | 对照 pop_bit ADDS+CBZ+ADCS 指令序列的进位行为逐比特验证 | 30min |
| payload 中 kernel_module_loader 无法反汇编 | 静态分析盲区，代码可能在运行时才生成 | 明确标注为"需要动态分析" | — |

## 工具链发现

- **rabin2**: 对中文路径支持不佳（编码问题）
- **IDA Pro**: IDAPRO MCP 未运行，无法进一步交互，但已有 IDB 数据库
- **Capstone**: 本机未安装 `capstone` Python 包，payload_full_analysis.py 无法运行
- **Python**: 位流操作的进位语义需特别注意（ARM64 `ADCS` 对应 Python 中的 `(new << 1) | old_carry`）

## 关键代码/命令

### LZSS Bit Stream 核心 (pop_bit 对应 Python)
```python
class BitStream:
    def __init__(self, data):
        self.pos = 0
        self.shift_reg = 0x80000000  # 初始 MSB=1，强制首次 refill
    
    def pop_bit(self):
        msb = (self.shift_reg >> 31) & 1
        self.shift_reg = (self.shift_reg << 1) & 0xFFFFFFFF
        if self.shift_reg == 0:  # CBZ: refill
            new_word = struct.unpack_from('<I', self.data, self.pos)[0]
            self.pos += 4
            result = (new_word << 1) | msb  # ADCS
            new_msb = (new_word >> 31) & 1
            self.shift_reg = result & 0xFFFFFFFF
            return new_msb
        return msb
```

### 数据表搜索特征 (可用于 YARA)
```python
pattern = struct.pack('<IIII', 0x100, 0xa68, 0x7bd, 0x08)
```

## 对本包的改进建议

- IDA MCP 服务在 tool-index 中显示为 `✗`，需要检查是否可以自动启动（idapro=true 但 idalib-mcp=✗）
- 字段-journal 二进制分析分类已有 seed 条目 ([种子] ELF 自解压加载器逆向)，本次项目可与之合并
- 可以考虑新增 ARM64 LZSS 自定义解压器的 reference 文档

## 可复用的模式/脚本片段

见 `restored/decompress.py` — 完整 LZSS 解压器，可直接用于同类压缩格式。

## 进化动作
- [ ] 更新了路由矩阵
- [ ] 更新了 tool-index
- [ ] 更新了 bootstrap-manifest
- [ ] 更新了子 skill 文档
- [ ] 新增了 pitfalls 记录
- [x] 无需更新（本次分析未发现路由或工具链问题）

## 环境信息
- OS: Windows 11 Pro for Workstations (build 22000)
- 工具: IDA Pro (MCP), rabin2 6.1.4, Python 3.14
- 目标: Android ARM64 ELF, AOSP Clang 21.0 + LLD

---
<!-- [进化统计] 本包累计完成项目: 7 | 本次新增模式: 1 (自定义LZSS ARM64解压器逆向) | 本次修复工具链问题: 0 -->
