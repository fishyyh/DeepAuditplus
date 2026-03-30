"""
Analysis Agent (漏洞分析层) - LLM 驱动版

LLM 是真正的安全分析大脑！
- LLM 决定分析策略
- LLM 选择使用什么工具
- LLM 决定深入分析哪些代码
- LLM 判断发现的问题是否是真实漏洞

类型: ReAct (真正的!)
"""

import asyncio
import json
import logging
import os
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .base import BaseAgent, AgentConfig, AgentResult, AgentType, AgentPattern, TaskHandoff
from ..json_parser import AgentJsonParser
from ..prompts import CORE_SECURITY_PRINCIPLES, VULNERABILITY_PRIORITIES

logger = logging.getLogger(__name__)

README_MISMATCH_PATTERN_NAME = "readme_code_behavior_mismatch"


ANALYSIS_SYSTEM_PROMPT = """你是 DeepAudit 的漏洞分析 Agent，一个**自主**的安全专家。

## 你的角色
你是安全审计的**核心大脑**，不是工具执行器。你需要：
1. 自主制定分析策略
2. 选择最有效的工具和方法
3. 深入分析可疑代码
4. 判断是否是真实漏洞
5. 动态调整分析方向

## ⚠️ 核心原则：优先使用外部专业工具！

**外部工具优先级最高！** 必须首先使用外部安全工具进行扫描，它们有：
- 经过验证的专业规则库
- 更低的误报率
- 更全面的漏洞检测能力

## 🔧 工具优先级（必须按此顺序使用）

### 第一优先级：外部专业安全工具 ⭐⭐⭐ 【必须首先使用！】
- **semgrep_scan**: 全语言静态分析 - **每次分析必用**
  参数: target_path (str), rules (str: "auto" 或 "p/security-audit")
  示例: {"target_path": ".", "rules": "auto"}

- **bandit_scan**: Python 安全扫描 - **Python项目必用**
  参数: target_path (str), severity (str)
  示例: {"target_path": ".", "severity": "medium"}

- **gitleaks_scan**: 密钥泄露检测 - **每次分析必用**
  参数: target_path (str)
  示例: {"target_path": "."}

- **safety_scan**: Python 依赖漏洞 - **有 requirements.txt 时必用**
  参数: requirements_file (str)
  示例: {"requirements_file": "requirements.txt"}

- **npm_audit**: Node.js 依赖漏洞 - **有 package.json 时必用**
  参数: target_path (str)
  示例: {"target_path": "."}

- **kunlun_scan**: 深度代码审计（Kunlun-M）
  参数: target_path (str), language (str: "php"|"javascript"|"solidity")
  示例: {"target_path": ".", "language": "solidity"}

- **slither_scan**: Solidity 主力静态分析（推荐主扫描器）
  参数: target_path (str), detectors (str, 可选)
  示例: {"target_path": ".", "detectors": "reentrancy-eth,tx-origin"}

- **mythril_scan**: Solidity 符号执行补充扫描
  参数: target_path (str), execution_timeout (int), max_files (int)
  示例: {"target_path": ".", "execution_timeout": 90, "max_files": 8}

### 第二优先级：智能扫描工具 ⭐⭐
- **smart_scan**: 智能批量安全扫描
  参数: target (str), quick_mode (bool), focus_vulnerabilities (list)
  示例: {"target": ".", "quick_mode": true}

- **quick_audit**: 快速文件审计
  参数: file_path (str), deep_analysis (bool)
  示例: {"file_path": "app/views.py", "deep_analysis": true}

### 第三优先级：内置分析工具 ⭐
- **pattern_match**: 危险模式匹配（外部工具不可用时的备选）
  参数: scan_file (str) 或 code (str), pattern_types (list)
  示例: {"scan_file": "app/models.py", "pattern_types": ["sql_injection"]}

- **dataflow_analysis**: 数据流追踪
  参数: source_code (str), variable_name (str)

### 辅助工具（RAG 优先，401 自动降级）
- **rag_query**: **🔥 首选** 语义搜索代码，理解业务逻辑
  参数: query (str), top_k (int)
- **security_search**: **🔥 首选** 安全相关搜索
  参数: query (str)
- **read_file**: 读取文件内容
  参数: file_path (str), start_line (int), end_line (int)
- **list_files**: ⚠️ 仅列出目录，严禁遍历
- **search_code**: ⚠️ RAG 返回 401/Unauthorized 时的首选降级工具，用精确关键字定位函数/危险调用

## 📋 推荐分析流程（严格按此执行！）

### 第一步：外部工具全面扫描（60%时间）⚡ 最重要！
根据项目技术栈，**必须首先**执行以下外部工具：

```
# 所有项目必做
Action: semgrep_scan
Action Input: {"target_path": ".", "rules": "auto"}

Action: gitleaks_scan
Action Input: {"target_path": "."}

# Python 项目必做
Action: bandit_scan
Action Input: {"target_path": ".", "severity": "medium"}

Action: safety_scan
Action Input: {"requirements_file": "requirements.txt"}

# Node.js 项目必做
Action: npm_audit
Action Input: {"target_path": "."}

# Solidity 深度扫描（优先并行）
Action: slither_scan
Action Input: {"target_path": "."}

Action: mythril_scan
Action Input: {"target_path": ".", "execution_timeout": 90, "max_files": 8}

# Solidity/JS 补充扫描（与 npm_audit 并行）
Action: kunlun_scan
Action Input: {"target_path": ".", "language": "solidity"}
```

### 第二步：分析外部工具结果（25%时间）
对外部工具发现的问题进行深入分析：
- 使用 `read_file` 查看完整代码上下文
- 使用 `dataflow_analysis` 追踪数据流
- 验证是否为真实漏洞，排除误报

### 第三步：补充扫描（10%时间）
如果外部工具覆盖不足，使用内置工具补充：
- `smart_scan` 综合扫描
- `pattern_match` 模式匹配

### 第四步：汇总报告（5%时间）
整理所有发现，输出 Final Answer

## ⚠️ 重要提醒
1. **不要跳过外部工具！** 即使内置工具可能更快，外部工具的检测能力更强
2. **Docker依赖**：外部工具需要Docker环境，如果返回"Docker不可用"，再使用内置工具
3. **并行执行**：优先并行覆盖 `slither_scan + mythril_scan`，其次 `kunlun_scan + npm_audit`
4. **RAG 401 降级**：若 `rag_query/security_search/function_context` 返回 401/Unauthorized，立即切换 `search_code + read_file`

## 工作方式
每一步，你需要输出：

```
Thought: [分析当前情况，思考下一步应该做什么]
Action: [工具名称]
Action Input: [JSON 格式的参数]
```

当你完成分析后，输出：

```
Thought: [总结所有发现]
Final Answer: [JSON 格式的漏洞报告]
```

## ⚠️ 输出格式要求（严格遵守）

**禁止使用 Markdown 格式标记！** 你的输出必须是纯文本格式：

✅ 正确：
```
Thought: 我需要使用 semgrep 扫描代码。
Action: semgrep_scan
Action Input: {"target_path": ".", "rules": "auto"}
```

❌ 错误（禁止）：
```
**Thought:** 我需要扫描
**Action:** semgrep_scan
**Action Input:** {...}
```

## Final Answer 格式
```json
{
    "findings": [
        {
            "vulnerability_type": "sql_injection",
            "severity": "high",
            "title": "SQL 注入漏洞",
            "description": "详细描述",
            "file_path": "path/to/file.py",
            "line_start": 42,
            "code_snippet": "危险代码片段",
            "source": "污点来源",
            "sink": "危险函数",
            "suggestion": "修复建议",
            "confidence": 0.9,
            "needs_verification": true
        }
    ],
    "summary": "分析总结"
}
```

## 重点关注的漏洞类型
- SQL 注入 (query, execute, raw SQL)
- XSS (innerHTML, document.write, v-html)
- 命令注入 (exec, system, subprocess)
- 路径遍历 (open, readFile, path 拼接)
- SSRF (requests, fetch, http client)
- 硬编码密钥 (password, secret, api_key)
- 不安全的反序列化 (pickle, yaml.load, eval)

## 重要原则
1. **外部工具优先** - 首先使用 semgrep、bandit 等专业工具
2. **质量优先** - 宁可深入分析几个真实漏洞，不要浅尝辄止报告大量误报
3. **上下文分析** - 看到可疑代码要读取上下文，理解完整逻辑
4. **自主判断** - 不要机械相信工具输出，要用你的专业知识判断

## 🚨 知识工具使用警告（防止幻觉！）

**知识库中的代码示例仅供概念参考，不是实际代码！**

当你使用 `get_vulnerability_knowledge` 或 `query_security_knowledge` 时：
1. **知识示例 ≠ 项目代码** - 知识库的代码示例是通用示例，不是目标项目的代码
2. **语言可能不匹配** - 知识库可能返回 Python 示例，但项目可能是 PHP/Rust/Go
3. **必须在实际代码中验证** - 你只能报告你在 read_file 中**实际看到**的漏洞
4. **禁止推测** - 不要因为知识库说"这种模式常见"就假设项目中存在

❌ 错误做法（幻觉来源）：
```
1. 查询 auth_bypass 知识 -> 看到 JWT 示例
2. 没有在项目中找到 JWT 代码
3. 仍然报告 "JWT 认证绕过漏洞"  <- 这是幻觉！
```

✅ 正确做法：
```
1. 查询 auth_bypass 知识 -> 了解认证绕过的概念
2. 使用 read_file 读取项目的认证代码
3. 只有**实际看到**有问题的代码才报告漏洞
4. file_path 必须是你**实际读取过**的文件
```

## ⚠️ 关键约束 - 必须遵守！
1. **禁止直接输出 Final Answer** - 你必须先调用工具来分析代码
2. **至少调用两个工具** - 使用 smart_scan/semgrep_scan 进行扫描，然后用 read_file 查看代码
3. **没有工具调用的分析无效** - 不允许仅凭推测直接报告漏洞
4. **先 Action 后 Final Answer** - 必须先执行工具，获取 Observation，再输出最终结论

错误示例（禁止）：
```
Thought: 根据项目信息，可能存在安全问题
Final Answer: {...}  ❌ 没有调用任何工具！
```

正确示例（必须）：
```
Thought: 我需要先使用智能扫描工具对项目进行全面分析
Action: smart_scan
Action Input: {"scan_type": "security", "max_files": 50}
```
然后等待 Observation，再继续深入分析或输出 Final Answer。

现在开始你的安全分析！首先使用外部工具进行全面扫描。"""


@dataclass
class AnalysisStep:
    """分析步骤"""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict] = None


class AnalysisAgent(BaseAgent):
    """
    漏洞分析 Agent - LLM 驱动版
    
    LLM 全程参与，自主决定：
    1. 分析什么
    2. 使用什么工具
    3. 深入哪些代码
    4. 报告什么发现
    """
    
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        # 组合增强的系统提示词，注入核心安全原则和漏洞优先级
        full_system_prompt = f"{ANALYSIS_SYSTEM_PROMPT}\n\n{CORE_SECURITY_PRINCIPLES}\n\n{VULNERABILITY_PRIORITIES}"
        
        config = AgentConfig(
            name="Analysis",
            agent_type=AgentType.ANALYSIS,
            pattern=AgentPattern.REACT,
            max_iterations=30,
            system_prompt=full_system_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[AnalysisStep] = []

    @staticmethod
    def _normalize_language_text(values: List[Any]) -> str:
        return " ".join(str(v).lower() for v in values if v is not None)

    def _is_solidity_project(
        self,
        tech_stack: Dict[str, Any],
        project_info: Dict[str, Any],
        target_files: List[str],
    ) -> bool:
        """判断是否为 Solidity 项目。"""
        tech_languages = tech_stack.get("languages", []) if isinstance(tech_stack, dict) else []
        project_languages = project_info.get("languages", []) if isinstance(project_info, dict) else []
        language_text = self._normalize_language_text([*tech_languages, *project_languages])

        if "solidity" in language_text or "vyper" in language_text:
            return True

        return any(str(path).lower().endswith(".sol") for path in (target_files or []))

    @staticmethod
    def _detect_protocol_type(
        readme_context: str,
        target_files: List[str],
    ) -> List[str]:
        """从 README 文本和文件名中识别 DeFi 协议类型。

        返回检测到的协议类型列表（如 ['DEX/AMM', '质押/Staking']）。
        """
        text = (readme_context + " " + " ".join(str(f) for f in target_files)).lower()

        protocol_keywords: Dict[str, List[str]] = {
            "DEX/AMM": ["swap", "addliquidity", "getreserves", "uniswapv2", "uniswapv3", "curve", "balancer", " amm", " dex", "pool", "liquidity"],
            "借贷/Lending": ["collateral", "borrow", "repay", "liquidat", "healthfactor", "lending", "loan", "aave", "compound"],
            "NFT": ["erc721", "erc1155", "mint", "tokenuri", "safetransferfrom", " nft", "collectible", "opensea"],
            "质押/Staking": ["stake", "unstake", "rewardpertoken", "getreward", "synthetix", "staking", "rewardsduration"],
            "跨链/Bridge": ["lzreceive", "ccipreceive", "xreceive", "bridge", "relay", "crosschain", "layerzero", "axelar"],
            "治理/Governance": ["propose", " vote", "execute", "quorum", "timelockcontroller", "governance", "dao"],
            "代理合约/Proxy": ["upgradeto", "initialize", "delegatecall", "eip1967", "uups", "upgradeable", "transparentproxy"],
            "多签/Multisig": ["threshold", "exectransaction", "gnosissafe", "multisig", "safetx"],
        }

        detected: List[str] = []
        for protocol_type, keywords in protocol_keywords.items():
            if any(kw in text for kw in keywords):
                detected.append(protocol_type)

        return detected

    @staticmethod
    def _safe_project_root(project_root: str) -> str:
        root = os.path.realpath(project_root or ".")
        return root if os.path.isdir(root) else "."

    def _collect_readme_candidates(
        self,
        project_root: str,
        target_files: Optional[List[str]] = None,
        max_candidates: int = 6,
    ) -> List[str]:
        """收集 README 候选文件（绝对路径）。"""
        root = self._safe_project_root(project_root)
        target_files = target_files or []
        candidates: List[str] = []
        seen = set()

        def add_candidate(path: str) -> None:
            real = os.path.realpath(path)
            if not real.startswith(root):
                return
            if not os.path.isfile(real):
                return
            key = real.lower()
            if key in seen:
                return
            seen.add(key)
            candidates.append(real)

        # 1) 从用户目标文件里优先找 README
        for rel in target_files:
            name = os.path.basename(str(rel)).lower()
            if name.startswith("readme"):
                add_candidate(os.path.join(root, str(rel)))
                if len(candidates) >= max_candidates:
                    return candidates

        # 2) 常见 README 名称
        common_names = [
            "README.md",
            "README.MD",
            "readme.md",
            "README_EN.md",
            "README_ZH.md",
            "README_CN.md",
            "README.txt",
            "docs/README.md",
        ]
        for rel in common_names:
            add_candidate(os.path.join(root, rel))
            if len(candidates) >= max_candidates:
                return candidates

        # 3) 顶层与 docs 下兜底搜索（限制深度）
        skip_dirs = {".git", "node_modules", "vendor", "lib", "dist", "build", "artifacts", "cache", "out"}
        for current_root, dirs, files in os.walk(root):
            rel_depth = os.path.relpath(current_root, root).count(os.sep)
            if rel_depth > 2:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                lower = filename.lower()
                if lower.startswith("readme") and lower.endswith((".md", ".txt")):
                    add_candidate(os.path.join(current_root, filename))
                    if len(candidates) >= max_candidates:
                        return candidates

        return candidates

    @staticmethod
    def _read_text_file(path: str, max_chars: int = 12000) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(max_chars)
        except Exception:
            return ""

    def _extract_business_logic_points(self, markdown_text: str, max_points: int = 18) -> List[str]:
        """从 README 提取业务逻辑关键信息（启发式）。"""
        if not markdown_text:
            return []

        lines = [line.strip() for line in markdown_text.splitlines() if line.strip()]
        if not lines:
            return []

        keywords = (
            "protocol", "architecture", "mechanism", "workflow", "logic", "business",
            "token", "tokenomics", "vault", "pool", "swap", "router", "hook",
            "deposit", "withdraw", "redeem", "mint", "burn", "stake", "unstake",
            "collateral", "liquidation", "oracle", "fee", "reward", "governance",
            "phase", "limit", "cooldown", "risk", "flash", "loan", "upgrade",
            "业务", "机制", "逻辑", "架构", "流程", "代币", "池", "存款", "取款", "赎回",
            "铸造", "销毁", "质押", "清算", "预言机", "费率", "奖励", "治理", "风控", "升级",
        )

        points: List[str] = []
        seen = set()
        for raw in lines:
            if raw.startswith("```") or raw.startswith("|---"):
                continue
            normalized = re.sub(r"^[#>\-\*\d\.\)\s]+", "", raw).strip()
            if len(normalized) < 8:
                continue
            lower = normalized.lower()
            if any(k in lower for k in keywords):
                if normalized not in seen:
                    seen.add(normalized)
                    points.append(normalized)
                if len(points) >= max_points:
                    break

        # 兜底：关键词过少时补充前几条二级标题
        if len(points) < 6:
            for raw in lines:
                if not raw.startswith("##"):
                    continue
                normalized = re.sub(r"^[#\s]+", "", raw).strip()
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    points.append(normalized)
                if len(points) >= max_points:
                    break

        return points[:max_points]

    def _build_solidity_readme_context(
        self,
        project_root: str,
        target_files: Optional[List[str]] = None,
    ) -> str:
        """构建 Solidity 项目的 README 业务逻辑上下文摘要。"""
        candidates = self._collect_readme_candidates(project_root, target_files=target_files)
        if not candidates:
            return ""

        sections: List[str] = []
        for path in candidates[:3]:
            content = self._read_text_file(path)
            if not content:
                continue
            points = self._extract_business_logic_points(content)
            if not points:
                continue
            rel = os.path.relpath(path, self._safe_project_root(project_root))
            bullet_text = "\n".join(
                f"- {self._shorten_text(point, max_len=180)}"
                for point in points[:10]
            )
            sections.append(f"### 来源: {rel}\n{bullet_text}")

        return "\n\n".join(sections)

    @staticmethod
    def _shorten_text(value: Any, max_len: int = 140) -> str:
        text = str(value or "").strip()
        if len(text) <= max_len:
            return text
        return text[:max_len].rstrip() + "..."

    def _build_compact_recon_context(
        self,
        high_risk_areas: List[Any],
        entry_points: List[Any],
        initial_findings: List[Any],
    ) -> str:
        """将 Recon 上下文压缩为高信噪比摘要，避免 JSON 大块注入。"""
        sections: List[str] = ["## 上下文信息（压缩摘要）"]

        risk_lines: List[str] = []
        seen_risks = set()
        for item in high_risk_areas[:10]:
            text = self._shorten_text(item, max_len=120)
            if not text or text in seen_risks:
                continue
            seen_risks.add(text)
            risk_lines.append(f"- {text}")
        if risk_lines:
            sections.append("### ⚠️ 高风险区域（优先读取）")
            sections.extend(risk_lines)
            sections.append("")

        entry_lines: List[str] = []
        for ep in entry_points[:8]:
            if isinstance(ep, dict):
                ep_type = self._shorten_text(ep.get("type", "entry"), max_len=28)
                ep_file = self._shorten_text(ep.get("file", ep.get("file_path", "")), max_len=90)
                ep_desc = self._shorten_text(ep.get("description", ""), max_len=90)
                core = f"[{ep_type}] {ep_file}" if ep_file else f"[{ep_type}]"
                if ep_desc:
                    core += f" - {ep_desc}"
                entry_lines.append(f"- {core}")
            else:
                text = self._shorten_text(ep, max_len=130)
                if text:
                    entry_lines.append(f"- {text}")
        if entry_lines:
            sections.append("### 入口点（摘要）")
            sections.extend(entry_lines)
            sections.append("")

        finding_lines: List[str] = []
        for f in initial_findings[:6]:
            if isinstance(f, dict):
                sev = self._shorten_text(f.get("severity", "unknown"), max_len=12).upper()
                title = self._shorten_text(f.get("title", "潜在问题"), max_len=80)
                path = self._shorten_text(f.get("file_path", ""), max_len=70)
                if path:
                    finding_lines.append(f"- [{sev}] {title} @ {path}")
                else:
                    finding_lines.append(f"- [{sev}] {title}")
            else:
                text = self._shorten_text(f, max_len=130)
                if text:
                    finding_lines.append(f"- {text}")
        if finding_lines:
            sections.append("### 初步发现（待验证）")
            sections.extend(finding_lines)
            sections.append("")

        sections.append("请基于上述摘要优先做精准 read_file（小窗口）验证，不要一次读取过长代码。")
        return "\n".join(sections).strip()

    def _build_solidity_focus_guide(self, protocol_types: List[str]) -> str:
        """
        生成 Solidity 精简业务逻辑指南。
        避免注入完整长指南，降低首轮上下文体积。
        """
        protocol_checklists: Dict[str, List[str]] = {
            "DEX/AMM": [
                "检查 reserve/price 是否可被闪贷同块操控（现货价风险）。",
                "核对手续费与不变量（k 值）维护顺序，防止逻辑绕过。",
                "确认 swap/add/remove 的滑点与最小输出保护是否有效。",
                "检查外部回调路径是否存在重入窗口。",
            ],
            "借贷/Lending": [
                "核对清算条件与健康因子计算边界（精度、四舍五入方向）。",
                "检查价格源是否可操控（AMM 现货 vs TWAP/Oracle）。",
                "确认清算/赎回流程不会被回调 revert 阻断。",
                "检查借贷上限、利率模型和资金池耗尽路径。",
            ],
            "NFT": [
                "核对 mint 总量、单地址限制、tokenId 唯一性。",
                "检查 safeTransfer 回调是否引入重入状态错乱。",
                "核对权限函数（mint/burn/setBaseURI）访问控制。",
                "检查随机铸造/稀有度逻辑是否可预测或被抢跑。",
            ],
            "质押/Staking": [
                "检查 rewardPerToken 累积逻辑和 totalSupply=0 分支。",
                "检查奖励预算是否可被超发/重复发放。",
                "核对 stake/unstake/getReward 是否受重入保护。",
                "检查是否存在同块套利（stake->claim->unstake）。",
            ],
            "跨链/Bridge": [
                "验证跨链消息来源与目标链身份校验是否严格。",
                "检查 nonce/消息重放保护是否完整。",
                "核对失败重试与补偿流程是否可被滥用。",
                "检查跨链资产记账是否会双花或错账。",
            ],
            "治理/Governance": [
                "核对投票权是否基于快照，而非实时余额。",
                "检查 timelock、quorum、votingDelay 是否可绕过。",
                "检查提案执行目标是否过宽（任意调用风险）。",
                "核对管理员权限与紧急权限边界。",
            ],
            "代理合约/Proxy": [
                "检查 initialize/upgrade 权限与可重入初始化风险。",
                "核对存储布局升级兼容性（变量顺序/slot 冲突）。",
                "检查 delegatecall 目标可控性与执行边界。",
                "核对实现合约是否正确禁用再次初始化。",
            ],
            "多签/Multisig": [
                "检查签名去重、阈值变更和 nonce 递增规则。",
                "核对签名域是否含 chainId + 合约地址防重放。",
                "检查执行目标白名单与 delegatecall 风险。",
                "核对 owner 管理与紧急路径权限。",
            ],
        }

        selected_types: List[str] = []
        for p in protocol_types or []:
            if p in protocol_checklists and p not in selected_types:
                selected_types.append(p)
            if len(selected_types) >= 3:
                break

        if not selected_types:
            selected_types = ["DEX/AMM", "借贷/Lending"]

        lines: List[str] = [
            "## 🧭 Solidity 业务逻辑精简审计指南",
            "- 先验证关键不变量，再看资金流与权限边界。",
            "- 优先检查可直接导致资金损失的路径：重入、价格操控、权限绕过、升级滥用。",
            "- 每个疑点必须用 read_file 小窗口复核后再下结论。",
            "",
        ]

        for protocol in selected_types:
            lines.append(f"### {protocol} 重点核查")
            for item in protocol_checklists.get(protocol, [])[:4]:
                lines.append(f"- {item}")
            lines.append("")

        return "\n".join(lines).strip()

    def _compact_handoff_context(self, handoff_context: str, max_chars: int = 4800) -> str:
        """
        压缩前序 Agent 交接上下文，避免原样注入导致首轮上下文膨胀。
        """
        text = (handoff_context or "").strip()
        if not text:
            return ""
        if len(text) <= max_chars:
            return text

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return self._head_tail_compact(text, max_chars=max_chars)

        head_lines = lines[:36]
        tail_lines = lines[-14:] if len(lines) > 36 else []

        markers = (
            "critical",
            "high",
            "medium",
            "漏洞",
            "风险",
            "建议",
            "attention",
            "priority",
            "file",
            "位置",
            "action",
            "summary",
            "发现",
            "关注",
            "优先",
        )

        signal_lines: List[str] = []
        for line in lines:
            lower = line.lower()
            if any(marker in lower for marker in markers):
                signal_lines.append(line)
            if len(signal_lines) >= 72:
                break

        merged: List[str] = []
        seen = set()
        for line in head_lines + signal_lines + tail_lines:
            if line in seen:
                continue
            seen.add(line)
            merged.append(line)

        omitted_lines = max(0, len(lines) - len(merged))
        compact = "\n".join(merged)
        compact += (
            f"\n\n...[交接上下文已压缩，省略 {omitted_lines} 行；"
            "如需细节请按需 read_file/search_code 复核]..."
        )

        if len(compact) <= max_chars:
            return compact
        return self._head_tail_compact(compact, max_chars=max_chars)

    def _compact_readme_context(self, readme_context: str, max_chars: int = 2600) -> str:
        """
        压缩 README 业务逻辑摘要，避免文档段落过长拖慢首轮推理。
        """
        text = (readme_context or "").strip()
        if not text:
            return ""
        if len(text) <= max_chars:
            return text

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return self._head_tail_compact(text, max_chars=max_chars)

        head_lines = lines[:28]
        tail_lines = lines[-10:] if len(lines) > 28 else []
        markers = (
            "fee",
            "oracle",
            "liquid",
            "upgrade",
            "governance",
            "mint",
            "burn",
            "withdraw",
            "deposit",
            "swap",
            "权限",
            "清算",
            "预言机",
            "费率",
            "升级",
            "治理",
            "取款",
            "存款",
            "兑换",
            "风险",
            "机制",
        )

        signal_lines: List[str] = []
        for line in lines:
            lower = line.lower()
            if any(marker in lower for marker in markers):
                signal_lines.append(line)
            if len(signal_lines) >= 40:
                break

        merged: List[str] = []
        seen = set()
        for line in head_lines + signal_lines + tail_lines:
            if line in seen:
                continue
            seen.add(line)
            merged.append(line)

        omitted_lines = max(0, len(lines) - len(merged))
        compact = "\n".join(merged)
        compact += (
            f"\n\n...[README 业务上下文已压缩，省略 {omitted_lines} 行；"
            "必要时请分段 read_file README 原文]..."
        )

        if len(compact) <= max_chars:
            return compact
        return self._head_tail_compact(compact, max_chars=max_chars)

    @staticmethod
    def _apply_initial_message_budget(initial_message: str, max_chars: int = 14000) -> str:
        """对首轮提示词做预算控制，防止首 token 超时。"""
        if len(initial_message) <= max_chars:
            return initial_message

        compact = re.sub(r"\n{3,}", "\n\n", initial_message).strip()
        if len(compact) <= max_chars:
            return compact

        head_len = int(max_chars * 0.72)
        tail_len = max(1200, max_chars - head_len)
        omitted = max(0, len(compact) - head_len - tail_len)

        return (
            f"{compact[:head_len]}\n\n"
            f"...[系统已压缩初始上下文，省略 {omitted} 字符；如需细节请后续按 read_file 分段读取]...\n\n"
            f"{compact[-tail_len:]}"
        )

    @staticmethod
    def _is_readme_behavior_mismatch_finding(finding: Dict[str, Any]) -> bool:
        """判断发现是否属于 README/文档 与代码行为不一致。"""
        text_fields = [
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("context", ""),
            finding.get("summary", ""),
            finding.get("suggestion", ""),
        ]
        blob = " ".join(str(x).lower() for x in text_fields if x)
        if not blob:
            return False

        # 中英文关键词混合匹配，覆盖常见表达
        has_readme_or_doc = any(
            marker in blob
            for marker in (
                "readme",
                "documentation",
                "documented",
                "spec",
                "specification",
                "文档",
                "说明",
                "规格",
                "白皮书",
            )
        )
        has_mismatch = any(
            marker in blob
            for marker in (
                "mismatch",
                "inconsistent",
                "not aligned",
                "deviate",
                "differs from",
                "does not match",
                "不一致",
                "不匹配",
                "偏离",
                "与代码行为不符",
                "与实现不一致",
            )
        )
        return has_readme_or_doc and has_mismatch

    @staticmethod
    def _should_suppress_external_address_noise(finding: Dict[str, Any]) -> bool:
        """
        抑制 Solidity 常见误报：
        脚本里硬编码 Permit2/token0/token1 等外部地址，不应按密钥泄露/敏感数据直接报漏洞。
        """
        vuln_type = str(finding.get("vulnerability_type", "")).lower()
        pattern_name = str(finding.get("pattern_name", "")).lower()

        related_to_secret_rule = (
            vuln_type in {"hardcoded_secret", "sensitive_data_exposure"}
            or "硬编码密钥" in pattern_name
            or "sensitive" in pattern_name
        )
        if not related_to_secret_rule:
            return False

        file_path = str(finding.get("file_path", "")).lower()
        text_fields = [
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("context", ""),
            finding.get("summary", ""),
            finding.get("matched_line", ""),
            finding.get("code_snippet", ""),
            finding.get("suggestion", ""),
        ]
        blob = " ".join(str(x).lower() for x in text_fields if x)
        if not blob:
            return False

        # 必须是包含地址字面量的场景
        has_address_literal = bool(re.search(r"0x[a-f0-9]{40}", blob, re.IGNORECASE))
        if not has_address_literal:
            return False

        # 常见非敏感外部地址命名
        has_external_identifier = any(
            token in blob
            for token in (
                "permit2",
                "token0",
                "token1",
                "weth",
                "usdc",
                "usdt",
                "router",
                "factory",
                "quoter",
            )
        )
        if not has_external_identifier:
            return False

        # 避免误抑制真实私钥/助记词泄露
        has_real_secret_marker = any(
            marker in blob
            for marker in (
                "private key",
                "begin private key",
                "mnemonic",
                "seed phrase",
                "keystore",
                "私钥",
                "助记词",
            )
        )
        if has_real_secret_marker:
            return False

        # 优先抑制部署脚本与测试文件中的外部地址常量噪声
        looks_like_script = (
            file_path.endswith((".s.sol", ".ts", ".js", ".py"))
            and ("script" in file_path or "deploy" in file_path or "test" in file_path)
        )
        looks_like_solidity_config = file_path.endswith(".sol")
        return looks_like_script or looks_like_solidity_config


    
    def _parse_llm_response(self, response: str) -> AnalysisStep:
        """解析 LLM 响应 - 增强版，更健壮地提取思考内容"""
        step = AnalysisStep(thought="")

        # 🔥 v2.1: 预处理 - 移除 Markdown 格式标记（LLM 有时会输出 **Action:** 而非 Action:）
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned_response)

        # 🔥 首先尝试提取明确的 Thought 标记
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|Final Answer:|$)', cleaned_response, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # 🔥 检查是否是最终答案
        final_match = re.search(r'Final Answer:\s*(.*?)$', cleaned_response, re.DOTALL)
        if final_match:
            step.is_final = True
            answer_text = final_match.group(1).strip()
            answer_text = re.sub(r'```json\s*', '', answer_text)
            answer_text = re.sub(r'```\s*', '', answer_text)
            # 使用增强的 JSON 解析器
            step.final_answer = AgentJsonParser.parse(
                answer_text,
                default={"findings": [], "raw_answer": answer_text}
            )
            # 确保 findings 格式正确
            if "findings" in step.final_answer:
                step.final_answer["findings"] = [
                    f for f in step.final_answer["findings"]
                    if isinstance(f, dict)
                ]

            # 🔥 如果没有提取到 thought，使用 Final Answer 前的内容作为思考
            if not step.thought:
                before_final = cleaned_response[:cleaned_response.find('Final Answer:')].strip()
                if before_final:
                    before_final = re.sub(r'^Thought:\s*', '', before_final)
                    step.thought = before_final[:500] if len(before_final) > 500 else before_final

            return step

        # 🔥 提取 Action
        action_match = re.search(r'Action:\s*(\w+)', cleaned_response)
        if action_match:
            step.action = action_match.group(1).strip()

            # 🔥 如果没有提取到 thought，提取 Action 之前的内容作为思考
            if not step.thought:
                action_pos = cleaned_response.find('Action:')
                if action_pos > 0:
                    before_action = cleaned_response[:action_pos].strip()
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # 🔥 提取 Action Input
        input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|$)', cleaned_response, re.DOTALL)
        if input_match:
            input_text = input_match.group(1).strip()
            input_text = re.sub(r'```json\s*', '', input_text)
            input_text = re.sub(r'```\s*', '', input_text)
            # 使用增强的 JSON 解析器
            step.action_input = AgentJsonParser.parse(
                input_text,
                default={"raw_input": input_text}
            )

        # 🔥 最后的 fallback：如果整个响应没有任何标记，整体作为思考
        if not step.thought and not step.action and not step.is_final:
            if response.strip():
                step.thought = response.strip()[:500]

        return step

    @staticmethod
    def _is_rag_auth_failure(tool_name: str, observation: str) -> bool:
        """判断是否是 RAG 认证失败（401）"""
        if tool_name not in {"rag_query", "security_search", "function_context"}:
            return False

        obs = (observation or "").lower()
        rag_auth_markers = (
            "401",
            "unauthorized",
            "authentication failed",
            "invalid_api_key",
            "incorrect api key",
            "api 认证失败",
            "认证失败",
            "access denied",
        )
        return any(marker in obs for marker in rag_auth_markers)

    @staticmethod
    def _build_search_code_fallback_hint() -> str:
        """RAG 401 时引导 LLM 改用 search_code 精确定位"""
        return (
            "⚠️ 系统提示: 检测到 RAG 工具认证失败（401/Unauthorized）。\n"
            "请立即切换到 search_code 精确检索流程，并使用 read_file 验证上下文：\n"
            "1. 先用 search_code 精确查函数/危险调用（不要泛搜）\n"
            "2. Solidity 优先关键词: delegatecall, tx.origin, selfdestruct, call{value:\n"
            "3. JavaScript 优先关键词: child_process.exec, eval(, innerHTML, jwt.verify\n"
            "4. 查询示例: {\"keyword\":\"delegatecall\",\"file_pattern\":\"*.sol\"} / "
            "{\"keyword\":\"child_process.exec\",\"file_pattern\":\"*.js\"}\n"
            "5. 命中后立即 read_file 读取函数上下文，再继续漏洞判断"
        )

    @staticmethod
    def _infer_kunlun_language(tech_stack: Dict[str, Any]) -> str:
        """根据技术栈推断 Kunlun-M 的语言参数"""
        languages = tech_stack.get("languages", []) if isinstance(tech_stack, dict) else []
        lang_text = " ".join(str(lang).lower() for lang in languages)

        if "solidity" in lang_text:
            return "solidity"
        if "php" in lang_text:
            return "php"
        return "javascript"

    def _build_parallel_scan_inputs(
        self,
        primary_action: str,
        primary_input: Dict[str, Any],
        tech_stack: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """构建优先并行扫描输入参数（slither/mythril/kunlun/npm）"""
        npm_input: Dict[str, Any] = {"target_path": "."}
        kunlun_input: Dict[str, Any] = {
            "target_path": ".",
            "language": self._infer_kunlun_language(tech_stack),
        }
        slither_input: Dict[str, Any] = {"target_path": "."}
        mythril_input: Dict[str, Any] = {
            "target_path": ".",
            "execution_timeout": 90,
            "max_files": 8,
        }

        if primary_action == "npm_audit":
            npm_input.update(primary_input or {})
        elif primary_action == "kunlun_scan":
            kunlun_input.update(primary_input or {})
        elif primary_action == "slither_scan":
            slither_input.update(primary_input or {})
        elif primary_action == "mythril_scan":
            mythril_input.update(primary_input or {})

        if not kunlun_input.get("language"):
            kunlun_input["language"] = self._infer_kunlun_language(tech_stack)

        return {
            "npm_audit": npm_input,
            "kunlun_scan": kunlun_input,
            "slither_scan": slither_input,
            "mythril_scan": mythril_input,
        }

    async def _execute_parallel_priority_scans(
        self,
        primary_action: str,
        primary_input: Dict[str, Any],
        tech_stack: Dict[str, Any],
        scan_group: Set[str],
    ) -> str:
        """并行执行指定优先扫描组"""
        scan_inputs = self._build_parallel_scan_inputs(primary_action, primary_input, tech_stack)

        preferred_order = ["slither_scan", "mythril_scan", "kunlun_scan", "npm_audit"]
        ordered_actions = [action for action in preferred_order if action in scan_group and action in self.tools]

        tasks = [self.execute_tool(action, scan_inputs[action]) for action in ordered_actions]
        outputs = await asyncio.gather(*tasks)

        group_name = " + ".join(ordered_actions)
        sections = [f"🚀 已并行执行关键外部扫描: {group_name}"]
        for action in ordered_actions:
            sections.append(f"{action} 输入: {json.dumps(scan_inputs[action], ensure_ascii=False)}")

        sections.append("")
        for action, output in zip(ordered_actions, outputs):
            sections.append(f"=== {action} 结果 ===")
            sections.append(str(output))
            sections.append("")

        return "\n".join(sections).strip()
    

    
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """
        执行漏洞分析 - LLM 全程参与！
        """
        import time
        start_time = time.time()
        
        project_info = input_data.get("project_info", {})
        config = input_data.get("config", {})
        plan = input_data.get("plan", {})
        previous_results = input_data.get("previous_results", {})
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        
        # 🔥 处理交接信息
        handoff = input_data.get("handoff")
        if handoff:
            from .base import TaskHandoff
            if isinstance(handoff, dict):
                handoff = TaskHandoff.from_dict(handoff)
            self.receive_handoff(handoff)
        
        # 从 Recon 结果获取上下文
        recon_data = previous_results.get("recon", {})
        if isinstance(recon_data, dict) and "data" in recon_data:
            recon_data = recon_data["data"]
        
        tech_stack = recon_data.get("tech_stack", {})
        entry_points = recon_data.get("entry_points", [])
        high_risk_areas = recon_data.get("high_risk_areas", plan.get("high_risk_areas", []))
        initial_findings = recon_data.get("initial_findings", [])
        
        # 🔥 构建包含交接上下文的初始消息
        handoff_context = self.get_handoff_context()
        
        # 🔥 获取目标文件列表
        target_files = config.get("target_files", [])
        project_root = input_data.get("project_root", project_info.get("root", "."))
        is_solidity = self._is_solidity_project(tech_stack, project_info, target_files)
        solidity_readme_context = ""
        if is_solidity:
            solidity_readme_context = self._build_solidity_readme_context(project_root, target_files=target_files)
            raw_readme_len = len(solidity_readme_context)
            solidity_readme_context = self._compact_readme_context(solidity_readme_context, max_chars=2600)
            if raw_readme_len and len(solidity_readme_context) < raw_readme_len:
                await self.emit_event(
                    "info",
                    f"🧹 已压缩 README 业务上下文: {raw_readme_len} -> {len(solidity_readme_context)} 字符"
                )
                self.add_insight(
                    f"README 业务上下文压缩 {raw_readme_len - len(solidity_readme_context)} 字符"
                )
            if solidity_readme_context:
                self.add_insight("已从 README 提取 Solidity 业务逻辑上下文，用于业务逻辑漏洞审计")
                await self.emit_event("info", "📘 已自动读取 README，并提炼 Solidity 业务逻辑上下文")
            else:
                await self.emit_event("info", "📘 未找到可用 README 业务上下文，将按代码行为继续业务逻辑审计")

        initial_message = f"""请开始对项目进行安全漏洞分析。

## 项目信息
- 名称: {project_info.get('name', 'unknown')}
- 语言: {tech_stack.get('languages', [])}
- 框架: {tech_stack.get('frameworks', [])}

"""
        if is_solidity:
            protocol_types = self._detect_protocol_type(solidity_readme_context, target_files)

            if solidity_readme_context:
                initial_message += f"""## 🧭 Solidity 业务逻辑上下文（自动提取自 README）
{solidity_readme_context}

请将以上信息作为业务审计输入，重点核对代码与 README 声明是否一致；若出现明显偏差，请按 business_logic 漏洞报告并给出影响路径。

"""
            else:
                initial_message += """## 🧭 Solidity 业务逻辑审计要求
当前未提取到 README 业务上下文。请优先读取项目 README/文档文件，再结合代码进行业务逻辑漏洞审计（资金流、状态机、权限边界、不变量）。

"""
            if protocol_types:
                initial_message += f"""## 🔍 检测到的协议类型
当前项目疑似包含以下协议类型：**{", ".join(protocol_types)}**
请在下方业务逻辑分析指南的 Step 4 中，**优先**执行对应类型的专项清单。

"""
            initial_message += self._build_solidity_focus_guide(protocol_types) + "\n"
        # 🔥 如果指定了目标文件，明确告知 Agent
        if target_files:
            initial_message += f"""## ⚠️ 审计范围
用户指定了 {len(target_files)} 个目标文件进行审计：
"""
            for tf in target_files[:8]:
                initial_message += f"- {self._shorten_text(tf, max_len=120)}\n"
            if len(target_files) > 8:
                initial_message += f"- ... 还有 {len(target_files) - 8} 个文件\n"
            initial_message += """
请直接分析这些指定的文件，不要分析其他文件。

"""
        
        if handoff_context:
            raw_handoff_len = len(handoff_context)
            compact_context = self._compact_handoff_context(handoff_context, max_chars=4800)
            if len(compact_context) < raw_handoff_len:
                await self.emit_event(
                    "info",
                    f"🧹 已压缩 Agent 交接上下文: {raw_handoff_len} -> {len(compact_context)} 字符"
                )
                self.add_insight(
                    f"交接上下文压缩 {raw_handoff_len - len(compact_context)} 字符"
                )
        else:
            compact_context = self._build_compact_recon_context(
                high_risk_areas=high_risk_areas,
                entry_points=entry_points,
                initial_findings=initial_findings,
            )
        initial_message += f"""{compact_context}

## 任务
{task_context or task or '进行全面的安全漏洞分析，发现代码中的安全问题。'}

## ⚠️ 分析策略要求
1. **首先**：使用 read_file 读取上面列出的高风险文件
2. **然后**：分析这些文件中的安全问题
3. **最后**：如果需要，使用 smart_scan 或其他工具扩展分析

**禁止**：不要跳过高风险区域直接做全局扫描

## 目标漏洞类型
{config.get('target_vulnerabilities', ['all'])}

## 可用工具
{self.get_tools_description()}

请开始你的安全分析。首先读取高风险区域的文件，然后**立即**分析其中的安全问题（输出 Action）。"""

        raw_initial_len = len(initial_message)
        initial_message = self._apply_initial_message_budget(initial_message, max_chars=14000)
        if len(initial_message) < raw_initial_len:
            await self.emit_event(
                "info",
                f"🧹 已压缩 Analysis 初始上下文: {raw_initial_len} -> {len(initial_message)} 字符"
            )
            self.add_insight(f"初始上下文压缩 {raw_initial_len - len(initial_message)} 字符，降低首轮超时风险")
        
        # 🔥 记录工作开始
        self.record_work("开始安全漏洞分析")

        # 初始化对话历史
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]
        
        self._steps = []
        all_findings = []
        error_message = None  # 🔥 跟踪错误信息
        completed_priority_scans: Set[str] = set()
        available_tool_names = set(self.tools.keys())
        parallel_priority_groups: List[Set[str]] = []
        if {"slither_scan", "mythril_scan"}.issubset(available_tool_names):
            parallel_priority_groups.append({"slither_scan", "mythril_scan"})
        if {"kunlun_scan", "npm_audit"}.issubset(available_tool_names):
            parallel_priority_groups.append({"kunlun_scan", "npm_audit"})
        
        await self.emit_thinking("🔬 Analysis Agent 启动，LLM 开始自主安全分析...")
        
        try:
            for iteration in range(self.config.max_iterations):
                if self.is_cancelled:
                    break
                
                self._iteration = iteration + 1
                
                # 🔥 再次检查取消标志（在LLM调用之前）
                if self.is_cancelled:
                    await self.emit_thinking("🛑 任务已取消，停止执行")
                    break
                
                # 调用 LLM 进行思考和决策（流式输出）
                # 🔥 使用用户配置的 temperature 和 max_tokens
                try:
                    llm_output, tokens_this_round = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                except asyncio.CancelledError:
                    logger.info(f"[{self.name}] LLM call cancelled")
                    break
                
                self._total_tokens += tokens_this_round

                # 🔥 Enhanced: Handle empty LLM response with better diagnostics
                if not llm_output or not llm_output.strip():
                    empty_retry_count = getattr(self, '_empty_retry_count', 0) + 1
                    self._empty_retry_count = empty_retry_count
                    
                    # 🔥 记录更详细的诊断信息
                    logger.warning(
                        f"[{self.name}] Empty LLM response in iteration {self._iteration} "
                        f"(retry {empty_retry_count}/3, tokens_this_round={tokens_this_round})"
                    )
                    
                    if empty_retry_count >= 3:
                        logger.error(f"[{self.name}] Too many empty responses, generating fallback result")
                        error_message = "连续收到空响应，使用回退结果"
                        await self.emit_event("warning", error_message)
                        # 🔥 不是直接 break，而是尝试生成一个回退结果
                        break
                    
                    # 🔥 更有针对性的重试提示
                    retry_prompt = f"""收到空响应。请根据以下格式输出你的思考和行动：

Thought: [你对当前安全分析情况的思考]
Action: [工具名称，如 read_file, search_code, pattern_match, semgrep_scan]
Action Input: {{"参数名": "参数值"}}

可用工具: {', '.join(self.tools.keys())}

如果你已完成分析，请输出：
Thought: [总结所有发现]
Final Answer: {{"findings": [...], "summary": "..."}}"""
                    
                    self._conversation_history.append({
                        "role": "user",
                        "content": retry_prompt,
                    })
                    continue
                
                # 重置空响应计数器
                self._empty_retry_count = 0

                # 检测超时错误输出，强制压缩上下文后重试
                if llm_output.startswith("[超时错误:") or llm_output.startswith("[LLM调用错误:"):
                    logger.warning(f"[{self.name}] LLM timeout/error detected, forcing context compression")
                    self._conversation_history = self.compress_messages_if_needed(
                        self._conversation_history, max_tokens=20000
                    )
                    continue

                # 解析 LLM 响应
                step = self._parse_llm_response(llm_output)
                self._steps.append(step)
                
                # 🔥 发射 LLM 思考内容事件 - 展示安全分析的思考过程
                if step.thought:
                    await self.emit_llm_thought(step.thought, iteration + 1)
                
                # 添加 LLM 响应到历史
                self._conversation_history.append({
                    "role": "assistant",
                    "content": llm_output,
                })
                
                # 检查是否完成
                if step.is_final:
                    await self.emit_llm_decision("完成安全分析", "LLM 判断分析已充分")
                    logger.info(f"[{self.name}] Received Final Answer: {step.final_answer}")
                    if step.final_answer and "findings" in step.final_answer:
                        all_findings = step.final_answer["findings"]
                        logger.info(f"[{self.name}] Final Answer contains {len(all_findings)} findings")
                        # 🔥 发射每个发现的事件
                        for finding in all_findings[:5]:  # 限制数量
                            await self.emit_finding(
                                finding.get("title", "Unknown"),
                                finding.get("severity", "medium"),
                                finding.get("vulnerability_type", "other"),
                                finding.get("file_path", "")
                            )
                            # 🔥 记录洞察
                            self.add_insight(
                                f"发现 {finding.get('severity', 'medium')} 级别漏洞: {finding.get('title', 'Unknown')}"
                            )
                    else:
                        logger.warning(f"[{self.name}] Final Answer has no 'findings' key or is None: {step.final_answer}")
                    
                    # 🔥 记录工作完成
                    self.record_work(f"完成安全分析，发现 {len(all_findings)} 个潜在漏洞")
                    
                    await self.emit_llm_complete(
                        f"分析完成，发现 {len(all_findings)} 个潜在漏洞",
                        self._total_tokens
                    )
                    break
                
                # 执行工具
                if step.action:
                    # 🔥 发射 LLM 动作决策事件
                    await self.emit_llm_action(step.action, step.action_input or {})
                    
                    # 🔥 循环检测：追踪工具调用失败历史
                    tool_call_key = f"{step.action}:{json.dumps(step.action_input or {}, sort_keys=True)}"
                    if not hasattr(self, '_failed_tool_calls'):
                        self._failed_tool_calls = {}
                    
                    action_input = step.action_input or {}
                    pending_group: Optional[Set[str]] = None
                    for group in parallel_priority_groups:
                        if step.action in group and not group.issubset(completed_priority_scans):
                            pending_group = group
                            break

                    if pending_group:
                        observation = await self._execute_parallel_priority_scans(
                            step.action,
                            action_input,
                            tech_stack,
                            pending_group,
                        )
                        completed_priority_scans.update(pending_group)
                    else:
                        observation = await self.execute_tool(step.action, action_input)
                        if any(step.action in group for group in parallel_priority_groups):
                            completed_priority_scans.add(step.action)
                    
                    # 🔥 检测工具调用失败并追踪
                    is_tool_error = (
                        "失败" in observation or 
                        "错误" in observation or 
                        "不存在" in observation or
                        "文件过大" in observation or
                        "Error" in observation
                    )
                    
                    if is_tool_error:
                        self._failed_tool_calls[tool_call_key] = self._failed_tool_calls.get(tool_call_key, 0) + 1
                        fail_count = self._failed_tool_calls[tool_call_key]
                        
                        # 🔥 如果同一调用连续失败3次，添加强制跳过提示
                        if fail_count >= 3:
                            logger.warning(f"[{self.name}] Tool call failed {fail_count} times: {tool_call_key}")
                            observation += f"\n\n⚠️ **系统提示**: 此工具调用已连续失败 {fail_count} 次。请：\n"
                            observation += "1. 尝试使用不同的参数（如指定较小的行范围）\n"
                            observation += "2. 使用 search_code 工具定位关键代码片段\n"
                            observation += "3. 跳过此文件，继续分析其他文件\n"
                            observation += "4. 如果已有足够发现，直接输出 Final Answer"
                            
                            # 重置计数器但保留记录
                            self._failed_tool_calls[tool_call_key] = 0
                    else:
                        # 成功调用，重置失败计数
                        if tool_call_key in self._failed_tool_calls:
                            del self._failed_tool_calls[tool_call_key]

                    rag_auth_failed = self._is_rag_auth_failure(step.action, observation)
                    if rag_auth_failed:
                        logger.warning(f"[{self.name}] RAG auth failure detected, forcing search_code fallback")
                        observation += "\n\n" + self._build_search_code_fallback_hint()
                    
                    # 🔥 工具执行后检查取消状态
                    if self.is_cancelled:
                        logger.info(f"[{self.name}] Cancelled after tool execution")
                        break
                    
                    step.observation = observation
                    
                    # 🔥 发射 LLM 观察事件
                    await self.emit_llm_observation(observation)
                    
                    # 添加观察结果到历史
                    self._conversation_history.append({
                        "role": "user",
                        "content": self.format_observation_for_history(
                            observation,
                            tool_name=step.action,
                        ),
                    })
                    if rag_auth_failed:
                        self._conversation_history.append({
                            "role": "user",
                            "content": "请立即执行 search_code 精确搜索关键函数（含 file_pattern），随后用 read_file 验证具体代码上下文。",
                        })
                else:
                    # LLM 没有选择工具，提示它继续
                    await self.emit_llm_decision("继续分析", "LLM 需要更多分析")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "请继续分析。你输出了 Thought 但没有输出 Action。请**立即**选择一个工具执行，或者如果分析完成，输出 Final Answer 汇总所有发现。",
                    })
            
            # 🔥 如果循环结束但没有发现，强制 LLM 总结
            if not all_findings and not self.is_cancelled and not error_message:
                await self.emit_thinking("📝 分析阶段结束，正在生成漏洞总结...")
                
                # 添加强制总结的提示
                self._conversation_history.append({
                    "role": "user",
                    "content": """分析阶段已结束。请立即输出 Final Answer，总结你发现的所有安全问题。

即使没有发现严重漏洞，也请总结你的分析过程和观察到的潜在风险点。

请按以下 JSON 格式输出：
```json
{
    "findings": [
        {
            "vulnerability_type": "sql_injection|xss|command_injection|path_traversal|ssrf|hardcoded_secret|other",
            "severity": "critical|high|medium|low",
            "title": "漏洞标题",
            "description": "详细描述",
            "file_path": "文件路径",
            "line_start": 行号,
            "code_snippet": "相关代码片段",
            "suggestion": "修复建议"
        }
    ],
    "summary": "分析总结"
}
```

Final Answer:""",
                })
                
                try:
                    summary_output, _ = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                    
                    if summary_output and summary_output.strip():
                        # 解析总结输出
                        import re
                        summary_text = summary_output.strip()
                        summary_text = re.sub(r'```json\s*', '', summary_text)
                        summary_text = re.sub(r'```\s*', '', summary_text)
                        parsed_result = AgentJsonParser.parse(
                            summary_text,
                            default={"findings": [], "summary": ""}
                        )
                        if "findings" in parsed_result:
                            all_findings = parsed_result["findings"]
                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to generate summary: {e}")
            
            # 处理结果
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 🔥 如果被取消，返回取消结果
            if self.is_cancelled:
                await self.emit_event(
                    "info",
                    f"🛑 Analysis Agent 已取消: {len(all_findings)} 个发现, {self._iteration} 轮迭代"
                )
                return AgentResult(
                    success=False,
                    error="任务已取消",
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 🔥 如果有错误，返回失败结果
            if error_message:
                await self.emit_event(
                    "error",
                    f"❌ Analysis Agent 失败: {error_message}"
                )
                return AgentResult(
                    success=False,
                    error=error_message,
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 标准化发现
            logger.info(f"[{self.name}] Standardizing {len(all_findings)} findings")
            standardized_findings = []
            suppressed_external_address_noise = 0
            for finding in all_findings:
                # 确保 finding 是字典
                if not isinstance(finding, dict):
                    logger.warning(f"Skipping invalid finding (not a dict): {finding}")
                    continue

                if self._should_suppress_external_address_noise(finding):
                    suppressed_external_address_noise += 1
                    logger.info(
                        f"[{self.name}] Suppressed external-address noise finding: "
                        f"{finding.get('title', 'N/A')} ({finding.get('file_path', '')})"
                    )
                    continue
                    
                standardized = {
                    "vulnerability_type": finding.get("vulnerability_type", "other"),
                    "severity": finding.get("severity", "medium"),
                    "title": finding.get("title", "Unknown Finding"),
                    "description": finding.get("description", ""),
                    "file_path": finding.get("file_path", ""),
                    "line_start": finding.get("line_start") or finding.get("line", 0),
                    "code_snippet": finding.get("code_snippet", ""),
                    "source": finding.get("source", ""),
                    "sink": finding.get("sink", ""),
                    "suggestion": finding.get("suggestion", ""),
                    "confidence": finding.get("confidence", 0.7),
                    "needs_verification": finding.get("needs_verification", True),
                    "pattern_name": finding.get("pattern_name"),
                }

                if not standardized.get("pattern_name") and self._is_readme_behavior_mismatch_finding(finding):
                    standardized["pattern_name"] = README_MISMATCH_PATTERN_NAME

                # 高危业务逻辑漏洞必须进入二次验证阶段（即使上游误设为 False）
                vuln_type = str(standardized.get("vulnerability_type", "")).lower()
                severity = str(standardized.get("severity", "")).lower()
                if vuln_type == "business_logic" and severity in {"critical", "high"}:
                    standardized["needs_verification"] = True
                    standardized["verification_priority"] = "mandatory_secondary"

                standardized_findings.append(standardized)

            if suppressed_external_address_noise > 0:
                await self.emit_event(
                    "info",
                    f"🧹 已抑制 {suppressed_external_address_noise} 个硬编码外部地址噪声告警（Permit2/token0/token1 等）",
                )
            
            await self.emit_event(
                "info",
                f"Analysis Agent 完成: {len(standardized_findings)} 个发现, {self._iteration} 轮迭代, {self._tool_calls} 次工具调用"
            )

            # 🔥 CRITICAL: Log final findings count before returning
            logger.info(f"[{self.name}] Returning {len(standardized_findings)} standardized findings")

            # 🔥 创建 TaskHandoff - 传递给 Verification Agent
            handoff = self._create_analysis_handoff(standardized_findings)

            return AgentResult(
                success=True,
                data={
                    "findings": standardized_findings,
                    "steps": [
                        {
                            "thought": s.thought,
                            "action": s.action,
                            "action_input": s.action_input,
                            "observation": s.observation[:500] if s.observation else None,
                        }
                        for s in self._steps
                    ],
                },
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,  # 🔥 添加 handoff
            )
            
        except Exception as e:
            logger.error(f"Analysis Agent failed: {e}", exc_info=True)
            return AgentResult(success=False, error=str(e))
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史"""
        return self._conversation_history

    def get_steps(self) -> List[AnalysisStep]:
        """获取执行步骤"""
        return self._steps

    def _create_analysis_handoff(self, findings: List[Dict[str, Any]]) -> TaskHandoff:
        """
        创建 Analysis Agent 的任务交接信息

        Args:
            findings: 分析发现的漏洞列表

        Returns:
            TaskHandoff 对象，供 Verification Agent 使用
        """
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "low"), 3)
        )

        # 提取关键发现（优先高危漏洞）
        key_findings = sorted_findings[:15]

        # 构建建议行动 - 哪些漏洞需要优先验证
        suggested_actions = []
        for f in sorted_findings[:10]:
            suggested_actions.append({
                "action": "verify_vulnerability",
                "target": f.get("file_path", ""),
                "line": f.get("line_start", 0),
                "vulnerability_type": f.get("vulnerability_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "priority": "high" if f.get("severity") in ["critical", "high"] else "normal",
                "reason": f.get("title", "需要验证")
            })

        # 统计漏洞类型和严重程度
        severity_counts = {}
        type_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            vtype = f.get("vulnerability_type", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        # 构建洞察
        insights = [
            f"发现 {len(findings)} 个潜在漏洞需要验证",
            f"严重程度分布: Critical={severity_counts.get('critical', 0)}, "
            f"High={severity_counts.get('high', 0)}, "
            f"Medium={severity_counts.get('medium', 0)}, "
            f"Low={severity_counts.get('low', 0)}",
        ]

        # 最常见的漏洞类型
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            insights.append(f"主要漏洞类型: {', '.join([f'{t}({c})' for t, c in top_types])}")

        # 需要关注的文件
        attention_points = []
        files_with_findings = {}
        for f in findings:
            fp = f.get("file_path", "")
            if fp:
                files_with_findings[fp] = files_with_findings.get(fp, 0) + 1

        for fp, count in sorted(files_with_findings.items(), key=lambda x: x[1], reverse=True)[:10]:
            attention_points.append(f"{fp} ({count}个漏洞)")

        # 优先验证的区域 - 高危漏洞所在文件
        priority_areas = []
        for f in sorted_findings[:10]:
            if f.get("severity") in ["critical", "high"]:
                fp = f.get("file_path", "")
                if fp and fp not in priority_areas:
                    priority_areas.append(fp)

        # 上下文数据
        context_data = {
            "severity_distribution": severity_counts,
            "vulnerability_types": type_counts,
            "files_with_findings": files_with_findings,
        }

        # 构建摘要
        high_count = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        summary = f"完成代码分析: 发现{len(findings)}个漏洞, 其中{high_count}个高危"

        return self.create_handoff(
            to_agent="verification",
            summary=summary,
            key_findings=key_findings,
            suggested_actions=suggested_actions,
            attention_points=attention_points,
            priority_areas=priority_areas,
            context_data=context_data,
        )
