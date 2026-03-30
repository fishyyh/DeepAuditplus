"""
智能批量扫描工具
整合多种扫描能力，一次性完成多项安全检查

设计目的：
1. 减少 LLM 需要做的工具调用次数
2. 提供更完整的扫描概览
3. 自动选择最适合的扫描策略
"""

import os
import re
import asyncio
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass, field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


class SmartScanInput(BaseModel):
    """智能扫描输入"""
    target: str = Field(
        default=".",
        description="扫描目标：可以是目录路径、文件路径或文件模式（如 '*.py'）"
    )
    scan_types: Optional[List[str]] = Field(
        default=None,
        description="扫描类型列表。可选: pattern, secret, dependency, consistency, all。默认为 all"
    )
    focus_vulnerabilities: Optional[List[str]] = Field(
        default=None,
        description="重点关注的漏洞类型，如 ['sql_injection', 'xss', 'command_injection']"
    )
    max_files: int = Field(default=50, description="最大扫描文件数")
    quick_mode: bool = Field(default=False, description="快速模式：只扫描高风险文件")


class SmartScanTool(AgentTool):
    """
    智能批量扫描工具
    
    自动整合多种扫描能力：
    - 危险模式匹配 (pattern)
    - 密钥泄露检测 (secret)
    - 依赖漏洞检查 (dependency)
    
    特点：
    1. 自动识别项目类型和技术栈
    2. 智能选择最适合的扫描策略
    3. 按风险级别汇总结果
    4. 一次调用完成多项检查
    """
    
    # 高风险文件模式
    HIGH_RISK_PATTERNS = [
        r'.*auth.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*login.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*user.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*api.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*view.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*route.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*controller.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*model.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*db.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*sql.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*upload.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*file.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*exec.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*admin.*\.(py|js|ts|tsx|jsx|java|php|swift|m|mm|kt|rs|go)$',
        r'.*config.*\.(py|js|ts|tsx|jsx|json|yaml|yml|xml|properties|plist)$',
        r'.*setting.*\.(py|js|ts|tsx|jsx|json|yaml|yml|xml|properties|plist)$',
        r'.*secret.*\.(py|js|ts|tsx|jsx|json|yaml|yml|xml|properties|plist)$',
        r'.*\.env.*$',
        r'.*Info\.plist$',
        r'.*AndroidManifest\.xml$',
        r'.*contract.*\.sol$',
        r'.*token.*\.sol$',
        r'.*vault.*\.sol$',
        r'.*proxy.*\.sol$',
        r'.*\.sol$',
    ]
    
    # 危险模式库（精简版，用于快速扫描）
    QUICK_PATTERNS = {
        "sql_injection": [
            (r'execute\s*\([^)]*%', "SQL格式化"),
            (r'execute\s*\([^)]*\+', "SQL拼接"),
            (r'execute\s*\(.*f["\']', "SQL f-string"),
            (r'\.query\s*\([^)]*\+', "Query拼接"),
            (r'raw\s*\([^)]*%', "Raw SQL"),
            (r'sqlite3_exec\s*\(', "SQLite3 Exec"),
            (r'NSPredicate\(format:', "NSPredicate Format"),
        ],
        "command_injection": [
            (r'os\.system\s*\(', "os.system"),
            (r'subprocess.*shell\s*=\s*True', "shell=True"),
            (r'eval\s*\(', "eval()"),
            (r'exec\s*\(', "exec()"),
            (r'Process\s*\(\s*launchPath:', "Swift Process"),
            (r'NSTask\s*\.launch', "NSTask Launch"),
        ],
        "xss": [
            (r'innerHTML\s*=', "innerHTML"),
            (r'v-html\s*=', "v-html"),
            (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML"),
            (r'\|\s*safe\b', "safe filter"),
            (r'mark_safe\s*\(', "mark_safe"),
            (r'loadHTMLString', "WebView Load HTML"),
            (r'evaluateJavaScript', "WebView JS Exec"),
        ],
        "path_traversal": [
            (r'open\s*\([^)]*\+', "open拼接"),
            (r'send_file\s*\([^)]*request', "send_file"),
            (r'include\s*\(\s*\$', "include变量"),
        ],
        "hardcoded_secret": [
            (r'password\s*=\s*["\'][^"\']{4,}["\']', "硬编码密码"),
            (r'api_?key\s*=\s*["\'][^"\']{8,}["\']', "硬编码API Key"),
            (r'secret\s*=\s*["\'][^"\']{8,}["\']', "硬编码Secret"),
            (r'-----BEGIN.*PRIVATE KEY-----', "私钥"),
        ],
        "ssrf": [
            (r'requests\.(get|post)\s*\([^)]*request\.', "requests用户URL"),
            (r'fetch\s*\([^)]*req\.', "fetch用户URL"),
        ],
        # Solidity 常见高风险模式
        "auth_bypass": [
            (r'tx\.origin', "tx.origin 认证"),
            (
                r'function\s+(?:mint|burn|pause|unpause|set\w+|upgrade\w*|withdraw\w*)\s*\([^)]*\)\s*(?:public|external)(?![^;\n{]*(?:onlyOwner|onlyRole|auth|requiresAuth))',
                "敏感函数疑似缺少访问控制修饰符",
            ),
        ],
        "race_condition": [
            (r'\.call\s*\{\s*value\s*:', "低级 call.value 外部调用"),
            (r'\.call\.value\s*\(', "旧语法 call.value"),
            (r'\.send\s*\(', "send 转账"),
            (r'\.transfer\s*\(', "transfer 转账"),
        ],
        "code_injection": [
            (r'delegatecall\s*\(', "delegatecall"),
            (r'callcode\s*\(', "callcode"),
            (r'assembly\s*\{', "内联 assembly"),
            (r'selfdestruct\s*\(', "selfdestruct"),
            (r'suicide\s*\(', "suicide (已废弃)"),
        ],
        "business_logic": [
            (r'block\.timestamp', "使用 block.timestamp"),
            (r'blockhash\s*\(', "使用 blockhash"),
            (r'block\.prevrandao', "使用 block.prevrandao"),
            (r'keccak256\s*\([^)]*(?:block\.timestamp|blockhash|block\.prevrandao|msg\.sender|tx\.origin)', "可预测随机源"),
            (r'for\s*\([^)]*;\s*[^;]*\.length\s*;\s*[^)]*\)', "基于动态数组长度的循环（潜在Gas DoS）"),
        ],
        "sensitive_data_exposure": [
            (r'\b(?:string|bytes|bytes32)\s+(?:public|private|internal)\s+\w*(?:secret|password|key|token)\w*', "链上敏感数据字段"),
        ],
    }
    
    def __init__(self, project_root: str):
        super().__init__()
        self.project_root = project_root
    
    @property
    def name(self) -> str:
        return "smart_scan"
    
    @property
    def description(self) -> str:
        return """🚀 智能批量安全扫描工具 - 一次调用完成多项检查

这是 Analysis Agent 的首选工具！在分析开始时优先使用此工具获取项目安全概览。

功能：
- 自动识别高风险文件
- 批量检测多种漏洞模式
- 按严重程度汇总结果
- 支持快速模式和完整模式

使用示例:
- 快速全面扫描: {"target": ".", "quick_mode": true}
- 扫描特定目录: {"target": "src/api", "scan_types": ["pattern"]}
- 聚焦特定漏洞: {"target": ".", "focus_vulnerabilities": ["sql_injection", "xss"]}

扫描类型:
- pattern: 危险代码模式匹配
- secret: 密钥泄露检测
- consistency: 跨文件一致性检查（部署脚本 vs 合约实现，重点 Solidity）
- all: 所有类型（默认）

输出：按风险级别分类的发现汇总，可直接用于制定进一步分析策略。"""
    
    @property
    def args_schema(self):
        return SmartScanInput
    
    async def _execute(
        self,
        target: str = ".",
        scan_types: Optional[List[str]] = None,
        focus_vulnerabilities: Optional[List[str]] = None,
        max_files: int = 50,
        quick_mode: bool = False,
        **kwargs
    ) -> ToolResult:
        """执行智能扫描"""
        scan_types = scan_types or ["all"]
        
        # 收集要扫描的文件
        files_to_scan = await self._collect_files(target, max_files, quick_mode)
        
        if not files_to_scan:
            return ToolResult(
                success=True,
                data=f"在目标 '{target}' 中未找到可扫描的文件",
                metadata={"files_scanned": 0}
            )
        
        # 执行扫描
        all_findings = []
        files_with_issues = set()
        
        for file_path in files_to_scan:
            file_findings = await self._scan_file(file_path, focus_vulnerabilities)
            if file_findings:
                all_findings.extend(file_findings)
                files_with_issues.add(file_path)

        # Solidity 业务逻辑增强：跨文件一致性检查（部署脚本 vs 合约实现）
        if self._should_run_consistency_scan(scan_types, focus_vulnerabilities):
            consistency_findings = await self._scan_solidity_consistency(target)
            if consistency_findings:
                all_findings.extend(consistency_findings)
                for finding in consistency_findings:
                    file_path = finding.get("file_path")
                    if file_path:
                        files_with_issues.add(file_path)
        
        # 生成报告
        return self._generate_report(
            files_to_scan, 
            files_with_issues, 
            all_findings,
            quick_mode
        )

    def _should_run_consistency_scan(
        self,
        scan_types: Optional[List[str]],
        focus_vulnerabilities: Optional[List[str]],
    ) -> bool:
        """判断是否执行 Solidity 跨文件一致性扫描。"""
        selected_scan_types = set(scan_types or ["all"])
        if "all" not in selected_scan_types and "consistency" not in selected_scan_types:
            return False

        if not focus_vulnerabilities:
            return True

        focus_set = {v.lower() for v in focus_vulnerabilities}
        return bool(
            {"business_logic", "auth_bypass", "race_condition", "reentrancy", "code_injection"} & focus_set
        )

    def _collect_solidity_context_files(self, target: str, max_files: int = 220) -> List[str]:
        """
        收集 Solidity 业务逻辑扫描上下文文件（合约 + 部署脚本）。
        返回相对 project_root 的路径。
        """
        full_target = os.path.join(self.project_root, target)
        if not os.path.exists(full_target):
            full_target = self.project_root

        skip_dirs = {
            ".git", "node_modules", "vendor", "lib", "artifacts", "cache",
            "dist", "build", "out", ".next", ".turbo"
        }
        candidates: List[str] = []

        for root, dirs, files in os.walk(full_target):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                lower_name = filename.lower()
                rel_path = os.path.relpath(os.path.join(root, filename), self.project_root)
                if lower_name.endswith(".sol"):
                    candidates.append(rel_path)
                elif (
                    lower_name.endswith((".s.sol", ".js", ".ts", ".py"))
                    and ("deploy" in lower_name or "script" in rel_path.lower())
                ):
                    candidates.append(rel_path)

                if len(candidates) >= max_files:
                    return candidates

        return candidates

    @staticmethod
    def _line_no(content: str, marker: str) -> int:
        """根据子串定位近似行号。"""
        idx = content.find(marker)
        if idx < 0:
            return 0
        return content[:idx].count("\n") + 1

    @staticmethod
    def _line_no_by_regex(content: str, pattern: str) -> int:
        """根据正则定位近似行号。"""
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        if not match:
            return 0
        return content[:match.start()].count("\n") + 1

    @staticmethod
    def _line_text(content: str, line_number: int) -> str:
        """获取指定行文本，用于报告展示。"""
        if line_number <= 0:
            return ""
        lines = content.split("\n")
        if line_number > len(lines):
            return ""
        return lines[line_number - 1].strip()[:220]

    def _best_line_no(
        self,
        content: str,
        markers: Optional[List[str]] = None,
        regex_patterns: Optional[List[str]] = None,
    ) -> int:
        """优先按 marker 定位，再按 regex 定位。"""
        for marker in markers or []:
            line_no = self._line_no(content, marker)
            if line_no > 0:
                return line_no

        for pattern in regex_patterns or []:
            line_no = self._line_no_by_regex(content, pattern)
            if line_no > 0:
                return line_no

        return 1

    def _build_consistency_finding(
        self,
        file_path: str,
        content: str,
        pattern_name: str,
        summary: str,
        context: str,
        severity: str,
        markers: Optional[List[str]] = None,
        regex_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """统一构建 Solidity 一致性扫描发现，确保包含可定位代码行。"""
        line_number = self._best_line_no(content, markers=markers, regex_patterns=regex_patterns)
        line_text = self._line_text(content, line_number)
        return {
            "vulnerability_type": "business_logic",
            "pattern_name": pattern_name,
            "file_path": file_path,
            "line_number": line_number,
            "matched_line": line_text or summary,
            "summary": summary,
            "context": context,
            "severity": severity,
            "code_snippet": line_text or None,
        }

    async def _scan_solidity_consistency(self, target: str) -> List[Dict[str, Any]]:
        """
        Solidity 合约业务逻辑跨文件一致性扫描。
        聚焦部署脚本/Hook 配置/记账口径等高价值逻辑问题。
        """
        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        def add_finding(finding: Dict[str, Any]) -> None:
            key = (
                finding.get("pattern_name"),
                finding.get("file_path"),
                finding.get("line_number"),
            )
            if key in seen_keys:
                return
            seen_keys.add(key)
            findings.append(finding)

        files = self._collect_solidity_context_files(target)
        if not files:
            return findings

        contents: Dict[str, str] = {}
        for rel_path in files:
            full_path = os.path.join(self.project_root, rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    contents[rel_path] = f.read()
            except Exception:
                continue

        script_files = [
            p for p in contents
            if p.lower().endswith((".s.sol", ".js", ".ts", ".py"))
            and ("deploy" in p.lower() or "script" in p.lower())
        ]
        contract_files = [p for p in contents if p.lower().endswith(".sol")]

        # 规则1：beforeSwap 直接用 sender 做用户统计（router 身份误用）
        for path in contract_files:
            text = contents[path]
            if (
                re.search(r"function\s+_?beforeSwap\s*\(\s*address\s+sender", text, re.IGNORECASE)
                and (
                    re.search(r"addressSwappedAmount\s*\[\s*sender\s*\]\s*\+?=", text)
                    or re.search(r"addressLastSwapBlock\s*\[\s*sender\s*\]\s*=", text)
                )
            ):
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="router_sender_identity_misuse",
                        summary="beforeSwap 中使用 sender 直接记账，可能把 router 当成真实用户",
                        context="建议核查 sender 语义并按真实用户维度统计风控状态。",
                        severity="critical",
                        regex_patterns=[
                            r"addressSwappedAmount\s*\[\s*sender\s*\]\s*\+?=",
                            r"addressLastSwapBlock\s*\[\s*sender\s*\]\s*=",
                        ],
                    )
                )

        # 规则2：phase 重置仅清空 address(0)
        for path in contract_files:
            text = contents[path]
            if (
                re.search(r"function\s+_?resetPerAddressTracking\s*\(", text, re.IGNORECASE)
                and re.search(r"address\s*\(\s*0\s*\)", text)
            ):
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="phase_reset_only_zero_address",
                        summary="阶段重置逻辑仅重置 address(0)，真实用户状态可能未清理",
                        context="建议改为 phase 分桶统计或按用户懒重置。",
                        severity="high",
                        regex_patterns=[r"address\s*\(\s*0\s*\)"],
                    )
                )

        # 规则3：全局状态疑似未按 PoolId 隔离
        for path in contract_files:
            text = contents[path]
            has_global_phase_state = bool(
                re.search(r"\b(currentPhase|launchStartBlock|lastPhaseUpdateBlock|initialLiquidity)\b", text)
            )
            has_after_init = bool(re.search(r"function\s+_?afterInitialize\s*\(", text))
            writes_global = bool(
                re.search(r"(currentPhase|launchStartBlock|lastPhaseUpdateBlock|initialLiquidity)\s*=", text)
            )
            has_per_pool_state = bool(re.search(r"mapping\s*\(\s*PoolId\s*=>", text))

            if has_global_phase_state and has_after_init and writes_global and not has_per_pool_state:
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="pool_state_not_isolated",
                        summary="Hook 生命周期状态疑似全局共享，可能存在跨池状态污染",
                        context="建议将阶段/流动性/用户统计改为 PoolId 作用域。",
                        severity="critical",
                        regex_patterns=[r"(currentPhase|launchStartBlock|lastPhaseUpdateBlock|initialLiquidity)\s*="],
                    )
                )

        # 规则4：Hook 权限位脚本与合约声明不一致（BEFORE/AFTER_INITIALIZE）
        contract_after_init_true = False
        contract_before_init_true = False
        for path in contract_files:
            text = contents[path]
            if re.search(r"function\s+getHookPermissions\s*\(", text):
                if re.search(r"afterInitialize\s*:\s*true", text):
                    contract_after_init_true = True
                if re.search(r"beforeInitialize\s*:\s*true", text):
                    contract_before_init_true = True

        for path in script_files:
            text = contents[path]
            has_before_flag = "Hooks.BEFORE_INITIALIZE_FLAG" in text
            has_after_flag = "Hooks.AFTER_INITIALIZE_FLAG" in text
            mismatch = (
                (contract_after_init_true and has_before_flag and not has_after_flag)
                or (contract_before_init_true and has_after_flag and not has_before_flag)
            )
            if mismatch:
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="hook_permission_flag_mismatch",
                        summary="部署脚本 Hook flags 与合约 getHookPermissions 声明疑似不一致",
                        context="建议统一 BEFORE/AFTER_INITIALIZE 权限位来源并在部署前断言一致。",
                        severity="high",
                        regex_patterns=[r"Hooks\.(BEFORE|AFTER)_INITIALIZE_FLAG"],
                    )
                )

        # 规则5：HookMiner deployer 参数疑似错配 / 常量未定义
        for path in script_files:
            text = contents[path]
            has_hookminer = "HookMiner.find(" in text
            has_factory_arg = bool(re.search(r"HookMiner\.find\s*\(\s*CREATE2_FACTORY", text))
            has_start_broadcast = "startBroadcast" in text
            has_salt_deploy = bool(re.search(r"new\s+\w+\s*\{\s*salt\s*:", text))
            create2_factory_commented = bool(re.search(r"//\s*address\s+constant\s+CREATE2_FACTORY", text))

            if has_hookminer and has_factory_arg and has_start_broadcast and has_salt_deploy:
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="hookminer_deployer_mismatch",
                        summary="HookMiner 挖矿地址与实际部署者可能不一致，存在地址错配风险",
                        context="建议使用实际 deployer 地址参与挖矿并校验 address(hook)==mined。",
                        severity="medium",
                        regex_patterns=[r"HookMiner\.find\s*\("],
                    )
                )
            if has_hookminer and create2_factory_commented and has_factory_arg:
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="undefined_create2_factory_constant",
                        summary="CREATE2_FACTORY 疑似注释/未定义但仍被引用",
                        context="建议修复常量定义并保证脚本可编译、可复现部署地址。",
                        severity="medium",
                        regex_patterns=[r"CREATE2_FACTORY"],
                    )
                )

        # 规则6：amountSpecified 绝对值统一记账，疑似 exact in/out 口径错误
        abs_amount_pattern = (
            r"amountSpecified\s*<\s*0\s*\?\s*uint256\s*\(\s*-\s*params\.amountSpecified\s*\)\s*:\s*uint256\s*\(\s*params\.amountSpecified\s*\)"
        )
        for path in contract_files:
            text = contents[path]
            if re.search(abs_amount_pattern, text):
                add_finding(
                    self._build_consistency_finding(
                        file_path=path,
                        content=text,
                        pattern_name="swap_amount_accounting_mismatch",
                        summary="swapAmount 对 amountSpecified 正负统一绝对值，疑似 exact in/out 记账偏差",
                        context="建议基于 afterSwap BalanceDelta 按方向记账，避免误触发限额/惩罚。",
                        severity="high",
                        regex_patterns=[abs_amount_pattern],
                    )
                )

        return findings
    
    async def _collect_files(
        self, 
        target: str, 
        max_files: int, 
        quick_mode: bool
    ) -> List[str]:
        """收集要扫描的文件"""
        full_path = os.path.normpath(os.path.join(self.project_root, target))
        
        # 安全检查
        if not full_path.startswith(os.path.normpath(self.project_root)):
            return []
        
        files = []
        
        # 排除目录
        exclude_dirs = {
            'node_modules', '__pycache__', '.git', 'venv', '.venv',
            'build', 'dist', 'target', '.idea', '.vscode', 'vendor',
            'coverage', '.pytest_cache', '.mypy_cache',
        }
        
        # 支持的代码文件扩展名
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php',
            '.go', '.rb', '.cs', '.c', '.cpp', '.h', '.hpp',
            '.swift', '.m', '.mm', '.kt', '.rs', '.sh', '.bat',
            '.vue', '.html', '.htm', '.xml', '.gradle', '.properties',
            '.sol',
        }
        
        # 配置文件扩展名
        config_extensions = {'.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.plist', '.conf'}
        
        all_extensions = code_extensions | config_extensions
        
        if os.path.isfile(full_path):
            return [os.path.relpath(full_path, self.project_root)]
        
        for root, dirs, filenames in os.walk(full_path):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in all_extensions:
                    continue
                
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, self.project_root)
                
                # 快速模式：只扫描高风险文件
                if quick_mode:
                    is_high_risk = any(
                        re.search(pattern, rel_path, re.IGNORECASE)
                        for pattern in self.HIGH_RISK_PATTERNS
                    )
                    if not is_high_risk:
                        continue
                
                files.append(rel_path)
                
                if len(files) >= max_files:
                    break
            
            if len(files) >= max_files:
                break
        
        return files
    
    async def _scan_file(
        self, 
        file_path: str,
        focus_vulnerabilities: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """扫描单个文件"""
        full_path = os.path.join(self.project_root, file_path)
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"无法读取文件 {file_path}: {e}")
            return []
        
        lines = content.split('\n')
        findings = []
        
        # 确定要检查的漏洞类型
        vuln_types = focus_vulnerabilities or list(self.QUICK_PATTERNS.keys())
        
        for vuln_type in vuln_types:
            patterns = self.QUICK_PATTERNS.get(vuln_type, [])
            
            for pattern, pattern_name in patterns:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            # 获取上下文
                            start = max(0, i - 1)
                            end = min(len(lines), i + 2)
                            context = '\n'.join(lines[start:end])
                            
                            findings.append({
                                "vulnerability_type": vuln_type,
                                "pattern_name": pattern_name,
                                "file_path": file_path,
                                "line_number": i + 1,
                                "matched_line": line.strip()[:150],
                                "context": context[:300],
                                "severity": self._get_severity(vuln_type),
                            })
                except re.error:
                    continue
        
        return findings
    
    def _get_severity(self, vuln_type: str) -> str:
        """获取漏洞严重程度"""
        severity_map = {
            "sql_injection": "high",
            "command_injection": "critical",
            "xss": "high",
            "path_traversal": "high",
            "ssrf": "high",
            "hardcoded_secret": "medium",
            "auth_bypass": "high",
            "race_condition": "critical",
            "reentrancy": "critical",
            "code_injection": "high",
            "business_logic": "medium",
            "sensitive_data_exposure": "medium",
        }
        return severity_map.get(vuln_type, "medium")
    
    def _generate_report(
        self,
        files_scanned: List[str],
        files_with_issues: set,
        findings: List[Dict],
        quick_mode: bool
    ) -> ToolResult:
        """生成扫描报告"""
        
        # 按严重程度分组
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            sev = f.get("severity", "medium")
            by_severity[sev].append(f)
        
        # 按漏洞类型分组
        by_type = {}
        for f in findings:
            vtype = f.get("vulnerability_type", "unknown")
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(f)
        
        # 构建报告
        output_parts = [
            f"🔍 智能安全扫描报告",
            f"{'(快速模式)' if quick_mode else '(完整模式)'}",
            "",
            f"📊 扫描概览:",
            f"- 扫描文件数: {len(files_scanned)}",
            f"- 有问题文件: {len(files_with_issues)}",
            f"- 总发现数: {len(findings)}",
            "",
        ]
        
        # 严重程度统计
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        output_parts.append("📈 按严重程度分布:")
        for sev in ["critical", "high", "medium", "low"]:
            count = len(by_severity[sev])
            if count > 0:
                output_parts.append(f"  {severity_icons[sev]} {sev.upper()}: {count}")
        
        output_parts.append("")
        
        # 漏洞类型统计
        if by_type:
            output_parts.append("📋 按漏洞类型分布:")
            for vtype, vfindings in sorted(by_type.items(), key=lambda x: -len(x[1])):
                output_parts.append(f"  - {vtype}: {len(vfindings)}")
        
        output_parts.append("")
        
        # 详细发现（按严重程度排序，最多显示15个）
        if findings:
            output_parts.append("⚠️ 重点发现 (按严重程度排序):")
            shown = 0
            for sev in ["critical", "high", "medium", "low"]:
                for f in by_severity[sev][:5]:  # 每个级别最多5个
                    if shown >= 15:
                        break
                    icon = severity_icons[f["severity"]]
                    output_parts.append(f"\n{icon} [{f['severity'].upper()}] {f['vulnerability_type']}")
                    output_parts.append(f"   📍 {f['file_path']}:{f['line_number']}")
                    output_parts.append(f"   🔍 模式: {f['pattern_name']}")
                    output_parts.append(f"   📝 代码: {f['matched_line'][:80]}")
                    shown += 1
                if shown >= 15:
                    break
            
            if len(findings) > 15:
                output_parts.append(f"\n... 还有 {len(findings) - 15} 个发现")
        
        # 建议的下一步
        output_parts.append("")
        output_parts.append("💡 建议的下一步:")
        
        if by_severity["critical"]:
            output_parts.append("  1. ⚠️ 优先处理 CRITICAL 级别问题 - 使用 read_file 深入分析")
        if by_severity["high"]:
            output_parts.append("  2. 🔍 分析 HIGH 级别问题的上下文和数据流")
        if files_with_issues:
            top_files = list(files_with_issues)[:3]
            output_parts.append(f"  3. 📁 重点审查这些文件: {', '.join(top_files)}")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "files_scanned": len(files_scanned),
                "files_with_issues": len(files_with_issues),
                "total_findings": len(findings),
                "by_severity": {k: len(v) for k, v in by_severity.items()},
                "by_type": {k: len(v) for k, v in by_type.items()},
                "findings": findings[:20],
                "high_risk_files": list(files_with_issues)[:10],
            }
        )


class QuickAuditInput(BaseModel):
    """快速审计输入"""
    file_path: str = Field(description="要审计的文件路径")
    deep_analysis: bool = Field(
        default=True,
        description="是否进行深度分析（包括上下文和数据流分析）"
    )


class QuickAuditTool(AgentTool):
    """
    快速文件审计工具
    
    对单个文件进行全面的安全审计，包括：
    - 模式匹配
    - 上下文分析
    - 风险评估
    - 修复建议
    """
    
    def __init__(self, project_root: str):
        super().__init__()
        self.project_root = project_root
    
    @property
    def name(self) -> str:
        return "quick_audit"
    
    @property
    def description(self) -> str:
        return """🎯 快速文件审计工具 - 对单个文件进行全面安全分析

当 smart_scan 发现高风险文件后，使用此工具进行深入审计。

功能：
- 全面的模式匹配
- 代码结构分析
- 风险评估和优先级排序
- 具体的修复建议

使用示例:
- {"file_path": "app/views.py", "deep_analysis": true}

适用场景：
- smart_scan 发现的高风险文件
- 需要详细分析的可疑代码
- 生成具体的修复建议"""
    
    @property
    def args_schema(self):
        return QuickAuditInput
    
    async def _execute(
        self,
        file_path: str,
        deep_analysis: bool = True,
        **kwargs
    ) -> ToolResult:
        """执行快速审计"""
        full_path = os.path.join(self.project_root, file_path)
        
        # 安全检查
        if not os.path.normpath(full_path).startswith(os.path.normpath(self.project_root)):
            return ToolResult(success=False, error="安全错误：路径越界")
        
        if not os.path.exists(full_path):
            return ToolResult(success=False, error=f"文件不存在: {file_path}")
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return ToolResult(success=False, error=f"读取文件失败: {str(e)}")
        
        lines = content.split('\n')
        
        # 分析结果
        audit_result = {
            "file_path": file_path,
            "total_lines": len(lines),
            "findings": [],
            "code_metrics": {},
            "recommendations": [],
        }
        
        # 代码指标
        audit_result["code_metrics"] = {
            "total_lines": len(lines),
            "non_empty_lines": len([l for l in lines if l.strip()]),
            "comment_lines": len([l for l in lines if l.strip().startswith(('#', '//', '/*', '*'))]),
        }
        
        # 执行模式匹配
        from .pattern_tool import PatternMatchTool
        pattern_tool = PatternMatchTool(self.project_root)
        
        # 使用完整的模式库进行扫描
        for vuln_type, config in pattern_tool.PATTERNS.items():
            patterns_dict = config.get("patterns", {})
            
            # 检测语言
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {".py": "python", ".js": "javascript", ".ts": "javascript", 
                       ".php": "php", ".java": "java", ".go": "go", ".sol": "solidity"}
            language = lang_map.get(ext)
            
            patterns_to_check = patterns_dict.get(language, [])
            patterns_to_check.extend(patterns_dict.get("_common", []))
            
            for pattern, pattern_name in patterns_to_check:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = '\n'.join(f"{start+j+1}: {lines[start+j]}" for j in range(end-start))
                            
                            finding = {
                                "vulnerability_type": vuln_type,
                                "pattern_name": pattern_name,
                                "severity": config.get("severity", "medium"),
                                "line_number": i + 1,
                                "matched_line": line.strip()[:150],
                                "context": context,
                                "description": config.get("description", ""),
                                "cwe_id": config.get("cwe_id", ""),
                            }
                            
                            # 深度分析：添加修复建议
                            if deep_analysis:
                                finding["recommendation"] = self._get_recommendation(vuln_type)
                            
                            audit_result["findings"].append(finding)
                except re.error:
                    continue
        
        # 生成报告
        return self._format_audit_report(audit_result)
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            "sql_injection": "使用参数化查询或 ORM。例如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "command_injection": "避免使用 shell=True，使用参数列表传递命令。验证和清理所有用户输入。",
            "xss": "对所有用户输入进行 HTML 实体编码。使用框架自带的模板转义功能。",
            "path_traversal": "使用白名单验证文件路径。确保路径不包含 .. 序列。使用 os.path.basename() 提取文件名。",
            "ssrf": "验证 URL 白名单。禁止访问内部 IP 地址和保留地址。",
            "hardcoded_secret": "使用环境变量或密钥管理服务存储敏感信息。",
            "deserialization": "避免反序列化不可信数据。使用安全的序列化格式如 JSON。",
            "weak_crypto": "使用 SHA-256 或更强的哈希算法。使用 AES-256-GCM 进行加密。",
            "auth_bypass": "避免使用 tx.origin 做权限校验，改用 msg.sender 并结合 OpenZeppelin Ownable/AccessControl。",
            "race_condition": "遵循 Checks-Effects-Interactions 模式并添加 ReentrancyGuard，避免在状态更新前进行外部调用。",
            "reentrancy": "遵循 Checks-Effects-Interactions 模式并添加 ReentrancyGuard，避免在状态更新前进行外部调用。",
            "code_injection": "避免不受信任目标的 delegatecall/callcode；若必须使用，限定白名单并验证实现合约。",
            "business_logic": "不要将 block.timestamp/blockhash 用于关键随机性或经济安全逻辑，改用可验证随机源。",
            "sensitive_data_exposure": "不要在链上存储明文密钥、口令、私有业务秘密；private 不能防止链上读取。",
        }
        return recommendations.get(vuln_type, "请手动审查此代码段的安全性。")
    
    def _format_audit_report(self, audit_result: Dict) -> ToolResult:
        """格式化审计报告"""
        findings = audit_result["findings"]
        
        output_parts = [
            f"📋 文件审计报告: {audit_result['file_path']}",
            "",
            f"📊 代码统计:",
            f"  - 总行数: {audit_result['code_metrics']['total_lines']}",
            f"  - 有效代码: {audit_result['code_metrics']['non_empty_lines']}",
            "",
        ]
        
        if not findings:
            output_parts.append("✅ 未发现已知的安全问题")
        else:
            # 按严重程度分组
            by_severity = {"critical": [], "high": [], "medium": [], "low": []}
            for f in findings:
                by_severity[f["severity"]].append(f)
            
            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            
            output_parts.append(f"⚠️ 发现 {len(findings)} 个潜在问题:")
            output_parts.append("")
            
            for sev in ["critical", "high", "medium", "low"]:
                for f in by_severity[sev]:
                    icon = severity_icons[sev]
                    output_parts.append(f"{icon} [{sev.upper()}] {f['vulnerability_type']}")
                    output_parts.append(f"   📍 第 {f['line_number']} 行: {f['pattern_name']}")
                    output_parts.append(f"   💻 代码: {f['matched_line'][:80]}")
                    if f.get("cwe_id"):
                        output_parts.append(f"   🔗 CWE: {f['cwe_id']}")
                    if f.get("recommendation"):
                        output_parts.append(f"   💡 建议: {f['recommendation'][:100]}")
                    output_parts.append("")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "file_path": audit_result["file_path"],
                "findings_count": len(findings),
                "findings": findings,
                "code_metrics": audit_result["code_metrics"],
            }
        )
