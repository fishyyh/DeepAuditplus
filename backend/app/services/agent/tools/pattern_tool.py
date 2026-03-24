"""
模式匹配工具
快速扫描代码中的危险模式

优化版本：
- 支持直接扫描文件（无需先读取）
- 支持传入代码内容扫描
- 增强的漏洞模式库（OWASP Top 10 2025）
- 更好的输出格式化
"""

import os
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass

from .base import AgentTool, ToolResult


@dataclass
class PatternMatch:
    """模式匹配结果"""
    pattern_name: str
    pattern_type: str
    file_path: str
    line_number: int
    matched_text: str
    context: str
    severity: str
    description: str
    cwe_id: str = ""  # 🔥 添加 CWE ID 引用


class PatternMatchInput(BaseModel):
    """模式匹配输入 - 支持两种模式"""
    # 🔥 模式1: 传入代码内容
    code: Optional[str] = Field(
        default=None, 
        description="要扫描的代码内容（与 scan_file 二选一）"
    )
    # 🔥 模式2: 直接扫描文件
    scan_file: Optional[str] = Field(
        default=None,
        description="要扫描的文件路径（相对于项目根目录，与 code 二选一）"
    )
    file_path: str = Field(default="unknown", description="文件路径（用于上下文）")
    pattern_types: Optional[List[str]] = Field(
        default=None,
        description="要检测的漏洞类型列表，如 ['sql_injection', 'xss']。为空则检测所有类型"
    )
    language: Optional[str] = Field(default=None, description="编程语言，用于选择特定模式")


class PatternMatchTool(AgentTool):
    """
    模式匹配工具
    使用正则表达式快速扫描代码中的危险模式
    """
    
    def __init__(self, project_root: str = None):
        """
        初始化模式匹配工具
        
        Args:
            project_root: 项目根目录（可选，用于上下文）
        """
        super().__init__()
        self.project_root = project_root
    
    # 危险模式定义
    PATTERNS: Dict[str, Dict[str, Any]] = {
        # SQL 注入模式
        "sql_injection": {
            "patterns": {
                "python": [
                    (r'cursor\.execute\s*\(\s*["\'].*%[sd].*["\'].*%', "格式化字符串构造SQL"),
                    (r'cursor\.execute\s*\(\s*f["\']', "f-string构造SQL"),
                    (r'cursor\.execute\s*\([^,)]+\+', "字符串拼接构造SQL"),
                    (r'\.execute\s*\(\s*["\'][^"\']*\{', "format()构造SQL"),
                    (r'text\s*\(\s*["\'].*\+.*["\']', "SQLAlchemy text()拼接"),
                ],
                "javascript": [
                    (r'\.query\s*\(\s*[`"\'].*\$\{', "模板字符串构造SQL"),
                    (r'\.query\s*\(\s*["\'].*\+', "字符串拼接构造SQL"),
                    (r'mysql\.query\s*\([^,)]+\+', "MySQL查询拼接"),
                ],
                "java": [
                    (r'Statement.*execute.*\+', "Statement字符串拼接"),
                    (r'createQuery\s*\([^,)]+\+', "JPA查询拼接"),
                    (r'\.executeQuery\s*\([^,)]+\+', "executeQuery拼接"),
                ],
                "php": [
                    (r'mysql_query\s*\(\s*["\'].*\.\s*\$', "mysql_query拼接"),
                    (r'mysqli_query\s*\([^,]+,\s*["\'].*\.\s*\$', "mysqli_query拼接"),
                    (r'\$pdo->query\s*\(\s*["\'].*\.\s*\$', "PDO query拼接"),
                ],
                "go": [
                    (r'\.Query\s*\([^,)]+\+', "Query字符串拼接"),
                    (r'\.Exec\s*\([^,)]+\+', "Exec字符串拼接"),
                    # 匹配 db.QueryXxx(fmt.Sprintf(...)) 或 fmt.Sprintf 包含 SQL 关键词
                    (r'(?:\.Query|\.Exec|\.QueryRow)\w*\s*\([^)]*fmt\.Sprintf', "Sprintf 结果传入 db 方法（SQL 注入风险）"),
                    (r'fmt\.Sprintf\s*\([^,)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b', "Sprintf 构造含 SQL 关键词的字符串"),
                ],
            },
            "severity": "high",
            "description": "SQL注入漏洞：用户输入直接拼接到SQL语句中",
        },
        
        # XSS 模式
        "xss": {
            "patterns": {
                "javascript": [
                    (r'innerHTML\s*=\s*[^;]+', "innerHTML赋值"),
                    (r'outerHTML\s*=\s*[^;]+', "outerHTML赋值"),
                    (r'document\.write\s*\(', "document.write"),
                    (r'\.html\s*\([^)]+\)', "jQuery html()"),
                    (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
                ],
                "python": [
                    (r'\|\s*safe\b', "Django safe过滤器"),
                    (r'Markup\s*\(', "Flask Markup"),
                    (r'mark_safe\s*\(', "Django mark_safe"),
                ],
                "php": [
                    (r'echo\s+\$_(?:GET|POST|REQUEST)', "直接输出用户输入"),
                    (r'print\s+\$_(?:GET|POST|REQUEST)', "打印用户输入"),
                ],
                "java": [
                    (r'out\.print(?:ln)?\s*\([^)]*request\.getParameter', "直接输出请求参数"),
                ],
            },
            "severity": "high",
            "description": "XSS跨站脚本漏洞：未转义的用户输入被渲染到页面",
        },
        
        # 命令注入模式
        "command_injection": {
            "patterns": {
                "python": [
                    (r'os\.system\s*\([^)]*\+', "os.system拼接"),
                    (r'os\.system\s*\([^)]*%', "os.system格式化"),
                    (r'os\.system\s*\(\s*f["\']', "os.system f-string"),
                    (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', "shell=True"),
                    (r'subprocess\.(?:call|run|Popen)\s*\(\s*["\'][^"\']+%', "subprocess格式化"),
                    (r'eval\s*\(', "eval()"),
                    (r'exec\s*\(', "exec()"),
                ],
                "javascript": [
                    (r'exec\s*\([^)]+\+', "exec拼接"),
                    (r'spawn\s*\([^)]+,\s*\{[^}]*shell:\s*true', "spawn shell"),
                    (r'eval\s*\(', "eval()"),
                    (r'Function\s*\(', "Function构造器"),
                ],
                "php": [
                    (r'exec\s*\(\s*\$', "exec变量"),
                    (r'system\s*\(\s*\$', "system变量"),
                    (r'passthru\s*\(\s*\$', "passthru变量"),
                    (r'shell_exec\s*\(\s*\$', "shell_exec变量"),
                    (r'`[^`]*\$[^`]*`', "反引号命令执行"),
                ],
                "java": [
                    (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]+\+', "Runtime.exec拼接"),
                    (r'ProcessBuilder[^;]+\+', "ProcessBuilder拼接"),
                ],
                "go": [
                    (r'exec\.Command\s*\([^)]+\+', "exec.Command拼接"),
                ],
            },
            "severity": "critical",
            "description": "命令注入漏洞：用户输入被用于执行系统命令",
        },
        
        # 路径遍历模式
        "path_traversal": {
            "patterns": {
                "python": [
                    (r'open\s*\([^)]*\+', "open()拼接"),
                    (r'open\s*\([^)]*%', "open()格式化"),
                    (r'os\.path\.join\s*\([^)]*request', "join用户输入"),
                    (r'send_file\s*\([^)]*request', "send_file用户输入"),
                ],
                "javascript": [
                    (r'fs\.read(?:File|FileSync)\s*\([^)]+\+', "readFile拼接"),
                    (r'path\.join\s*\([^)]*req\.', "path.join用户输入"),
                    (r'res\.sendFile\s*\([^)]+\+', "sendFile拼接"),
                ],
                "php": [
                    (r'include\s*\(\s*\$', "include变量"),
                    (r'require\s*\(\s*\$', "require变量"),
                    (r'file_get_contents\s*\(\s*\$', "file_get_contents变量"),
                    (r'fopen\s*\(\s*\$', "fopen变量"),
                ],
                "java": [
                    (r'new\s+File\s*\([^)]+request\.getParameter', "File构造用户输入"),
                    (r'new\s+FileInputStream\s*\([^)]+\+', "FileInputStream拼接"),
                ],
            },
            "severity": "high",
            "description": "路径遍历漏洞：用户可以访问任意文件",
        },
        
        # SSRF 模式
        "ssrf": {
            "patterns": {
                "python": [
                    (r'requests\.(?:get|post|put|delete)\s*\([^)]*request\.', "requests用户URL"),
                    (r'urllib\.request\.urlopen\s*\([^)]*request\.', "urlopen用户URL"),
                    (r'httpx\.(?:get|post)\s*\([^)]*request\.', "httpx用户URL"),
                ],
                "javascript": [
                    (r'fetch\s*\([^)]*req\.', "fetch用户URL"),
                    (r'axios\.(?:get|post)\s*\([^)]*req\.', "axios用户URL"),
                    (r'http\.request\s*\([^)]*req\.', "http.request用户URL"),
                ],
                "java": [
                    (r'new\s+URL\s*\([^)]*request\.getParameter', "URL构造用户输入"),
                    (r'HttpClient[^;]+request\.getParameter', "HttpClient用户URL"),
                ],
                "php": [
                    (r'curl_setopt[^;]+CURLOPT_URL[^;]+\$', "curl用户URL"),
                    (r'file_get_contents\s*\(\s*\$_', "file_get_contents用户URL"),
                ],
            },
            "severity": "high",
            "description": "SSRF漏洞：服务端请求用户控制的URL",
        },
        
        # 不安全的反序列化
        "deserialization": {
            "patterns": {
                "python": [
                    (r'pickle\.loads?\s*\(', "pickle反序列化"),
                    (r'yaml\.load\s*\([^)]*(?!Loader)', "yaml.load无安全Loader"),
                    (r'yaml\.unsafe_load\s*\(', "yaml.unsafe_load"),
                    (r'marshal\.loads?\s*\(', "marshal反序列化"),
                ],
                "javascript": [
                    # node-serialize 存在已知 RCE（IIFE payload）
                    (r'require\s*\(\s*["\']node-serialize["\']', "引入 node-serialize（CVE-2017-5941，存在 RCE 漏洞）"),
                    (r'\.unserialize\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)', "unserialize 用户输入（RCE 风险）"),
                    # serialize-javascript eval 组合
                    (r'eval\s*\(\s*serialize\s*\(', "eval(serialize(...)) 组合（RCE 风险）"),
                    # 原型污染：JSON.parse 后直接合并到对象
                    (r'Object\.assign\s*\([^)]*JSON\.parse\s*\([^)]*(?:req\.|body\.)', "JSON.parse 结果直接 Object.assign（原型污染风险）"),
                    (r'__proto__\s*[=\[]', "__proto__ 赋值（原型污染）"),
                ],
                "java": [
                    (r'ObjectInputStream\s*\(', "ObjectInputStream"),
                    (r'XMLDecoder\s*\(', "XMLDecoder"),
                    (r'readObject\s*\(', "readObject"),
                ],
                "php": [
                    (r'unserialize\s*\(\s*\$', "unserialize用户输入"),
                ],
            },
            "severity": "critical",
            "description": "不安全的反序列化：可能导致远程代码执行",
        },

        # 权限绕过（Web + Solidity）
        "auth_bypass": {
            "patterns": {
                "python": [
                    # JWT decode 跳过验证
                    (r'jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature\s*:\s*False', "JWT decode 关闭签名验证"),
                    (r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]*["\']none["\']', "JWT decode 允许 alg=none（签名绕过）"),
                    # PyJWT 不传 algorithms 参数（默认允许 none）
                    (r'jwt\.decode\s*\(\s*\w+\s*,\s*\w+\s*\)', "jwt.decode 未指定 algorithms 参数（可能允许 alg=none）"),
                ],
                "javascript": [
                    # jsonwebtoken verify 选项关闭验证
                    (r'jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*["\']none["\']', "JWT verify 允许 alg=none"),
                    (r'jwt\.decode\s*\((?![^)]*complete)', "jwt.decode 代替 jwt.verify（不验证签名）"),
                    # cookie 未设置 httpOnly / secure
                    (r'res\.cookie\s*\([^)]*\{(?![^}]*httpOnly\s*:\s*true)', "Set-Cookie 疑似缺少 httpOnly 标志"),
                ],
                "java": [
                    # Spring @PreAuthorize / @Secured 缺失（直接暴露的方法）
                    (r'@(?:GetMapping|PostMapping|RequestMapping)\s*\([^)]*\)\s*\n\s*public(?!\s*\w+\s*\w+\s*\(\s*\))', "Controller 方法疑似缺少权限注解（@PreAuthorize/@Secured）"),
                    # JWT 解析不验证签名（parseClaimsJwt 而非 parseClaimsJws）
                    (r'\.parseClaimsJwt\s*\(', "parseClaimsJwt 不验证签名（应使用 parseClaimsJws）"),
                ],
                "php": [
                    # 直接使用 $_SESSION 赋值 role（未校验来源）
                    (r'\$_SESSION\s*\[\s*["\'](?:role|admin|is_admin|user_type)["\']', "直接读写 SESSION 角色字段（确认赋值来源是否可信）"),
                ],
                "solidity": [
                    # tx.origin 作为身份验证依据（可被中间合约伪造）
                    (r'(?:require|if)\s*\([^)]*tx\.origin', "tx.origin 用于权限校验（可被钓鱼合约绕过）"),
                    # owner/admin 赋值未经权限校验
                    (r'owner\s*=\s*msg\.sender', "构造器外直接赋值 owner（需确认有访问控制）"),
                    # 危险的初始化函数（Proxy 模式下可被二次调用）
                    (r'function\s+initialize\s*\([^)]*\)\s*(?:public|external)(?!\s*initializer)', "initialize() 缺少 initializer 修饰符（可被重放）"),
                ],
            },
            "severity": "high",
            "description": "认证/授权绕过风险：权限判断逻辑不安全，可能被攻击者绕过",
        },

        # 重入漏洞（Solidity）- 精准标记高危 .call 模式
        "reentrancy": {
            "patterns": {
                "solidity": [
                    # 无 gas 限制的 ETH 转账（主要重入向量）
                    (r'\.call\s*\{[^}]*value\s*:', "不带 gas 限制的 ETH 低级 call（重入主要向量）"),
                    (r'\.call\.value\s*\(', "旧语法 .call.value()（重入向量）"),
                    # 合约代码中 payable 函数没有 nonReentrant 修饰符
                    (r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*payable(?!\s*\w*nonReentrant)', "payable 函数疑似缺少 nonReentrant 保护"),
                    # 先转账再改状态（违反 CEI 模式的典型特征）
                    (r'\.transfer\s*\([^)]+\)[^;]*;\s*\n[^\n]*\b\w+\[', "transfer 后紧跟状态变更（疑似违反 CEI 原则）"),
                ],
            },
            "severity": "critical",
            "description": "重入漏洞：外部 ETH 转账可能被恶意合约回调重复执行，需遵循 Checks-Effects-Interactions 模式",
        },

        # 危险低级调用（Solidity）- 区分可利用程度
        "code_injection": {
            "patterns": {
                "solidity": [
                    # delegatecall 到用户可控地址（最危险）
                    (r'delegatecall\s*\(', "delegatecall（目标可控时可接管合约存储）"),
                    # callcode 已废弃，仍具危险性
                    (r'callcode\s*\(', "callcode（已废弃，等同危险 delegatecall）"),
                    # selfdestruct / suicide
                    (r'selfdestruct\s*\(', "selfdestruct（可销毁合约并强制转账）"),
                    (r'suicide\s*\(', "suicide（已废弃的 selfdestruct，危险）"),
                    # 内联汇编写存储槽
                    (r'assembly\s*\{[^}]*sstore\s*\(', "assembly 中直接写存储槽（潜在存储污染）"),
                    # create2 可以在确定地址部署恶意代码
                    (r'\bnew\s+\w+\s*\{[^}]*salt\s*:', "CREATE2（需防范地址碰撞攻击）"),
                ],
            },
            "severity": "high",
            "description": "危险低级调用：delegatecall/callcode/selfdestruct 可能导致任意逻辑执行或合约销毁",
        },

        # 业务逻辑安全（Solidity）
        "business_logic": {
            "patterns": {
                "solidity": [
                    # 将链上值直接用作随机源（可被矿工/验证者操控）
                    (r'keccak256\s*\([^)]*(?:block\.timestamp|blockhash|block\.prevrandao|block\.difficulty|msg\.sender|tx\.origin)', "使用可预测的链上值作为随机源"),
                    # 仅用 block.timestamp 作唯一随机熵
                    (r'uint\w*\s+\w+\s*=\s*block\.timestamp\s*%', "block.timestamp 取模作随机（可被操控）"),
                    # 价格依赖单一链上预言机（闪贷攻击面）；去掉 .price() 避免大量误报
                    (r'\.getPrice\s*\(\s*\)|\.latestAnswer\s*\(\s*\)', "单点链上价格查询（getPrice/latestAnswer，建议改用 TWAP 防闪贷操控）"),
                ],
            },
            "severity": "medium",
            "description": "业务逻辑风险：关键逻辑依赖可被操控的链上值（时间戳/随机源/价格预言机）",
        },

        # 敏感数据暴露（Solidity 可见性误解等）
        "sensitive_data_exposure": {
            "patterns": {
                "solidity": [
                    # 链上存储 private 变量仍可被链上读取
                    (r'\b(?:string|bytes|bytes32|uint\w*)\s+private\s+\w*(?:secret|password|key|seed|mnemonic|privkey)\w*', "private 变量存储敏感数据（链上可读）"),
                    # 未锁定编译器版本（floating pragma）
                    (r'pragma\s+solidity\s+[\^~>]', "浮动编译器版本（pragma 应锁定到具体版本）"),
                    # 返回值未检查的低级调用
                    (r'(?<!\breturn\s)(?<!\bbool\s\w+\s*=\s)(?<!\bif\s*\()\.call(?:code)?\s*\((?![^;]*=\s*)', "低级 .call() 返回值未检查（失败静默忽略）"),
                ],
            },
            "severity": "medium",
            "description": "敏感数据暴露：链上 private 变量可被读取；浮动 pragma 导致编译行为不确定；未检查 .call() 返回值",
        },

        # 整数溢出（Solidity <0.8.0 无内置 overflow 检查）
        "integer_overflow": {
            "patterns": {
                "solidity": [
                    # 旧版本 pragma + 未使用 SafeMath（判断 pragma 行本身）
                    (r'pragma\s+solidity\s+(?:\^0\.[0-7]\.|>=\s*0\.[0-4]\.|0\.[0-7]\.)', "编译版本 <0.8.0（无内置溢出检查，需 SafeMath）"),
                    # unchecked 块内的算术运算（0.8.0+ 主动绕过检查）
                    (r'unchecked\s*\{[^}]*(?:\+\+|--|\+=|-=|\*=|[^!]=\s*\w+\s*[+\-\*]\s*\w+)', "unchecked 块内算术运算（显式跳过溢出保护）"),
                ],
            },
            "severity": "high",
            "description": "整数溢出/下溢：0.8.0 以下版本无内置检查；unchecked 块主动绕过溢出保护，需严格审查边界",
        },

        # 签名与身份验证（Solidity）
        "signature_issues": {
            "patterns": {
                "solidity": [
                    # ecrecover 返回 address(0) 未校验（签名伪造）
                    (r'ecrecover\s*\(', "ecrecover() 调用（需验证返回值不为 address(0)）"),
                    # 签名消息缺少 nonce（重放攻击）
                    (r'abi\.encodePacked\s*\([^)]*(?:msg\.sender|address|amount|value)(?![^)]*nonce)', "签名消息疑似缺少 nonce（签名重放风险）"),
                    # 过时的 \x19Ethereum Signed Message 而非 EIP-712
                    (r'\\x19Ethereum\s+Signed\s+Message', "使用旧版 eth_sign 格式（建议改用 EIP-712 结构化签名）"),
                    # 直接使用 ecrecover 而非 ECDSA.recover（签名延展性漏洞 SC-010）
                    (r'=\s*ecrecover\s*\(', "直接调用 ecrecover 而未使用 OpenZeppelin ECDSA.recover（签名延展性风险）"),
                    # v 值未校验
                    (r'\bv\b\s*[!=]=\s*2[78]\b', "v 值校验逻辑（确认 v 只允许 27/28）"),
                ],
            },
            "severity": "high",
            "description": "签名安全问题：ecrecover 零地址绕过、签名重放、签名延展性（s 值未限制低半阶）",
        },

        # 代理合约安全（SC-011/SC-012：存储槽冲突与未初始化升级合约）
        "proxy_security": {
            "patterns": {
                "solidity": [
                    # 构造函数未调用 _disableInitializers（逻辑合约可被直接初始化）
                    (r'constructor\s*\([^)]*\)\s*\{(?![^}]*_disableInitializers)', "构造函数未调用 _disableInitializers()（可升级合约逻辑部署后可被初始化）"),
                    # 使用了 delegatecall 但未使用 EIP-1967 标准 slot
                    (r'bytes32\s+(?:private\s+)?constant\s+\w*(?:IMPL|IMPLEMENT|ADMIN|BEACON)\w*\s*=\s*(?!.*keccak256\s*\(.*-\s*1)', "实现/管理员 slot 常量疑似非 EIP-1967 标准（keccak256(...)-1 格式）"),
                    # 升级函数（upgradeTo/upgradeToAndCall）没有访问控制
                    (r'function\s+upgrade[Tt]o\w*\s*\([^)]*\)\s*(?:public|external)(?!\s*\w*(?:onlyOwner|onlyProxy|onlyRole|ifAdmin))', "upgradeTo 函数疑似缺少访问控制"),
                    # 初始化函数可见性为 public 且无 initializer/reinitializer
                    (r'function\s+initialize\s*\([^)]*\)\s*public(?!\s*\w*initializer)', "initialize() 缺少 initializer 修饰符（可被重复调用）"),
                    # 父合约初始化函数未调用（__{Name}_init 未出现）
                    (r'function\s+initialize\s*\([^)]*\)\s*public\s+initializer\s*\{(?![^}]*__\w+_init)', "initializer 中疑似未调用父合约 __xxx_init()"),
                ],
            },
            "severity": "critical",
            "description": "代理合约安全：存储槽冲突（非 EIP-1967）、初始化函数未加 initializer、逻辑合约未禁用初始化",
        },

        # 精度损失（SC-014/SC-027：除法截断与价格精度）
        "precision_loss": {
            "patterns": {
                "solidity": [
                    # 先除后乘（精度损失的经典错误模式）
                    (r'\w+\s*/\s*\w+\s*\*\s*\w+', "先除后乘（建议改为先乘后除以减少精度损失）"),
                    # 与 1e18/10**18 基数不匹配的直接除法
                    (r'(?:amount|price|rate|balance|fee|reward)\s*/\s*(?!1e18|10\s*\*\*\s*18|1_000_000_000_000_000_000)\w+', "金融计算中的除法（确认精度基数是否为 1e18）"),
                    # ERC4626 首次存款攻击（虚拟份额缺失）
                    (r'function\s+convertTo(?:Shares|Assets)\s*\([^)]*\)', "ERC4626 convertToShares/Assets（确认是否有虚拟储备防止首次存款攻击）"),
                    # uint128/uint64 存储价格或余额（截断风险）
                    (r'\buint(?:128|96|64|32)\s+\w*(?:price|amount|balance|rate|fee)\w*', "uint128/64 存储价格/余额（高价值代币可能超出范围导致截断）"),
                ],
            },
            "severity": "high",
            "description": "精度损失：先除后乘导致截断误差、uint128/64 存储价格溢出、ERC4626 首次存款攻击",
        },

        # 前端运行与滑点保护（SC-016/SC-035）
        "front_running": {
            "patterns": {
                "solidity": [
                    # amountOutMin = 0 / amountAMin = 0（滑点保护为零）
                    (r'(?:amountOutMin|amountAMin|amountBMin|minOut|minAmountOut)\s*(?:,|\)|\s).*0\b', "swap/addLiquidity 最小输出量为 0（无滑点保护，可被三明治攻击）"),
                    # swap 调用中 amountOutMin 位置传入 0 字面量
                    (r'swap\w*\s*\([^)]*,\s*0\s*[,)]', "swap 参数中疑似存在 0 最小输出（滑点保护缺失）"),
                    # deadline 使用 block.timestamp（等同于无截止时间）
                    (r'deadline\s*[=:,]\s*block\.timestamp\b', "deadline = block.timestamp（实际上不设置截止时间，交易可被无限延迟执行）"),
                    # deadline 使用极大值
                    (r'deadline\s*[=:,]\s*type\s*\(\s*uint256\s*\)\.max', "deadline = uint256.max（无截止时间保护）"),
                    # 没有 commit-reveal 的竞拍/抽奖（可被抢跑）
                    (r'function\s+(?:bid|reveal|mint|claim)\s*\([^)]*\)\s*(?:public|external)(?![^{]*commit)', "bid/mint/claim 函数疑似无 commit-reveal 防抢跑保护"),
                ],
            },
            "severity": "high",
            "description": "前端运行/MEV 风险：滑点保护为零（三明治攻击）、deadline 无效、竞拍/铸造可被抢跑",
        },

        # ERC20 安全合规（SC-026）
        "erc20_safety": {
            "patterns": {
                "solidity": [
                    # 直接调用 .transfer/.transferFrom 未使用 SafeERC20（USDT 等不返回 bool）
                    (r'IERC20\s*\([^)]+\)\.transfer\s*\(', "直接调用 ERC20.transfer()（USDT 等非标准代币不返回 bool，应使用 SafeERC20.safeTransfer）"),
                    (r'IERC20\s*\([^)]+\)\.transferFrom\s*\(', "直接调用 ERC20.transferFrom()（建议使用 SafeERC20.safeTransferFrom）"),
                    # token.transfer 未检查返回值
                    (r'(?<!\bbool\s\w+\s*=\s)token(?:\w*)\.transfer\s*\((?![^;]*require)', "token.transfer() 返回值未检查（建议 SafeERC20 或 require 返回值）"),
                    # approve race condition（直接 approve 非零值）
                    (r'\.approve\s*\(\s*\w+\s*,\s*(?!0\b)', "ERC20.approve() 直接设置非零值（approve race condition，建议先 approve(0) 或使用 increaseAllowance）"),
                    # Fee-on-Transfer 代币使用 amount 计账（应用转账前后余额差）
                    (r'(?:deposit|stake|addLiquidity)\w*[^{]*\{[^}]*amount[^}]*transfer(?!.*balanceOf.*-)', "存入/质押后直接用 amount 计账（Fee-on-Transfer 代币实际到账可能少于 amount）"),
                ],
            },
            "severity": "high",
            "description": "ERC20 安全：非标准代币返回值缺失、approve race condition、Fee-on-Transfer 计账错误",
        },

        # 合约存在性与类型安全（SC-031/SC-032）
        "type_and_existence": {
            "patterns": {
                "solidity": [
                    # 低级 call 前未检查目标是否为合约（extcodesize/code.length）
                    (r'\.call\s*\{[^}]*\}\s*\([^)]*\)(?![^;]*\.code\.length)', "低级 call 前未验证目标地址是合约（code.length == 0 时 call 仍返回 true）"),
                    # 地址参数未做零地址校验
                    (r'function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?:public|external)[^{]*\{(?![^}]*require[^}]*address\(0\))', "address 参数函数疑似缺少零地址校验"),
                    # 不安全的强制向下类型转换（未使用 SafeCast）
                    (r'\buint(?:128|96|64|32|16|8)\s*\(\s*\w+\s*\)(?![^;]*SafeCast)', "uint 强制向下转换（未使用 SafeCast，大值会截断）"),
                    (r'\bint(?:128|96|64|32|16|8)\s*\(\s*\w+\s*\)', "int 强制向下转换（未使用 SafeCast，可能丢失高位）"),
                    # address(this).balance 用于逻辑判断（可被 selfdestruct 强制注入 ETH 破坏）
                    (r'address\s*\(\s*this\s*\)\.balance\s*(?:==|!=|>=|<=)', "依赖 address(this).balance 做精确判断（可被强制 ETH 注入破坏）"),
                ],
            },
            "severity": "high",
            "description": "类型安全与合约存在性：unsafe downcasting、低级 call 无合约校验、零地址未检查、余额逻辑可被强制注入破坏",
        },

        # DoS 攻击（SC-015）
        "defi_dos": {
            "patterns": {
                "solidity": [
                    # Push 分红：循环中直接 transfer（Gas DoS / revert 阻断）
                    (r'for\s*\([^;]*;[^;]*;[^)]*\)\s*\{[^}]*\.transfer\s*\(', "循环中 .transfer()（Push 分红模式，可被 Gas 耗尽或 receive revert 阻断）"),
                    (r'for\s*\([^;]*;[^;]*;[^)]*\)\s*\{[^}]*\.call\s*\{[^}]*value', "循环中 call{value}（Push 分红，可被重入或 Gas DoS）"),
                    # require 外部转账成功（对方可故意 revert 阻断合约运行）
                    (r'require\s*\(\s*(?:payable\s*\()?\w+[\.\w]*\.(?:transfer|send)\s*\(', "require 外部 transfer/send 成功（接收方可使 receive revert，永久阻断合约）"),
                    # 公共地址数组（循环遍历面临无界 Gas 风险）
                    (r'address\s*(?:payable\s*)?\[\s*\]\s+(?:public\s+)?(?:private\s+)?(?:internal\s+)?\w*(?:holders|recipients|users|stakers|members|investors|participants)\b', "地址数组（作为循环遍历目标时有 Gas Limit DoS 风险）"),
                    # mapping 替代被拒：单次分批循环过大
                    (r'\.push\s*\(\s*msg\.sender\s*\)', "msg.sender 追加到动态数组（无界增长将使后续循环 Gas DoS）"),
                ],
            },
            "severity": "high",
            "description": "DoS 拒绝服务：Push 分红循环可被 Gas 耗尽/revert 永久阻断；应改为 Pull Payment（用户主动 claim）",
        },

        # 治理攻击（SC-023）
        "governance_risk": {
            "patterns": {
                "solidity": [
                    # 直接使用实时 balanceOf 作为投票权（闪贷可刷高）
                    (r'(?:votes?|weight|power)\s*=\s*\w+\.balanceOf\s*\(', "投票权直接用 balanceOf（闪贷可单块刷高，应使用快照 getPastVotes）"),
                    (r'return\s+\w+\.balanceOf\s*\([^)]+\)\s*;', "投票函数返回实时 balanceOf（闪贷刷票风险）"),
                    # votingDelay 为 0
                    (r'function\s+votingDelay\s*\([^)]*\)[^{]*\{[^}]*return\s+0\s*;', "votingDelay() 返回 0（无缓冲期，提案立即可投票）"),
                    # quorum 为 0
                    (r'function\s+quorum\s*\([^)]*\)[^{]*\{[^}]*return\s+0\s*;', "quorum() 返回 0（法定人数为零，任意人可通过提案）"),
                    # 提案执行无 Timelock（直接 execute）
                    (r'function\s+execute\s*\([^)]*\)\s*(?:public|external)(?![^{]*[Tt]imelock|[^{]*delay)', "execute() 无 Timelock 延迟（高权限操作应有等待期让用户撤离）"),
                ],
            },
            "severity": "high",
            "description": "治理攻击：实时余额投票（闪贷刷票）、零 votingDelay、零 quorum、提案执行无 Timelock",
        },

        # NFT 安全（SC-036）
        "nft_risk": {
            "patterns": {
                "solidity": [
                    # safeTransferFrom 触发 onERC721Received 重入
                    (r'safeTransferFrom\s*\(', "safeTransferFrom 会触发 onERC721Received 回调（确认调用处有 nonReentrant 保护）"),
                    # tokenId 基于链上可预测值（可被抢跑）
                    (r'tokenId\s*=\s*uint256\s*\(\s*keccak256\s*\([^)]*(?:block\.|msg\.)', "tokenId 基于 block/msg 数据（可预测，可被抢跑占据特定 ID）"),
                    (r'uint256\s*\(\s*keccak256\s*\([^)]*(?:block\.timestamp|block\.number)\s*\)\s*\)', "tokenId/随机值基于 block 数据（可预测）"),
                    # mint 无 maxSupply 上限
                    (r'function\s+(?:mint|safeMint)\s*\([^)]*\)\s*(?:public|external)(?![^{]*(?:maxSupply|MAX_SUPPLY|totalSupply\s*<|_tokenIdCounter\s*<))', "mint 函数疑似无 maxSupply 限制（总量无上界）"),
                    # baseURI 可被 owner 随时修改（元数据不可变性）
                    (r'function\s+set(?:Base)?URI\s*\([^)]*\)\s*(?:public|external)\s*(?:onlyOwner|onlyRole)', "setBaseURI 可被 owner 修改（NFT 元数据中心化风险，建议 IPFS 不可变 URI）"),
                ],
            },
            "severity": "high",
            "description": "NFT 安全：safeTransferFrom 重入、可预测 tokenId（抢跑）、无 maxSupply 限制、可变 metadata URI",
        },

        # 质押奖励安全（SC-039）
        "staking_risk": {
            "patterns": {
                "solidity": [
                    # rewardPerToken 除以 totalSupply（除零崩溃）
                    (r'rewardRate\s*/\s*(?:_?totalSupply\b|totalStaked\b)', "rewardRate / totalSupply（totalSupply=0 时除零崩溃，需先 require(totalSupply > 0)）"),
                    (r'function\s+rewardPerToken\s*\(\s*\)', "rewardPerToken() 函数（确认 totalSupply=0 时有除零保护和跳过逻辑）"),
                    # 奖励 Token 与质押 Token 相同（getReward 时触发 stake 相关重入）
                    (r'rewardToken\s*=\s*stakingToken\b|rewardToken\s*=\s*token\b', "奖励 Token 与质押 Token 相同（getReward 的 transfer 可触发重入）"),
                    # 使用 balanceOf 而非内部变量追踪总量（可被直接转入破坏）
                    (r'(?:totalSupply|totalStaked)\s*=\s*IERC20[^.]*\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', "totalSupply/totalStaked 使用 balanceOf 计算（直接转入 token 可破坏记账）"),
                    # getReward/exit 缺少 nonReentrant
                    (r'function\s+(?:getReward|exit|claimReward|harvest)\s*\([^)]*\)\s*(?:public|external)(?!\s*\w*nonReentrant)', "getReward/exit 函数疑似缺少 nonReentrant 修饰符"),
                ],
            },
            "severity": "high",
            "description": "质押奖励风险：rewardPerToken 除零崩溃、奖励与质押同 token（重入）、balanceOf 计账被外部破坏",
        },

        # 闪电贷回调安全（SC-033）
        "flash_loan_callback": {
            "patterns": {
                "solidity": [
                    # onFlashLoan/executeOperation 未验证 msg.sender
                    (r'function\s+onFlashLoan\s*\([^)]*\)\s*(?:external|public)(?!\s*\w*(?:onlyLender|onlyFlash))', "onFlashLoan 缺少 msg.sender == lender 校验（任意人可直接调用）"),
                    (r'function\s+executeOperation\s*\([^)]*\)\s*(?:external|public)(?!\s*\w*only)', "executeOperation 疑似缺少来源验证（确认 msg.sender == POOL）"),
                    # 闪电贷未验证还款金额
                    (r'function\s+onFlashLoan[^{]*\{(?![^}]*require[^}]*amount|[^}]*fee)', "onFlashLoan 回调内未显式校验还款金额（本金+手续费）"),
                    # 提供闪电贷无手续费（攻击零成本）
                    (r'function\s+flash(?:Loan|loan)\s*\([^)]*\)[^{]*\{(?![^}]*fee|[^}]*premium|[^}]*Flash_FEE)', "flashLoan 函数疑似无手续费（零成本攻击，建议 basis points 手续费）"),
                ],
            },
            "severity": "high",
            "description": "闪电贷回调风险：onFlashLoan 无来源校验（可被直接调用）、未验证还款金额、零手续费降低攻击成本",
        },

        # Timelock 与高权限操作（SC-022）
        "missing_timelock": {
            "patterns": {
                "solidity": [
                    # setFee/setRate/setPrice 等关键参数直接变更（无 Timelock）
                    (r'function\s+set(?:Fee|Rate|Price|Treasury|Limit|Cap|Min|Max|Threshold)\w*\s*\([^)]*\)\s*(?:public|external)\s*(?:onlyOwner|onlyRole)', "关键参数变更函数无 Timelock（owner 可即时修改，建议添加延迟）"),
                    # upgradeTo 函数（升级无延迟）
                    (r'function\s+_?authorizeUpgrade\s*\([^)]*\)', "_authorizeUpgrade（UUPS 升级，确认是否有 Timelock 保护）"),
                    # 无多签要求的资产提取
                    (r'function\s+withdraw\w*\s*\([^)]*\)\s*(?:public|external)\s*(?:onlyOwner)(?![^{]*timelock|[^{]*Timelock)', "withdraw 函数仅需 onlyOwner（建议多签或 Timelock）"),
                ],
            },
            "severity": "medium",
            "description": "高权限操作缺少 Timelock：关键参数/升级/提款可被 owner 即时执行，无延迟给用户撤离时间",
        },

        # XXE 注入（XML 外部实体）
        "xxe": {
            "patterns": {
                "java": [
                    # DocumentBuilderFactory 未禁用 DOCTYPE / 外部实体
                    (r'DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![^;]{0,200}setFeature[^;]{0,100}DISALLOW_DOCTYPE)', "DocumentBuilderFactory 未禁用 DOCTYPE（XXE 风险）"),
                    (r'SAXParserFactory\.newInstance\s*\(\s*\)(?![^;]{0,200}setFeature)', "SAXParserFactory 未配置安全特性（XXE 风险）"),
                    (r'XMLInputFactory\.newInstance\s*\(\s*\)(?![^;]{0,200}IS_SUPPORTING_EXTERNAL_ENTITIES[^;]{0,100}false)', "XMLInputFactory 未禁用外部实体"),
                    (r'TransformerFactory\.newInstance\s*\(\s*\)(?![^;]{0,200}setFeature|setAttribute)', "TransformerFactory 未配置安全特性（SSRF/XXE）"),
                ],
                "python": [
                    # lxml 允许 resolve_entities
                    (r'etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*True', "lxml XMLParser resolve_entities=True（XXE）"),
                    # defusedxml 未使用而直接用 xml.etree
                    (r'from\s+xml\.etree(?:\.ElementTree)?\s+import', "使用标准 xml.etree（建议改用 defusedxml 防 XXE）"),
                    (r'xml\.etree\.ElementTree\.parse\s*\(', "ElementTree.parse（建议改用 defusedxml.ElementTree）"),
                ],
                "php": [
                    # libxml_disable_entity_loader 未调用 / 调用 false
                    (r'simplexml_load_string\s*\(\s*\$(?![^;]{0,200}libxml_disable_entity_loader\s*\(\s*true)', "simplexml_load_string 未禁用外部实体（XXE）"),
                    (r'new\s+DOMDocument\s*\(\s*\)(?![^;]{0,200}resolveExternals\s*=\s*false)', "DOMDocument 未禁用外部实体（XXE）"),
                    (r'libxml_disable_entity_loader\s*\(\s*false\s*\)', "libxml_disable_entity_loader(false) 显式启用外部实体"),
                ],
            },
            "severity": "high",
            "description": "XXE 注入：XML 解析器未禁用外部实体声明，可被用于读取本地文件、内网探测（SSRF）",
        },

        # 硬编码密钥
        "hardcoded_secret": {
            "patterns": {
                "_common": [
                    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "硬编码密码"),
                    (
                        r'(?:secret|api_?key|apikey|client_?secret|access_?token|bearer_?token|auth_?token|jwt_?secret)\s*=\s*["\'][^"\']{8,}["\']',
                        "硬编码密钥",
                    ),
                    (r'(?:private_?key|priv_?key)\s*=\s*["\'][^"\']+["\']', "硬编码私钥"),
                    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "私钥"),
                    (r'(?:aws_?access_?key|aws_?secret)\s*=\s*["\'][^"\']+["\']', "AWS密钥"),
                    (r'(?:ghp_|gho_|github_pat_)[a-zA-Z0-9]{36,}', "GitHub Token"),
                    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
                    (r'(?:bearer|authorization)\s*[=:]\s*["\'][^"\']{20,}["\']', "Bearer Token"),
                ],
            },
            "severity": "medium",
            "description": "硬编码密钥：敏感信息不应该硬编码在代码中",
        },
        
        # 弱加密
        "weak_crypto": {
            "patterns": {
                "python": [
                    (r'hashlib\.md5\s*\(', "MD5哈希"),
                    (r'hashlib\.sha1\s*\(', "SHA1哈希"),
                    (r'DES\s*\(', "DES加密"),
                    # 仅在明显安全上下文中标记（避免 ML/游戏代码误报）
                    (r'(?:token|password|secret|session|nonce|salt|key|otp|csrf)\w*\s*=.*random\.random\s*\(', "random.random 用于安全敏感值（应使用 secrets 模块）"),
                    (r'random\.random\s*\(\)\s*\*\s*(?:10|100|1000|[0-9]+)\b(?![^;#\n]*(?:test|sample|shuffle|choice))', "random.random 生成数值（确认是否用于安全场景）"),
                ],
                "javascript": [
                    (r'crypto\.createHash\s*\(\s*["\']md5["\']', "MD5哈希"),
                    (r'crypto\.createHash\s*\(\s*["\']sha1["\']', "SHA1哈希"),
                    # 仅标记明确用于 token/session/密码生成的 Math.random
                    (r'(?:token|password|secret|session|nonce|csrf|otp)\w*\s*[=+]=?\s*[^;]*Math\.random\s*\(', "Math.random 用于安全敏感值（应使用 crypto.randomBytes）"),
                    (r'Math\.random\s*\(\)\s*\.toString\s*\(\s*36\s*\)', "Math.random 转 base36 生成 ID（不适合用于安全 token）"),
                ],
                "java": [
                    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "MD5哈希"),
                    (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "SHA1哈希"),
                    (r'DESKeySpec', "DES密钥"),
                ],
                "php": [
                    (r'md5\s*\(', "MD5哈希"),
                    (r'sha1\s*\(', "SHA1哈希"),
                    (r'mcrypt_', "mcrypt已废弃"),
                ],
            },
            "severity": "low",
            "description": "弱加密算法：使用了不安全的加密或哈希算法",
            "cwe_id": "CWE-327",
        },
    }
    
    @property
    def name(self) -> str:
        return "pattern_match"
    
    @property
    def description(self) -> str:
        vuln_types = ", ".join(self.PATTERNS.keys())
        return f"""🔍 快速扫描代码中的危险模式和常见漏洞。

支持两种使用方式：
1. ⭐ 推荐：直接扫描文件 - 使用 scan_file 参数指定文件路径
2. 传入代码内容 - 使用 code 参数传入已读取的代码

支持的漏洞类型: {vuln_types}

使用示例:
- 方式1（推荐）: {{"scan_file": "app/views.py", "pattern_types": ["sql_injection", "xss"]}}
- 方式2: {{"code": "...", "file_path": "app/views.py"}}

输入参数:
- scan_file (推荐): 要扫描的文件路径（相对于项目根目录）
- code: 要扫描的代码内容（与 scan_file 二选一）
- file_path: 文件路径（用于上下文，如果使用 code 模式）
- pattern_types: 要检测的漏洞类型列表
- language: 指定编程语言（通常自动检测）

这是一个快速扫描工具，发现的问题需要进一步分析确认。"""
    
    @property
    def args_schema(self):
        return PatternMatchInput
    
    async def _execute(
        self,
        code: Optional[str] = None,
        scan_file: Optional[str] = None,
        file_path: str = "unknown",
        pattern_types: Optional[List[str]] = None,
        language: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """执行模式匹配 - 支持直接文件扫描或代码内容扫描"""
        
        # 🔥 模式1: 直接扫描文件
        if scan_file:
            if not self.project_root:
                return ToolResult(
                    success=False,
                    error="无法扫描文件：未配置项目根目录"
                )
            
            full_path = os.path.normpath(os.path.join(self.project_root, scan_file))
            
            # 安全检查：防止路径遍历
            if not full_path.startswith(os.path.normpath(self.project_root)):
                return ToolResult(
                    success=False,
                    error="安全错误：不允许访问项目目录外的文件"
                )
            
            if not os.path.exists(full_path):
                return ToolResult(
                    success=False,
                    error=f"文件不存在: {scan_file}"
                )
            
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                file_path = scan_file
            except Exception as e:
                return ToolResult(
                    success=False,
                    error=f"读取文件失败: {str(e)}"
                )
        
        # 🔥 检查是否有代码可以扫描
        if not code:
            return ToolResult(
                success=False,
                error="必须提供 scan_file（文件路径）或 code（代码内容）其中之一"
            )
        
        matches: List[PatternMatch] = []
        lines = code.split('\n')
        
        # 确定要检查的漏洞类型
        types_to_check = pattern_types or list(self.PATTERNS.keys())
        
        # 自动检测语言
        if not language:
            language = self._detect_language(file_path)
        
        for vuln_type in types_to_check:
            if vuln_type not in self.PATTERNS:
                continue
            
            pattern_config = self.PATTERNS[vuln_type]
            patterns_dict = pattern_config["patterns"]
            
            # 获取语言特定模式和通用模式
            patterns_to_use = []
            if language and language in patterns_dict:
                patterns_to_use.extend(patterns_dict[language])
            if "_common" in patterns_dict:
                patterns_to_use.extend(patterns_dict["_common"])
            
            # 如果没有特定语言模式，尝试使用所有模式
            if not patterns_to_use:
                for lang, pats in patterns_dict.items():
                    if lang != "_common":
                        patterns_to_use.extend(pats)
            
            # 执行匹配
            for pattern, pattern_name in patterns_to_use:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            # 获取上下文
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = '\n'.join(f"{j+1}: {lines[j]}" for j in range(start, end))
                            
                            matches.append(PatternMatch(
                                pattern_name=pattern_name,
                                pattern_type=vuln_type,
                                file_path=file_path,
                                line_number=i + 1,
                                matched_text=line.strip()[:200],
                                context=context,
                                severity=pattern_config["severity"],
                                description=pattern_config["description"],
                            ))
                except re.error:
                    continue
        
        if not matches:
            return ToolResult(
                success=True,
                data="没有检测到已知的危险模式",
                metadata={"patterns_checked": len(types_to_check), "matches": 0}
            )
        
        # 格式化输出
        output_parts = [f"⚠️ 检测到 {len(matches)} 个潜在问题:\n"]
        
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        for match in matches:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(match.severity, "⚪")
            output_parts.append(f"\n{severity_icon} [{match.severity.upper()}] {match.pattern_type}")
            output_parts.append(f"   位置: {match.file_path}:{match.line_number}")
            output_parts.append(f"   模式: {match.pattern_name}")
            output_parts.append(f"   描述: {match.description}")
            output_parts.append(f"   匹配: {match.matched_text}")
            output_parts.append(f"   上下文:\n{match.context}")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "matches": len(matches),
                "by_severity": {
                    s: len([m for m in matches if m.severity == s])
                    for s in ["critical", "high", "medium", "low"]
                },
                "details": [
                    {
                        "type": m.pattern_type,
                        "severity": m.severity,
                        "line": m.line_number,
                        "pattern": m.pattern_name,
                    }
                    for m in matches
                ]
            }
        )
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """根据文件扩展名检测语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".java": "java",
            ".php": "php",
            ".go": "go",
            ".rb": "ruby",
            ".sol": "solidity",
        }
        
        for ext, lang in ext_map.items():
            if file_path.lower().endswith(ext):
                return lang
        
        return None
