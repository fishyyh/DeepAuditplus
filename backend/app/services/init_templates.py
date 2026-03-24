"""
初始化系统预置的提示词模板和审计规则
"""

import json
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.prompt_template import PromptTemplate
from app.models.audit_rule import AuditRuleSet, AuditRule

logger = logging.getLogger(__name__)


# ==================== 系统提示词模板 ====================

SYSTEM_PROMPT_TEMPLATES = [
    {
        "name": "默认代码审计",
        "description": "全面的代码审计提示词，涵盖安全、性能、代码质量等多个维度",
        "template_type": "system",
        "is_default": True,
        "sort_order": 0,
        "variables": {"language": "编程语言", "code": "代码内容"},
        "content_zh": """你是一个专业的代码审计助手。请从以下维度全面分析代码：
- 安全漏洞（SQL注入、XSS、命令注入、路径遍历、SSRF、XXE、反序列化、硬编码密钥等）
- 潜在的 Bug 和逻辑错误
- 性能问题和优化建议
- 编码规范和代码风格
- 可维护性和可读性
- 最佳实践和设计模式

请尽可能多地找出代码中的所有问题，不要遗漏任何安全漏洞或潜在风险！""",
        "content_en": """You are a professional code auditing assistant. Please comprehensively analyze the code from the following dimensions:
- Security vulnerabilities (SQL injection, XSS, command injection, path traversal, SSRF, XXE, deserialization, hardcoded secrets, etc.)
- Potential bugs and logical errors
- Performance issues and optimization suggestions
- Coding standards and code style
- Maintainability and readability
- Best practices and design patterns

Find as many issues as possible! Do NOT miss any security vulnerabilities or potential risks!"""
    },
    {
        "name": "安全专项审计",
        "description": "专注于安全漏洞检测的提示词模板",
        "template_type": "system",
        "is_default": False,
        "sort_order": 1,
        "variables": {"language": "编程语言", "code": "代码内容"},
        "content_zh": """你是一个专业的安全审计专家。请专注于检测以下安全问题：

【注入类漏洞】
- SQL注入（包括盲注、时间盲注、联合查询注入）
- 命令注入（OS命令执行）
- LDAP注入
- XPath注入
- NoSQL注入

【跨站脚本（XSS）】
- 反射型XSS
- 存储型XSS
- DOM型XSS

【认证与授权】
- 硬编码凭证
- 弱密码策略
- 会话管理问题
- 权限绕过

【敏感数据】
- 敏感信息泄露
- 不安全的加密
- 明文传输敏感数据

【其他安全问题】
- SSRF（服务端请求伪造）
- XXE（XML外部实体注入）
- 反序列化漏洞
- 路径遍历
- 文件上传漏洞
- CSRF（跨站请求伪造）

请详细说明每个漏洞的风险等级、利用方式和修复建议。""",
        "content_en": """You are a professional security audit expert. Please focus on detecting the following security issues:

【Injection Vulnerabilities】
- SQL Injection (including blind, time-based, union-based)
- Command Injection (OS command execution)
- LDAP Injection
- XPath Injection
- NoSQL Injection

【Cross-Site Scripting (XSS)】
- Reflected XSS
- Stored XSS
- DOM-based XSS

【Authentication & Authorization】
- Hardcoded credentials
- Weak password policies
- Session management issues
- Authorization bypass

【Sensitive Data】
- Sensitive information disclosure
- Insecure cryptography
- Plaintext transmission of sensitive data

【Other Security Issues】
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity Injection)
- Deserialization vulnerabilities
- Path traversal
- File upload vulnerabilities
- CSRF (Cross-Site Request Forgery)

Please provide detailed risk level, exploitation method, and remediation suggestions for each vulnerability."""
    },
    {
        "name": "性能优化审计",
        "description": "专注于性能问题检测的提示词模板",
        "template_type": "system",
        "is_default": False,
        "sort_order": 2,
        "variables": {"language": "编程语言", "code": "代码内容"},
        "content_zh": """你是一个专业的性能优化专家。请专注于检测以下性能问题：

【数据库性能】
- N+1查询问题
- 缺少索引
- 不必要的全表扫描
- 大量数据一次性加载
- 未使用连接池

【内存问题】
- 内存泄漏
- 大对象未及时释放
- 缓存使用不当
- 循环中创建大量对象

【算法效率】
- 时间复杂度过高
- 不必要的重复计算
- 可优化的循环
- 递归深度过大

【并发问题】
- 线程安全问题
- 死锁风险
- 资源竞争
- 不必要的同步

【I/O性能】
- 同步阻塞I/O
- 未使用缓冲
- 频繁的小文件操作
- 网络请求未优化

请提供具体的优化建议和预期的性能提升。""",
        "content_en": """You are a professional performance optimization expert. Please focus on detecting the following performance issues:

【Database Performance】
- N+1 query problems
- Missing indexes
- Unnecessary full table scans
- Loading large amounts of data at once
- Not using connection pools

【Memory Issues】
- Memory leaks
- Large objects not released timely
- Improper cache usage
- Creating many objects in loops

【Algorithm Efficiency】
- High time complexity
- Unnecessary repeated calculations
- Optimizable loops
- Excessive recursion depth

【Concurrency Issues】
- Thread safety problems
- Deadlock risks
- Resource contention
- Unnecessary synchronization

【I/O Performance】
- Synchronous blocking I/O
- Not using buffers
- Frequent small file operations
- Unoptimized network requests

Please provide specific optimization suggestions and expected performance improvements."""
    },
    {
        "name": "代码质量审计",
        "description": "专注于代码质量和可维护性的提示词模板",
        "template_type": "system",
        "is_default": False,
        "sort_order": 3,
        "variables": {"language": "编程语言", "code": "代码内容"},
        "content_zh": """你是一个专业的代码质量审计专家。请专注于检测以下代码质量问题：

【代码规范】
- 命名不规范（变量、函数、类）
- 代码格式不一致
- 注释缺失或过时
- 魔法数字/字符串

【代码结构】
- 函数过长（超过50行）
- 类职责不单一
- 嵌套层级过深
- 重复代码

【可维护性】
- 高耦合低内聚
- 缺少错误处理
- 硬编码配置
- 缺少日志记录

【设计模式】
- 违反SOLID原则
- 可使用设计模式优化的场景
- 过度设计

【测试相关】
- 难以测试的代码
- 缺少边界条件处理
- 依赖注入问题

请提供具体的重构建议和代码示例。""",
        "content_en": """You are a professional code quality audit expert. Please focus on detecting the following code quality issues:

【Code Standards】
- Non-standard naming (variables, functions, classes)
- Inconsistent code formatting
- Missing or outdated comments
- Magic numbers/strings

【Code Structure】
- Functions too long (over 50 lines)
- Classes with multiple responsibilities
- Deep nesting levels
- Duplicate code

【Maintainability】
- High coupling, low cohesion
- Missing error handling
- Hardcoded configurations
- Missing logging

【Design Patterns】
- SOLID principle violations
- Scenarios that could benefit from design patterns
- Over-engineering

【Testing Related】
- Hard-to-test code
- Missing boundary condition handling
- Dependency injection issues

Please provide specific refactoring suggestions and code examples."""
    },
]


# ==================== 系统审计规则集 ====================

SYSTEM_RULE_SETS = [
    {
        "name": "OWASP Top 10",
        "description": "基于 OWASP Top 10 2021 的安全审计规则集",
        "language": "all",
        "rule_type": "security",
        "is_default": True,
        "sort_order": 0,
        "severity_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1},
        "rules": [
            {
                "rule_code": "A01",
                "name": "访问控制失效",
                "description": "检测权限绕过、越权访问、IDOR等访问控制问题",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否存在访问控制失效问题：权限检查缺失、越权访问、IDOR（不安全的直接对象引用）、CORS配置错误",
                "fix_suggestion": "实施最小权限原则，在服务端进行权限验证，使用基于角色的访问控制(RBAC)",
                "reference_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            },
            {
                "rule_code": "A02",
                "name": "加密机制失效",
                "description": "检测弱加密、明文传输、密钥管理不当等问题",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否存在加密问题：使用弱加密算法(MD5/SHA1/DES)、明文存储密码、硬编码密钥、不安全的随机数生成",
                "fix_suggestion": "使用强加密算法(AES-256/RSA-2048)，使用安全的密码哈希(bcrypt/Argon2)，妥善管理密钥",
                "reference_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            },
            {
                "rule_code": "A03",
                "name": "注入攻击",
                "description": "检测SQL注入、命令注入、LDAP注入等注入漏洞",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否存在注入漏洞：SQL注入、命令注入、LDAP注入、XPath注入、NoSQL注入、表达式语言注入",
                "fix_suggestion": "使用参数化查询，输入验证和转义，使用ORM框架，最小权限原则",
                "reference_url": "https://owasp.org/Top10/A03_2021-Injection/",
            },
            {
                "rule_code": "A04",
                "name": "不安全设计",
                "description": "检测业务逻辑漏洞、缺少安全控制等设计问题",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查是否存在不安全的设计：缺少速率限制、业务逻辑漏洞、缺少输入验证、信任边界不清",
                "fix_suggestion": "采用安全设计原则，威胁建模，实施深度防御",
                "reference_url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
            },
            {
                "rule_code": "A05",
                "name": "安全配置错误",
                "description": "检测默认配置、不必要的功能、错误的权限设置",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查是否存在安全配置错误：默认凭证、不必要的功能启用、详细错误信息泄露、缺少安全头",
                "fix_suggestion": "最小化安装，禁用不必要功能，定期审查配置，自动化配置检查",
                "reference_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            },
            {
                "rule_code": "A06",
                "name": "易受攻击和过时的组件",
                "description": "检测使用已知漏洞的依赖库",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查是否使用了已知漏洞的组件：过时的依赖库、未修补的漏洞、不安全的第三方组件",
                "fix_suggestion": "定期更新依赖，使用依赖扫描工具，订阅安全公告",
                "reference_url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            },
            {
                "rule_code": "A07",
                "name": "身份认证失效",
                "description": "检测弱密码、会话管理问题、凭证泄露",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否存在身份认证问题：弱密码策略、会话固定、凭证明文存储、缺少多因素认证",
                "fix_suggestion": "实施强密码策略，使用MFA，安全的会话管理，防止暴力破解",
                "reference_url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            },
            {
                "rule_code": "A08",
                "name": "软件和数据完整性失效",
                "description": "检测不安全的反序列化、CI/CD安全问题",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否存在完整性问题：不安全的反序列化、未验证的更新、CI/CD管道安全",
                "fix_suggestion": "验证数据完整性，使用数字签名，安全的反序列化",
                "reference_url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            },
            {
                "rule_code": "A09",
                "name": "安全日志和监控失效",
                "description": "检测日志记录不足、监控缺失",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查是否存在日志监控问题：缺少安全日志、敏感信息记录到日志、缺少告警机制",
                "fix_suggestion": "记录安全相关事件，实施监控和告警，定期审查日志",
                "reference_url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            },
            {
                "rule_code": "A10",
                "name": "服务端请求伪造(SSRF)",
                "description": "检测SSRF漏洞",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查是否存在SSRF漏洞：未验证的URL输入、内网资源访问、云元数据访问",
                "fix_suggestion": "验证和过滤URL，使用白名单，禁用不必要的协议",
                "reference_url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            },
        ]
    },
    {
        "name": "代码质量规则",
        "description": "通用代码质量检查规则集",
        "language": "all",
        "rule_type": "quality",
        "is_default": False,
        "sort_order": 1,
        "severity_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1},
        "rules": [
            {
                "rule_code": "CQ001",
                "name": "函数过长",
                "description": "函数超过50行，建议拆分",
                "category": "maintainability",
                "severity": "medium",
                "custom_prompt": "检查函数是否过长（超过50行），是否应该拆分为更小的函数",
                "fix_suggestion": "将大函数拆分为多个小函数，每个函数只做一件事",
            },
            {
                "rule_code": "CQ002",
                "name": "重复代码",
                "description": "检测重复的代码块",
                "category": "maintainability",
                "severity": "medium",
                "custom_prompt": "检查是否存在重复的代码块，可以提取为公共函数或类",
                "fix_suggestion": "提取重复代码为公共函数、类或模块",
            },
            {
                "rule_code": "CQ003",
                "name": "嵌套过深",
                "description": "代码嵌套层级超过4层",
                "category": "maintainability",
                "severity": "low",
                "custom_prompt": "检查代码嵌套是否过深（超过4层），影响可读性",
                "fix_suggestion": "使用早返回、提取函数等方式减少嵌套",
            },
            {
                "rule_code": "CQ004",
                "name": "魔法数字",
                "description": "代码中使用未命名的常量",
                "category": "style",
                "severity": "low",
                "custom_prompt": "检查是否存在魔法数字或魔法字符串，应该定义为常量",
                "fix_suggestion": "将魔法数字定义为有意义的常量",
            },
            {
                "rule_code": "CQ005",
                "name": "缺少错误处理",
                "description": "缺少异常捕获或错误处理",
                "category": "bug",
                "severity": "high",
                "custom_prompt": "检查是否缺少必要的错误处理，可能导致程序崩溃",
                "fix_suggestion": "添加适当的try-catch或错误检查",
            },
            {
                "rule_code": "CQ006",
                "name": "未使用的变量",
                "description": "声明但未使用的变量",
                "category": "style",
                "severity": "low",
                "custom_prompt": "检查是否存在声明但未使用的变量",
                "fix_suggestion": "删除未使用的变量或使用它们",
            },
            {
                "rule_code": "CQ007",
                "name": "命名不规范",
                "description": "变量、函数、类命名不符合规范",
                "category": "style",
                "severity": "low",
                "custom_prompt": "检查命名是否符合语言规范和最佳实践",
                "fix_suggestion": "使用有意义的、符合规范的命名",
            },
            {
                "rule_code": "CQ008",
                "name": "注释缺失",
                "description": "复杂逻辑缺少必要注释",
                "category": "maintainability",
                "severity": "low",
                "custom_prompt": "检查复杂逻辑是否缺少必要的注释说明",
                "fix_suggestion": "为复杂逻辑添加清晰的注释",
            },
        ]
    },
    {
        "name": "性能优化规则",
        "description": "性能问题检测规则集",
        "language": "all",
        "rule_type": "performance",
        "is_default": False,
        "sort_order": 2,
        "severity_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1},
        "rules": [
            {
                "rule_code": "PERF001",
                "name": "N+1查询",
                "description": "检测数据库N+1查询问题",
                "category": "performance",
                "severity": "high",
                "custom_prompt": "检查是否存在N+1查询问题，在循环中执行数据库查询",
                "fix_suggestion": "使用JOIN查询或批量查询替代循环查询",
            },
            {
                "rule_code": "PERF002",
                "name": "内存泄漏",
                "description": "检测潜在的内存泄漏",
                "category": "performance",
                "severity": "critical",
                "custom_prompt": "检查是否存在内存泄漏：未关闭的资源、循环引用、大对象未释放",
                "fix_suggestion": "使用try-finally或with语句确保资源释放",
            },
            {
                "rule_code": "PERF003",
                "name": "低效算法",
                "description": "检测时间复杂度过高的算法",
                "category": "performance",
                "severity": "medium",
                "custom_prompt": "检查是否存在低效算法，如O(n²)可优化为O(n)或O(nlogn)",
                "fix_suggestion": "使用更高效的算法或数据结构",
            },
            {
                "rule_code": "PERF004",
                "name": "不必要的对象创建",
                "description": "在循环中创建不必要的对象",
                "category": "performance",
                "severity": "medium",
                "custom_prompt": "检查是否在循环中创建不必要的对象，应该移到循环外",
                "fix_suggestion": "将对象创建移到循环外部，或使用对象池",
            },
            {
                "rule_code": "PERF005",
                "name": "同步阻塞",
                "description": "检测同步阻塞操作",
                "category": "performance",
                "severity": "medium",
                "custom_prompt": "检查是否存在同步阻塞操作，应该使用异步方式",
                "fix_suggestion": "使用异步I/O或多线程处理",
            },
        ]
    },
    {
        "name": "Solidity 业务逻辑安全规则",
        "description": "面向智能合约/DeFi 场景的业务逻辑与协议实现风险规则集",
        "language": "solidity",
        "rule_type": "security",
        "is_default": False,
        "sort_order": 3,
        "severity_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1},
        "rules": [
            {
                "rule_code": "SBL001",
                "name": "Router身份误用",
                "description": "检查是否把 router/callback caller 当作真实用户身份进行限额、冷却或惩罚统计",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查 beforeSwap/afterSwap 等回调中 sender 的真实语义。若 sender 实际是路由合约而非最终用户，不应直接作为用户维度限额键。重点检查 addressSwappedAmount[sender]、addressLastSwapBlock[sender] 这类按 sender 直接记账逻辑。",
                "fix_suggestion": "基于协议推荐方式解析真实用户身份（如兼容路由 msgSender 扩展），或明确以 router 维度设计并同步调整风控策略，避免误将全体用户聚合到同一地址。",
            },
            {
                "rule_code": "SBL002",
                "name": "池状态未隔离",
                "description": "检查 Hook/策略合约是否将应按 PoolId 隔离的状态定义为全局变量",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查 launchStartBlock/currentPhase/initialLiquidity/lastPhaseUpdateBlock 等状态是否为全局共享，且 Hook 可复用于多池。若可复用多池，则所有生命周期状态和用户统计都应按 PoolId 隔离。",
                "fix_suggestion": "引入 PoolState 结构并以 PoolId => PoolState 存储；用户统计改为 PoolId + user 双键，避免跨池污染和状态互相覆盖。",
            },
            {
                "rule_code": "SBL003",
                "name": "阶段重置无效",
                "description": "检查 phase 切换时是否存在无效重置（如仅重置 address(0)）",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 _resetPerAddressTracking 一类函数是否只清理无意义键（如 address(0)），导致实际用户统计跨阶段残留。重点核查阶段切换逻辑与用户计数器的耦合。",
                "fix_suggestion": "采用按 phase 分桶统计（address => phase => value），或基于 phaseStartBlock 懒重置当前用户状态，确保阶段切换后限额与冷却重新计量。",
            },
            {
                "rule_code": "SBL004",
                "name": "Hook权限位不一致",
                "description": "检查部署脚本中的 Hook flags 与合约 getHookPermissions 声明是否一致",
                "category": "security",
                "severity": "high",
                "custom_prompt": "比对脚本中 BEFORE/AFTER_* FLAG 组合与合约实际启用回调，检查 BEFORE_INITIALIZE 与 AFTER_INITIALIZE 等是否错配，避免部署后校验失败或行为偏差。",
                "fix_suggestion": "统一由单一来源生成 flag（建议从权限定义推导），在脚本部署前增加断言校验 mined flags 与合约权限一致。",
            },
            {
                "rule_code": "SBL005",
                "name": "CREATE2部署者不一致",
                "description": "检查 HookMiner.find 使用地址与实际 CREATE2 部署地址是否一致",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查是否使用外部 factory 地址挖盐，却由 EOA/不同部署者执行 new {salt}。若挖矿 deployer 与实际 deployer 不一致，会导致地址不匹配。",
                "fix_suggestion": "使用实际部署者地址进行地址挖矿；在脚本中保留 address(hook) == minedAddress 的强校验，并确保常量已定义且可编译。",
            },
            {
                "rule_code": "SBL006",
                "name": "精确输入输出记账错误",
                "description": "检查 exact input / exact output 模式下 swapAmount 口径是否一致",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 amountSpecified 正负分支是否被统一绝对值处理，导致 exact output 记账币种错误。重点核查限制/惩罚逻辑采用的计量口径是否与真实支出一致。",
                "fix_suggestion": "优先使用 afterSwap 的 BalanceDelta 计算真实输入输出并更新统计，按交易方向分别计量，避免错误触发或漏触发限额惩罚。",
            },
            {
                "rule_code": "SBL007",
                "name": "限额基于过期流动性",
                "description": "检查用户限额计算是否错误依赖 initialLiquidity 等静态值",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查 getUserRemainingLimit 等函数是否用初始流动性计算当前限额，而未读取最新池流动性。若可增减流动性，固定基准会导致展示和风控偏差。",
                "fix_suggestion": "按实时或阶段内定义的流动性快照计算限额，并在文档中明确口径（实时值/阶段快照值）以避免认知偏差。",
            },
            {
                "rule_code": "SBL008",
                "name": "阶段边界与时间窗口错误",
                "description": "检查 phase 切换边界条件（>= / >）和基准块更新时机是否正确",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 blocksSinceLaunch、lastPhaseUpdateBlock 相关判断，确认边界块不会重复触发或漏触发阶段切换。重点核查重入调用和多次触发时是否幂等。",
                "fix_suggestion": "封装统一 phase 计算函数并添加边界单元测试（phase1 末块、phase2 首块、跳块场景），确保状态更新单调且可验证。",
            },
            {
                "rule_code": "SBL009",
                "name": "冷却与限额键维度错误",
                "description": "检查 cooldown/limit 统计维度是否与业务对象一致（user/router/pool/phase）",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 addressLastSwapBlock/addressSwappedAmount 的键是否缺少 pool 或 phase 维度，导致用户互相影响、跨池串扰或跨阶段继承。",
                "fix_suggestion": "将统计键明确设计为 (poolId, phase, user) 或等效维度，并在 getter 和处罚逻辑中统一使用同一键空间。",
            },
            {
                "rule_code": "SBL010",
                "name": "跨池共享地址统计污染",
                "description": "检查同一 Hook 复用时地址统计是否在不同池之间共享",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查 mapping(address=>...) 是否在可复用 Hook 中直接承载业务风控统计，若无 poolId 维度则会出现跨池污染和可被恶意池重置/干扰。",
                "fix_suggestion": "引入 per-pool 用户统计结构，所有风控变量均按 poolId 隔离；对历史全局变量提供迁移或废弃策略。",
            },
            {
                "rule_code": "SBL011",
                "name": "治理参数无延迟生效",
                "description": "检查关键参数（费率/限额/惩罚/白名单）是否可即时修改且立即影响用户",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 setPhaseLimit/setPenalty/setFee 等管理函数是否缺少 timelock、公告期或生效延迟，防止治理/管理员突变参数伤害用户。",
                "fix_suggestion": "关键参数采用 timelock + 两阶段提交（queue/execute），并在事件中记录旧值/新值/生效时间。",
            },
            {
                "rule_code": "SBL012",
                "name": "紧急开关缺少职责分离",
                "description": "检查 pause/unpause/emergencyWithdraw 是否缺少多角色职责分离与审计轨迹",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查紧急权限是否集中在单一 owner，是否缺少 guardian/operator 分权，以及缺少事件记录导致追溯困难。",
                "fix_suggestion": "采用最小权限与职责分离（guardian 可暂停，governor 可恢复），并为紧急操作增加事件与可选延迟恢复流程。",
            },
            {
                "rule_code": "SBL013",
                "name": "升级入口权限与初始化风险",
                "description": "检查升级函数与初始化函数是否存在未授权或可重复初始化问题",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查 upgradeTo/upgradeToAndCall/initialize/reinitialize 是否受严格权限控制，是否可被重复调用，是否存在实现合约未禁用初始化。",
                "fix_suggestion": "升级入口仅允许治理合约调用；实现合约构造中禁用初始化；为 reinitializer 设置严格版本递增约束。",
            },
            {
                "rule_code": "SBL014",
                "name": "预言机陈旧数据未校验",
                "description": "检查价格读取是否校验更新时间、回滚轮次和有效区间",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 latestRoundData 等预言机结果是否验证 answeredInRound、updatedAt、price>0 和 staleness window，避免陈旧价参与关键逻辑。",
                "fix_suggestion": "为每个喂价源配置最大陈旧窗口，严格校验 round 完整性与价格有效性，异常时回退或熔断。",
            },
            {
                "rule_code": "SBL015",
                "name": "单点现货价可操纵",
                "description": "检查是否直接使用单区块 spot price 进行清算、铸造或风控判断",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否使用当前池即时报价决定高价值动作（清算、抵押率、铸币），未使用 TWAP/多源聚合将面临闪电贷操纵风险。",
                "fix_suggestion": "优先使用 TWAP 或多源中位价；对高风险操作加入价格偏离保护、速率限制与熔断机制。",
            },
            {
                "rule_code": "SBL016",
                "name": "滑点与最小接收保护缺失",
                "description": "检查 swap/mint/redeem 路径是否强制校验 minOut/maxIn",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查用户关键交易路径是否允许 minOut=0 或未做价格影响保护，是否可能被三明治攻击导致严重价值损失。",
                "fix_suggestion": "在所有交易入口强制 slippage 参数与 deadline 校验；提供合理默认值并在前端/合约两层防护。",
            },
            {
                "rule_code": "SBL017",
                "name": "Fee-on-transfer代币兼容缺失",
                "description": "检查金额计算是否假设 transfer 前后等值，忽略税费/通缩代币差异",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查 token transfer 后是否使用目标余额变化量而非输入参数记账，避免 fee-on-transfer 导致会计偏差与错误限额判断。",
                "fix_suggestion": "采用 balanceBefore/balanceAfter 差值作为实际到账/支出；对非标准 ERC20 增加白名单或兼容分支。",
            },
            {
                "rule_code": "SBL018",
                "name": "舍入与精度偏置",
                "description": "检查定价、份额、手续费计算中的向上/向下取整是否可被套利",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查 mulDiv 和比例换算在 mint/redeem/fee 方向上的取整策略，是否长期偏向单方并可被循环套利放大。",
                "fix_suggestion": "对不同业务方向定义一致的取整策略并进行经济仿真测试，关键路径采用成熟数学库与上限保护。",
            },
            {
                "rule_code": "SBL019",
                "name": "关键不变量缺少断言",
                "description": "检查状态转换后是否验证核心不变量（资金守恒、债务覆盖率、阶段单调性）",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查高价值函数（swap/mint/burn/liquidate/phaseUpdate）执行后是否验证核心不变量，是否仅依赖隐式假设。",
                "fix_suggestion": "为关键流程增加 require/assert 不变量检查，并配套 invariant/fuzz 测试，覆盖边界与异常路径。",
            },
            {
                "rule_code": "SBL020",
                "name": "部署配置与常量不一致",
                "description": "检查脚本/配置/链上参数是否存在常量缺失、网络错配、地址误配问题",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查部署脚本中的常量（工厂地址、路由地址、权限位、链ID）是否定义且与目标网络一致，避免部署后行为偏差或初始化失败。",
                "fix_suggestion": "统一配置源并在部署前执行静态校验（环境变量、链ID、关键地址、权限位、版本号），部署后执行地址与配置回读校验。",
            },
        ]
    },
    {
        "name": "通用逻辑审计规则（智能合约）",
        "description": "跨协议可复用的智能合约业务逻辑审计规则，覆盖状态机、会计一致性、不变量与升级安全",
        "language": "solidity",
        "rule_type": "security",
        "is_default": False,
        "sort_order": 4,
        "severity_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1},
        "rules": [
            {
                "rule_code": "GLB001",
                "name": "状态机单调性与阶段门禁",
                "description": "检查核心流程是否存在显式状态机且状态迁移单调，关键函数是否按阶段受限",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否定义 Init/Active/Closed 等状态机并在关键入口强制校验。重点核查是否存在绕过阶段限制的函数、逆向状态迁移或重复终态切换。",
                "fix_suggestion": "引入显式 enum 状态与统一 modifier；关键流程统一阶段门禁；保证状态迁移单向且终态不可逆。",
            },
            {
                "rule_code": "GLB002",
                "name": "权限边界与职责分离",
                "description": "检查治理、运营、紧急权限是否混用，是否违反最小权限原则",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查 owner/admin/guardian/operator 等角色是否职责重叠，高危函数是否由单一 EOA 控制，是否缺少权限分层与审计轨迹。",
                "fix_suggestion": "采用最小权限模型与职责分离；关键操作引入多签/治理合约；补齐权限变更与高危操作事件。",
            },
            {
                "rule_code": "GLB003",
                "name": "跨入口记账一致性",
                "description": "检查 deposit/withdraw/mint/burn/flashloan/repay 等入口是否采用统一会计口径",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查多入口是否更新同一组核心状态（份额、债务、费用、余额）并遵循同一公式，避免某一路径可绕过费用或约束。",
                "fix_suggestion": "收敛到统一内部记账函数；外部入口仅做参数校验并调用共享核心逻辑。",
            },
            {
                "rule_code": "GLB004",
                "name": "资金守恒不变量",
                "description": "检查关键流程执行前后是否满足资产守恒、债务覆盖、份额一致等不变量",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查高价值函数执行后是否验证资产负债关系与份额约束，是否存在通过边界路径破坏会计恒等式的可能。",
                "fix_suggestion": "为关键路径加入 require/assert 不变量检查，并配套 invariant/fuzz 测试覆盖异常与边界场景。",
            },
            {
                "rule_code": "GLB005",
                "name": "份额定价抗操纵",
                "description": "检查 share/LP 定价是否可被直接转账、临时余额或快照滞后操纵",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查份额铸造/赎回是否直接依赖瞬时 balanceOf 或可被外部转账影响的变量，是否存在价格操纵窗口。",
                "fix_suggestion": "使用内部净资产账本或受控口径进行份额定价；避免直接依赖可操纵瞬时余额。",
            },
            {
                "rule_code": "GLB006",
                "name": "快照时效与失效机制",
                "description": "检查用户份额/分母快照是否在状态变化后失效，避免使用陈旧快照",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 winnerShares、userSharesSnapshot、rateSnapshot 等快照在存取款/转账/重配后是否仍被沿用，是否可能导致分配失真。",
                "fix_suggestion": "引入 epoch/version 与快照失效机制；关键状态变化后强制重算或显式失效旧快照。",
            },
            {
                "rule_code": "GLB007",
                "name": "参与者唯一性与去重",
                "description": "检查 join/register/claim 参与者集合是否可重复写入导致重复计数或重复领取",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查参与者数组/列表是否允许重复地址，计数器是否与集合一致，退出路径是否同步清理状态避免幽灵数据。",
                "fix_suggestion": "使用 mapping 去重并维护一致的 add/remove 流程；同步更新计数器与关联快照。",
            },
            {
                "rule_code": "GLB008",
                "name": "外部调用顺序与重入面",
                "description": "检查外部调用与状态更新顺序，防止回调重入导致状态破坏",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查是否在状态落账前进行 token transfer/callback/external call，是否存在可重入路径影响会计状态。",
                "fix_suggestion": "遵循 Checks-Effects-Interactions；在高风险函数使用 ReentrancyGuard；先更新状态再外部调用。",
            },
            {
                "rule_code": "GLB009",
                "name": "价格源有效性与抗操纵",
                "description": "检查关键决策是否依赖可操纵现货价或陈旧预言机数据",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查清算/铸造/费率是否直接使用 spot price，是否校验预言机 staleness、round 完整性和正值约束。",
                "fix_suggestion": "使用 TWAP 或多源聚合价；配置偏离阈值与熔断；严格校验 oracle 更新时间与轮次完整性。",
            },
            {
                "rule_code": "GLB010",
                "name": "滑点与时效保护",
                "description": "检查价值交换入口是否强制 minOut/maxIn/deadline 保护",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查 swap/mint/redeem/liquidity 操作是否允许零滑点保护或无限时效执行，是否易受抢跑与夹击。",
                "fix_suggestion": "所有价值交换入口强制校验 minOut/maxIn 与 deadline，拒绝过宽参数。",
            },
            {
                "rule_code": "GLB011",
                "name": "非标准 Token 兼容",
                "description": "检查是否错误假设 transfer 等额到账，忽略 fee-on-transfer/rebase 等行为",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查存款、还款、赎回流程是否直接使用输入 amount 记账，是否基于真实到账差值更新状态。",
                "fix_suggestion": "统一采用 balanceBefore/balanceAfter 差值记账；对不兼容代币使用白名单或禁用策略。",
            },
            {
                "rule_code": "GLB012",
                "name": "精度与取整偏置",
                "description": "检查 mul/div 顺序和取整策略是否造成长期偏置或可循环套利",
                "category": "security",
                "severity": "medium",
                "custom_prompt": "检查份额、费用、奖励分配中的舍入方向是否一致，是否存在可通过多次小额操作放大利差。",
                "fix_suggestion": "明确业务方向取整策略并统一实现；关键路径采用安全数学库并设置最小费用阈值。",
            },
            {
                "rule_code": "GLB013",
                "name": "零值与边界条件",
                "description": "检查 totalSupply/reserve/winnerShares/fee 等零值边界是否触发冻结或免费攻击",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查除零、空池、初始状态、极小流动性与零手续费等分支，确认不会产生冻结、套利或错误分配。",
                "fix_suggestion": "显式处理零值边界并提供可恢复路径；必要时设置最小流动性和最小费用下限。",
            },
            {
                "rule_code": "GLB014",
                "name": "可用性与无界循环 DoS",
                "description": "检查是否存在按全量用户遍历结算等可被放大的 O(n) 路径",
                "category": "security",
                "severity": "high",
                "custom_prompt": "检查结算、分发、清理流程是否依赖无界数组遍历，是否可由攻击者扩大参与者规模导致交易不可执行。",
                "fix_suggestion": "采用分页、惰性结算或批处理上限；将全量处理拆分为可中断流程。",
            },
            {
                "rule_code": "GLB015",
                "name": "升级兼容与初始化安全",
                "description": "检查升级前后 storage layout 兼容性及 initialize/reinitialize 安全性",
                "category": "security",
                "severity": "critical",
                "custom_prompt": "检查代理升级时变量顺序/类型/slot 是否兼容，initialize 是否可重复调用，implementation 是否禁用初始化。",
                "fix_suggestion": "升级前执行 storage layout diff；禁用实现合约初始化；reinitializer 严格版本递增并受权限控制。",
            },
        ]
    },
]


async def init_system_templates(db: AsyncSession) -> None:
    """初始化系统提示词模板"""
    for template_data in SYSTEM_PROMPT_TEMPLATES:
        # 检查是否已存在
        result = await db.execute(
            select(PromptTemplate).where(
                PromptTemplate.name == template_data["name"],
                PromptTemplate.is_system == True
            )
        )
        existing = result.scalar_one_or_none()
        
        if not existing:
            template = PromptTemplate(
                name=template_data["name"],
                description=template_data["description"],
                template_type=template_data["template_type"],
                content_zh=template_data["content_zh"],
                content_en=template_data["content_en"],
                variables=json.dumps(template_data.get("variables", {})),
                is_default=template_data.get("is_default", False),
                is_system=True,
                is_active=True,
                sort_order=template_data.get("sort_order", 0),
            )
            db.add(template)
            logger.info(f"✓ 创建系统提示词模板: {template_data['name']}")
    
    await db.flush()


async def init_system_rule_sets(db: AsyncSession) -> None:
    """初始化系统审计规则集"""
    for rule_set_data in SYSTEM_RULE_SETS:
        # 检查是否已存在
        result = await db.execute(
            select(AuditRuleSet).where(
                AuditRuleSet.name == rule_set_data["name"],
                AuditRuleSet.is_system == True
            )
        )
        existing = result.scalar_one_or_none()
        
        if not existing:
            rule_set = AuditRuleSet(
                name=rule_set_data["name"],
                description=rule_set_data["description"],
                language=rule_set_data["language"],
                rule_type=rule_set_data["rule_type"],
                severity_weights=json.dumps(rule_set_data.get("severity_weights", {})),
                is_default=rule_set_data.get("is_default", False),
                is_system=True,
                is_active=True,
                sort_order=rule_set_data.get("sort_order", 0),
            )
            db.add(rule_set)
            await db.flush()
            
            # 创建规则
            for rule_data in rule_set_data.get("rules", []):
                rule = AuditRule(
                    rule_set_id=rule_set.id,
                    rule_code=rule_data["rule_code"],
                    name=rule_data["name"],
                    description=rule_data.get("description"),
                    category=rule_data["category"],
                    severity=rule_data.get("severity", "medium"),
                    custom_prompt=rule_data.get("custom_prompt"),
                    fix_suggestion=rule_data.get("fix_suggestion"),
                    reference_url=rule_data.get("reference_url"),
                    enabled=True,
                    sort_order=rule_data.get("sort_order", 0),
                )
                db.add(rule)
            
            logger.info(f"✓ 创建系统规则集: {rule_set_data['name']} ({len(rule_set_data.get('rules', []))} 条规则)")
    
    await db.flush()


async def init_templates_and_rules(db: AsyncSession) -> None:
    """初始化所有系统模板和规则"""
    logger.info("开始初始化系统模板和规则...")
    
    try:
        await init_system_templates(db)
        await init_system_rule_sets(db)
        await db.commit()
        logger.info("✓ 系统模板和规则初始化完成")
    except Exception as e:
        logger.warning(f"初始化模板和规则时出错（可能表不存在）: {e}")
        await db.rollback()
