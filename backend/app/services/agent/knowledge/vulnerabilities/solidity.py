"""
Solidity / 智能合约漏洞知识模块
"""

from ..base import KnowledgeDocument, KnowledgeCategory

SOLIDITY_REENTRANCY = KnowledgeDocument(
    id="vuln_solidity_reentrancy",
    title="Solidity 重入漏洞（Reentrancy）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "reentrancy", "smart-contract", "defi", "call-value"],
    severity="critical",
    cwe_ids=["CWE-841"],
    content="""
# 重入漏洞（Reentrancy）

## 概述
重入漏洞发生在合约向外部地址发送 ETH 或调用外部合约时，外部合约在回调中再次进入原合约，
趁原合约状态尚未更新时重复执行敏感逻辑（如提款）。DAO 攻击（2016）即为典型案例，损失超 3600 万美元。

## 漏洞模式

### 1. 违反 Checks-Effects-Interactions（CEI）原则
```solidity
// ❌ 危险：先转账，再清零余额（外部 fallback 可再次调用 withdraw）
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");  // 外部调用
    require(ok);
    balances[msg.sender] -= amount;  // 状态更新在外部调用后
}
```

### 2. 跨函数重入
```solidity
// ❌ 危险：deposit 和 withdraw 共享状态，attack 可在 withdraw 的 call 回调中调用 deposit
function deposit() external payable {
    balances[msg.sender] += msg.value;
}
function withdraw() external {
    uint bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");
    balances[msg.sender] = 0;  // 顺序错误
}
```

### 3. 只读重入（Read-Only Reentrancy）
```solidity
// ❌ 危险：回调时合约状态不一致，被读取合约的价格/余额可被恶意读取
// 常见于依赖外部合约余额或 LP 份额计算价格的协议
```

## 检测要点
- Source: `msg.sender.call{value:...}(...)` / `.call(data)` / 外部合约调用
- Sink: 函数内早于状态更新的外部 ETH 转账
- 标志: `.call{value:}` 出现在 `balances[x] -= amount` / `_burn()` / `totalSupply` 修改之前

## 修复方案

```solidity
// ✅ 方案一：遵循 CEI 原则（推荐）
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;       // 1. Effects（先更新状态）
    (bool ok,) = msg.sender.call{value: amount}("");  // 2. Interactions
    require(ok);
}

// ✅ 方案二：ReentrancyGuard 互斥锁（OpenZeppelin）
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
```

## 严重性
**Critical** - 可直接导致合约资金被完全盗取。
""",
)


SOLIDITY_INTEGER_OVERFLOW = KnowledgeDocument(
    id="vuln_solidity_integer_overflow",
    title="Solidity 整数溢出/下溢（Integer Overflow/Underflow）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "integer-overflow", "underflow", "safemath", "smart-contract"],
    severity="high",
    cwe_ids=["CWE-190", "CWE-191"],
    content="""
# 整数溢出/下溢

## 概述
Solidity 0.8.0 之前，整数运算不做溢出检查，超出类型范围后会静默回绕（wrap around）。
- `uint8(255) + 1 == 0`（上溢）
- `uint256(0) - 1 == 2^256 - 1`（下溢）

BatchOverflow 攻击（2018）利用 ERC20 合约的乘法溢出铸造天量代币。

## 漏洞模式

### 1. 乘法溢出（最危险）
```solidity
// ❌ Solidity ^0.6.0 无溢出保护
function batchTransfer(address[] memory receivers, uint256 value) public {
    uint256 amount = receivers.length * value;  // 乘法可能溢出→amount=0
    require(balances[msg.sender] >= amount);
    for (uint i = 0; i < receivers.length; i++) {
        balances[receivers[i]] += value;
    }
    balances[msg.sender] -= amount;
}
```

### 2. 加法溢出
```solidity
// ❌ 余额加法溢出→余额归零
balances[to] += amount;   // 若 to 余额接近 uint256.max，则归零
```

### 3. 减法下溢
```solidity
// ❌ 0.8.0 以下无检查
uint256 newBalance = balance - fee;  // balance < fee 时发生下溢
```

### 4. unchecked 块（0.8.0+ 主动绕过）
```solidity
// ⚠️ 显式跳过溢出检查，需严格审计
unchecked {
    counter++;          // 理由充分时可用（如 gas 优化循环计数器）
    balances[x] -= y;  // 危险！y > balances[x] 时下溢
}
```

## 检测要点
- `pragma solidity ^0.7` / `^0.6` 等旧版本 + 算术操作 + 未引入 `SafeMath`
- `unchecked { }` 块内的加减乘法
- `cast`（如 `uint128(largeUint)`）可能截断高位

## 修复方案

```solidity
// ✅ 方案一：升级到 Solidity 0.8.0+（内置检查）
pragma solidity ^0.8.0;

// ✅ 方案二：0.8.0 以下使用 SafeMath
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;
uint256 result = a.add(b);  // 溢出时 revert

// ✅ 方案三：unchecked 块只用于已验证安全的计数器
unchecked { i++; }  // 循环计数器（不涉及金融计算）
```

## 严重性
**High** - 可导致资金任意铸造/销毁，视具体业务逻辑可升级为 Critical。
""",
)


SOLIDITY_ACCESS_CONTROL = KnowledgeDocument(
    id="vuln_solidity_access_control",
    title="Solidity 访问控制缺陷（Access Control）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "access-control", "ownable", "role-based", "tx-origin", "initialize"],
    severity="high",
    cwe_ids=["CWE-284", "CWE-285"],
    content="""
# 访问控制缺陷

## 概述
智能合约中缺少或错误实现的访问控制可导致攻击者调用特权函数（mint、pause、upgrade、withdraw 等），
是 DeFi 协议被攻击的第二大原因（仅次于重入）。

## 漏洞模式

### 1. tx.origin 用于权限验证（钓鱼攻击）
```solidity
// ❌ 攻击者部署中间合约，受害者调用后 tx.origin 仍是受害者
function withdraw() public {
    require(tx.origin == owner, "Not owner");  // 可被钓鱼合约绕过
    payable(msg.sender).transfer(address(this).balance);
}
```

### 2. 初始化函数可被重调用（Proxy 模式）
```solidity
// ❌ 任何人都可以在部署后重新调用 initialize 夺取 owner
function initialize(address _owner) public {
    owner = _owner;  // 缺少 initializer 修饰符
}
```

### 3. 函数可见性过宽
```solidity
// ❌ 本应只被内部调用的敏感函数被标记为 public
function _setPrice(uint256 price) public {  // 应为 internal
    tokenPrice = price;
}
```

### 4. 缺失权限修饰符
```solidity
// ❌ 铸币函数对所有人开放
function mint(address to, uint256 amount) external {  // 缺少 onlyOwner/onlyMinter
    _mint(to, amount);
}
```

### 5. 角色混淆（中心化风险）
```solidity
// ⚠️ 单一 owner 控制所有关键操作，私钥泄露即全损
// 应考虑多签、TimeLock 或 DAO 治理
```

## 检测要点
- `tx.origin` 出现在 `require` 或 `if` 条件中
- `initialize()` 缺少 OpenZeppelin `initializer` 修饰符
- 敏感函数（mint/burn/pause/withdraw/setX/upgrade）没有访问控制修饰符
- `public` 函数执行状态修改但不应对外开放

## 修复方案

```solidity
// ✅ 使用 msg.sender（不受钓鱼攻击影响）
require(msg.sender == owner, "Not owner");

// ✅ initialize 使用 initializer 修饰符
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
function initialize(address _owner) public initializer {
    owner = _owner;
}

// ✅ 使用 OpenZeppelin Ownable 或 AccessControl
import "@openzeppelin/contracts/access/Ownable.sol";
function mint(address to, uint256 amount) external onlyOwner {
    _mint(to, amount);
}

// ✅ 高价值函数使用 TimeLock + 多签
```

## 严重性
**High ~ Critical** - 可直接导致合约资产被盗或功能被破坏。
""",
)


SOLIDITY_ORACLE_MANIPULATION = KnowledgeDocument(
    id="vuln_solidity_oracle_manipulation",
    title="Solidity 预言机操纵与闪贷攻击（Oracle Manipulation / Flash Loan）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "oracle", "flash-loan", "price-manipulation", "twap", "defi"],
    severity="critical",
    content="""
# 预言机操纵与闪贷攻击

## 概述
DeFi 协议使用链上价格（如 AMM spot price）计算抵押价值、清算门槛等关键参数时，
攻击者可通过无抵押闪贷在单笔交易内大幅扭曲价格，从而套利或盗取资金。

## 漏洞模式

### 1. 使用 AMM spot price 作为价格预言机
```solidity
// ❌ Uniswap V2 当前兑换比率可在同一区块内被操控
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // 可被闪贷瞬间扭曲
}
```

### 2. 依赖单一链下预言机（无聚合）
```solidity
// ❌ 单一 Chainlink 源，若数据过时或被操控则无保护
uint256 price = priceFeed.latestAnswer();  // 未检查 updatedAt
```

### 3. 闪贷攻击向量
```solidity
// 攻击流程（单笔交易）：
// 1. 闪贷借大量 TokenA
// 2. 在 AMM 中大额买入 TokenB → 价格拉高
// 3. 以高价格向受害合约抵押 TokenB 借出超额资金
// 4. 归还闪贷 → 价格恢复
// 5. 净利 = 借出资金 - 贷款成本
```

## 检测要点
- `getReserves()` / `.reserve0` / `.reserve1` 直接参与价格计算
- `latestAnswer()` 调用没有检查 `updatedAt` 时间戳
- 价格计算函数没有 TWAP（时间加权平均价）保护
- 合约在同一函数内既接受闪贷又进行价格敏感操作

## 修复方案

```solidity
// ✅ 方案一：使用 Uniswap V3 TWAP（时间加权平均价）
function getTWAP(uint32 secondsAgo) external view returns (int24 tick) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = secondsAgo;
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
    tick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(secondsAgo)));
}

// ✅ 方案二：Chainlink 价格 + 有效性检查
(, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
require(updatedAt >= block.timestamp - MAX_PRICE_AGE, "Stale price");
require(price > 0, "Invalid price");

// ✅ 方案三：Chainlink + 链上 AMM 价格双重验证（偏差超阈值时 revert）
```

## 严重性
**Critical** - 闪贷攻击可在单笔交易内盗取协议全部流动性，历史损失动辄数千万美元。
""",
)


SOLIDITY_SIGNATURE_REPLAY = KnowledgeDocument(
    id="vuln_solidity_signature_replay",
    title="Solidity 签名重放攻击（Signature Replay）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "signature", "replay", "ecrecover", "eip-712", "nonce"],
    severity="high",
    cwe_ids=["CWE-294"],
    content="""
# 签名重放攻击

## 概述
合约通过 `ecrecover` 验证链下签名时，若签名消息不包含 nonce、chainId 或合约地址，
攻击者可重复使用已有的合法签名执行操作，或跨链/跨合约重放签名。

## 漏洞模式

### 1. 缺少 nonce（同一链重放）
```solidity
// ❌ 签名可被无限次重放
function execute(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner);
    payable(to).transfer(amount);  // 同样参数可重复调用
}
```

### 2. 缺少 chainId（跨链重放）
```solidity
// ❌ Mainnet 签名可在测试网/分叉链重放
bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount, nonce));
// 无 block.chainid，主网签名可在相同合约地址的其他链重放
```

### 3. ecrecover 返回 address(0) 未验证
```solidity
// ❌ 无效签名时 ecrecover 返回 address(0)
// 若合约中 owner == address(0) 或 authorizedSigners[address(0)] == true 则被绕过
address signer = ecrecover(hash, v, r, s);
require(authorizedSigners[signer]);  // signer 可能为 address(0)
```

### 4. 前缀哈希格式不规范
```solidity
// ❌ 非标准前缀，钱包签名与合约验证不一致，或可被构造碰撞
bytes32 hash = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", msgHash));
```

## 检测要点
- `ecrecover` 返回值没有与 `address(0)` 比较
- 签名消息 `abi.encodePacked(...)` 中缺少 `nonce`
- 签名消息中缺少 `block.chainid` 或硬编码的 `DOMAIN_SEPARATOR`
- 非 EIP-712 标准的签名验证

## 修复方案

```solidity
// ✅ 使用 EIP-712 + nonce + chainId
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

bytes32 private constant TYPE_HASH = keccak256(
    "Execute(address to,uint256 amount,uint256 nonce,uint256 deadline)"
);

mapping(address => uint256) public nonces;

function execute(address to, uint256 amount, uint256 deadline, bytes memory sig) external {
    require(block.timestamp <= deadline, "Expired");
    bytes32 structHash = keccak256(abi.encode(TYPE_HASH, to, amount, nonces[msg.sender]++, deadline));
    bytes32 hash = _hashTypedDataV4(structHash);          // 含 chainId + 合约地址
    address signer = ECDSA.recover(hash, sig);            // 自动验证非 address(0)
    require(signer == owner, "Invalid signature");
    payable(to).transfer(amount);
}
```

## 严重性
**High** - 重放攻击可导致资金被多次转走，或授权操作被滥用。
""",
)


SOLIDITY_SIGNATURE_MALLEABILITY = KnowledgeDocument(
    id="vuln_solidity_signature_malleability",
    title="Solidity 签名延展性攻击（Signature Malleability）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "signature", "malleability", "ecrecover", "ecdsa", "secp256k1"],
    severity="high",
    cwe_ids=["CWE-347"],
    content="""
# 签名延展性攻击（Signature Malleability）

## 概述
在 secp256k1 椭圆曲线上，对于任意签名 (v, r, s)，存在另一个有效签名 (v', r, s')，
其中 s' = secp256k1n - s，v' = 27 + 28 - v。两个签名对同一消息都是数学上有效的。
若合约直接使用 `ecrecover` 而未限制 s 的范围，攻击者可构造第二个有效签名绕过"签名已使用"检查。

## 漏洞模式

### 1. 直接使用 ecrecover（未限制 s 值）
```solidity
// ❌ 危险：攻击者可通过改变 s 和 v 构造另一个有效签名
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
    address signer = ecrecover(hash, v, r, s);
    require(!usedSignatures[hash], "Already used");
    usedSignatures[hash] = true;  // 用原签名标记后，延展签名可再次通过
}
```

### 2. 未验证 v 值（仅允许 27/28）
```solidity
// ❌ v 值不验证，部分实现允许 v = 0/1 导致行为不一致
address signer = ecrecover(msgHash, v, r, s);
```

## 检测要点
- 直接调用 `ecrecover()` 而非 `ECDSA.recover()`
- 未对 `s` 值检查 `s <= 0x7FFFFFFF...FFFFFFFF`（secp256k1n/2）
- 未对 `v` 值校验必须为 27 或 28

## 修复方案

```solidity
// ✅ 使用 OpenZeppelin ECDSA（已内置 s 低半阶检查 + v 值验证）
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function verify(bytes32 hash, bytes memory signature) public {
    // ECDSA.recover 会在 s 超出低半阶或 v 非法时 revert
    address signer = ECDSA.recover(hash, signature);
    require(signer == expectedSigner, "Invalid signature");
}

// ✅ 若必须用 ecrecover，手动检查 s 值
bytes32 constant SECP256K1N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
require(uint256(s) <= uint256(SECP256K1N_HALF), "Invalid s value");
require(v == 27 || v == 28, "Invalid v value");
```

## 严重性
**High** - 可绕过签名去重逻辑，导致同一操作被执行两次。
""",
)


SOLIDITY_PROXY_SECURITY = KnowledgeDocument(
    id="vuln_solidity_proxy_security",
    title="Solidity 代理合约安全（Proxy Storage Collision & Uninitialized）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "proxy", "upgradeable", "storage-collision", "eip-1967", "initialize", "uups", "transparent"],
    severity="critical",
    cwe_ids=["CWE-665", "CWE-284"],
    content="""
# 代理合约安全

## 概述
可升级合约（Proxy Pattern）有两大常见安全风险：
1. **存储槽冲突**：代理合约与逻辑合约使用相同存储槽，导致变量互相覆写
2. **未初始化的逻辑合约**：逻辑合约直接部署后可被任意地址调用 `initialize`

## 漏洞一：存储槽冲突

### 1. 非 EIP-1967 标准存储槽
```solidity
// ❌ 代理合约 slot 0 存 implementation，与逻辑合约 slot 0 的变量冲突
contract BadProxy {
    address public implementation;  // slot 0 ← 与逻辑合约 slot 0 重叠！
    address public admin;           // slot 1 ← 与逻辑合约 slot 1 重叠！
}
```

### 2. 升级新增变量打乱存储布局
```solidity
// ❌ 升级后在中间插入新变量，导致后续所有变量 slot 偏移
contract V1 { uint256 a; uint256 b; }
contract V2 { uint256 a; uint256 newVar; uint256 b; }  // b 的 slot 从 1 变为 2！
```

### 修复方案
```solidity
// ✅ 使用 EIP-1967 随机 slot（keccak256 - 1 使碰撞概率极低）
bytes32 constant IMPL_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

// ✅ 升级只在末尾追加变量
contract V2 { uint256 a; uint256 b; uint256 newVar; }  // 正确

// ✅ 使用 OpenZeppelin Upgrades 插件自动检测存储兼容性
// npx hardhat compile && npx hardhat run scripts/deploy.js --network mainnet
```

## 漏洞二：未初始化的逻辑合约

### 攻击场景
```solidity
// ❌ 逻辑合约直接部署，任何人可抢先调用 initialize 夺取 owner
contract LogicV1 is Initializable {
    address public owner;
    function initialize(address _owner) public initializer {
        owner = _owner;  // 攻击者在部署后立即调用，占据 owner
    }
    // 没有构造函数调用 _disableInitializers()
}
```

### 修复方案
```solidity
// ✅ 逻辑合约构造函数调用 _disableInitializers()
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract LogicV1 is Initializable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();  // 阻止直接对逻辑合约初始化
    }

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}

// ✅ 部署脚本原子化：deploy + initialize 在同一笔交易
```

## 严重性
**Critical** - 存储冲突可导致逻辑合约覆写代理合约的 implementation 地址；未初始化可导致攻击者获得 owner 权限，进而升级合约到任意逻辑。
""",
)


SOLIDITY_PRECISION_LOSS = KnowledgeDocument(
    id="vuln_solidity_precision_loss",
    title="Solidity 精度损失与除法截断（Precision Loss）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "precision", "division", "rounding", "erc4626", "price-calculation"],
    severity="high",
    cwe_ids=["CWE-682"],
    content="""
# 精度损失与除法截断

## 概述
Solidity 整数除法向下取整（truncation），不当的运算顺序和精度基数选择会导致
实际计算结果偏小甚至为零，影响手续费收取、份额计算、利率计算等关键金融逻辑。

## 漏洞模式

### 1. 先除后乘（精度损失）
```solidity
// ❌ 先除后乘：a=5, b=3, c=2 → 5/3=1 → 1*2=2（实际应为 3.33*2≈6）
uint256 result = (a / b) * c;

// ✅ 先乘后除：5*2/3 = 10/3 = 3（误差从 1 缩小到 0.33）
uint256 result = (a * c) / b;
```

### 2. 手续费计算截断为零
```solidity
// ❌ 小额转账手续费为零（1e6 USDC * 100 / 1e18 = 0）
uint256 fee = amount * feeRate / 1e18;
// 当 amount = 100 USDC（1e8）, feeRate = 0.1%（1e15）:
// 1e8 * 1e15 = 1e23, / 1e18 = 1e5 = 0.1 USDC ✓ 但若基数不匹配则为 0
```

### 3. ERC4626 首次存款攻击（First Depositor Attack）
```solidity
// ❌ 攻击者先存 1 wei，然后直接转入大量 token 到合约
// convertToShares(assets) = assets * totalSupply / totalAssets
// totalSupply=1, totalAssets=1e18+1 时：新存款人 shares 被大幅稀释
function convertToShares(uint256 assets) public view returns (uint256) {
    return assets * totalSupply() / totalAssets();  // 无虚拟储备保护
}
```

### 4. uint128/uint96 存储价格截断
```solidity
// ❌ WBTC 价格 * 精度可能超出 uint128 范围
uint128 price;  // max ≈ 3.4e38，但累积计算可溢出
```

## 修复方案

```solidity
// ✅ 始终先乘后除
uint256 fee = (amount * feeRate) / FEE_PRECISION;

// ✅ ERC4626 添加虚拟储备防止首次存款攻击（OZ v5 已内置）
function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal view virtual returns (uint256)
{
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(),  // 虚拟份额
        totalAssets() + 1,                         // 虚拟资产
        rounding
    );
}

// ✅ 清算向有利于协议方向取整（用 Math.Rounding.Ceil）
uint256 requiredCollateral = debt.mulDiv(collateralRatio, 1e18, Math.Rounding.Ceil);

// ✅ 使用 PRBMath 或 FixedPoint 库处理高精度计算
```

## 严重性
**High** - 精度截断可导致手续费为零（协议收入损失）、份额稀释（用户资产损失）、清算条件计算错误。
""",
)


SOLIDITY_FRONT_RUNNING = KnowledgeDocument(
    id="vuln_solidity_front_running",
    title="Solidity 前端运行与 MEV 攻击（Front-Running / MEV）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "front-running", "mev", "sandwich", "slippage", "commit-reveal", "deadline"],
    severity="high",
    content="""
# 前端运行与 MEV 攻击

## 概述
公链交易进入 mempool 后，矿工/搜索者可以观察到交易内容并通过更高 gas 费抢在前面执行。
主要攻击形式：
- **三明治攻击（Sandwich）**：在目标 swap 前后各插入一笔交易，从滑点中获利
- **抢跑（Frontrunning）**：抢先复制竞拍/铸造交易，以相同条件占据先机
- **MEV**：矿工提取价值，包括套利、清算等

## 漏洞模式

### 1. Swap 无滑点保护
```solidity
// ❌ amountOutMin = 0，接受任意滑点
router.swapExactTokensForTokens(
    amountIn,
    0,              // minAmountOut = 0 → 三明治攻击可使价格偏移 99%
    path,
    address(this),
    block.timestamp
);
```

### 2. deadline = block.timestamp（无截止时间）
```solidity
// ❌ deadline = 当前时间，矿工可任意延迟打包
IUniswapV2Router.swapExactTokensForTokens(
    amountIn, minOut, path, to,
    block.timestamp  // 实际上任何未来时间都满足条件
);
```

### 3. NFT 铸造可被抢跑
```solidity
// ❌ 竞拍出价可被抢跑复制并以稍高 gas 优先执行
function bid(uint256 tokenId) external payable {
    require(msg.value > highestBid[tokenId]);
    highestBid[tokenId] = msg.value;
    highestBidder[tokenId] = msg.sender;
}
```

### 4. 批准（approve）可被抢跑
```solidity
// ❌ approve 从旧值改到新值的过程中，攻击者可快速 transferFrom 两次
token.approve(spender, newAllowance);  // 旧 allowance + 新 allowance 可被双花
```

## 修复方案

```solidity
// ✅ Swap 必须传入用户指定的最小输出量
function swapWithSlippage(
    uint256 amountIn,
    uint256 minAmountOut,  // 用户指定，不得为 0
    uint256 deadline       // 用户指定的截止时间戳
) external {
    require(minAmountOut > 0, "Zero slippage not allowed");
    require(deadline > block.timestamp, "Expired");
    router.swapExactTokensForTokens(amountIn, minAmountOut, path, msg.sender, deadline);
}

// ✅ 竞拍使用 commit-reveal 防抢跑
// Phase 1: commit（提交哈希，不暴露出价）
mapping(address => bytes32) public commitments;
function commit(bytes32 hash) external {
    commitments[msg.sender] = hash;
}
// Phase 2: reveal（揭示出价，此时抢跑已无意义）
function reveal(uint256 amount, bytes32 nonce) external {
    require(commitments[msg.sender] == keccak256(abi.encode(amount, nonce)));
    // 处理出价...
}

// ✅ ERC20 使用 increaseAllowance/decreaseAllowance 替代 approve
token.increaseAllowance(spender, addedValue);
```

## 严重性
**High** - 三明治攻击可导致用户在每次 swap 中损失数百至数万美元；抢跑可使竞拍/铸造机制完全失效。
""",
)


SOLIDITY_CROSSCHAIN_SECURITY = KnowledgeDocument(
    id="vuln_solidity_crosschain_security",
    title="Solidity 跨链消息伪造（Cross-Chain Message Forgery）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "cross-chain", "bridge", "layerzero", "ccip", "message-forgery", "relay"],
    severity="critical",
    content="""
# 跨链消息伪造

## 概述
跨链协议（LayerZero、Chainlink CCIP、Axelar 等）通过中继合约在链间传递消息。
若目标链合约的回调函数（lzReceive / ccipReceive / xReceive）不验证消息来源，
攻击者可直接调用该函数伪造跨链消息，无需在源链发出真实请求。

## 漏洞模式

### 1. 回调函数未验证 msg.sender
```solidity
// ❌ 任何人都可以调用 lzReceive，伪造任意跨链消息
function lzReceive(
    uint16 srcChainId,
    bytes memory srcAddress,
    uint64 nonce,
    bytes memory payload
) external override {
    // 没有验证 msg.sender == lzEndpoint
    _mint(abi.decode(payload, (address)), amount);  // 无限铸币
}
```

### 2. 未验证来源链 ID 和来源合约地址
```solidity
// ❌ 接受来自任意链、任意合约的消息
function ccipReceive(Client.Any2EVMMessage memory message) external {
    // 未检查 message.sourceChainSelector 是否在白名单
    // 未检查 message.sender 是否为授权合约
    _processMessage(message.data);
}
```

### 3. 跨链消息未含 nonce（重放攻击）
```solidity
// ❌ 同一消息可被中继多次
function xReceive(bytes32 transferId, uint256 amount, address to) external {
    // 未记录已处理的 transferId
    _mint(to, amount);
}
```

## 检测要点
- `lzReceive` / `ccipReceive` / `xReceive` / `executeWithToken` 第一行是否有 `msg.sender` 校验
- 是否双重验证来源链 ID + 来源合约地址
- 是否记录已处理消息哈希防止重放
- 铸造/解锁函数是否仅限跨链回调合约调用

## 修复方案

```solidity
// ✅ LayerZero：验证 msg.sender 为 endpoint，并验证来源合约
function lzReceive(
    uint16 srcChainId,
    bytes memory srcAddress,
    uint64 nonce,
    bytes memory payload
) external override {
    require(msg.sender == address(lzEndpoint), "Invalid endpoint");
    require(srcChainId == trustedSrcChain, "Untrusted chain");
    address srcContract = abi.decode(srcAddress, (address));
    require(srcContract == trustedSrcContract[srcChainId], "Untrusted source");

    bytes32 msgHash = keccak256(abi.encode(srcChainId, srcContract, nonce, payload));
    require(!processedMessages[msgHash], "Already processed");
    processedMessages[msgHash] = true;

    _processPayload(payload);
}

// ✅ Chainlink CCIP：使用 onlyRouter 修饰符
modifier onlyRouter() {
    require(msg.sender == address(i_router), "Only router");
    _;
}
function ccipReceive(Client.Any2EVMMessage memory message)
    external override onlyRouter
{
    require(allowlistedSourceChains[message.sourceChainSelector], "Not allowlisted");
    require(allowlistedSenders[abi.decode(message.sender, (address))], "Not allowlisted");
    // ...
}
```

## 严重性
**Critical** - 伪造跨链消息可无限铸造跨链资产，历史上已有多起亿美元级别的桥接漏洞。
""",
)


SOLIDITY_ERC20_SAFETY = KnowledgeDocument(
    id="vuln_solidity_erc20_safety",
    title="Solidity ERC20 非标准实现与安全问题",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "erc20", "safeERC20", "fee-on-transfer", "rebase", "approve", "usdt", "non-standard"],
    severity="high",
    cwe_ids=["CWE-252"],
    content="""
# ERC20 非标准实现与安全问题

## 概述
ERC20 标准存在多种非标准变体，若协议直接调用 `.transfer()` 而未使用 `SafeERC20`，
可能因返回值缺失、Fee-on-Transfer、Rebase 等特性导致资金损失。

## 漏洞模式

### 1. 不返回 bool 的代币（USDT、BNB 等）
```solidity
// ❌ USDT 的 transfer() 不返回 bool，直接调用在旧版 Solidity 会 revert
IERC20(usdt).transfer(to, amount);       // Solidity 0.8 中因 ABI 不匹配会 revert
IERC20(usdt).transferFrom(from, to, amount);
```

### 2. Fee-on-Transfer 代币（SAFEMOON 等）
```solidity
// ❌ 实际到账金额 < amount（被收取 1-10% 转账税）
function deposit(uint256 amount) external {
    token.safeTransferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // 错误！实际到账可能只有 0.9 * amount
}
```

### 3. Rebase 代币（stETH 等）
```solidity
// ❌ stETH 余额每天自动增加，用 amount 记账会导致累积误差
function stake(uint256 amount) external {
    stETH.transferFrom(msg.sender, address(this), amount);
    stakedAmount[msg.sender] += amount;  // 记账值与实际持有量逐渐偏离
}
```

### 4. approve Race Condition
```solidity
// ❌ Alice approve Bob 100 → Bob 看到后立即 transferFrom 100
// Alice 再 approve Bob 50 → Bob 又 transferFrom 50，共获得 150
token.approve(bob, 50);  // 应先 approve(bob, 0) 再 approve(bob, 50)
```

### 5. ERC20 decimals 不为 18
```solidity
// ❌ USDC 是 6 decimals，WBTC 是 8 decimals
// 直接与假设 18 decimals 的逻辑交互导致计算错误
uint256 valueInEth = usdcAmount * usdcPrice / 1e18;  // 错！USDC 是 1e6
```

## 修复方案

```solidity
// ✅ 使用 OpenZeppelin SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

IERC20(token).safeTransfer(to, amount);
IERC20(token).safeTransferFrom(from, to, amount);

// ✅ Fee-on-Transfer：用余额差计算实际到账
uint256 before = IERC20(token).balanceOf(address(this));
IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(token).balanceOf(address(this)) - before;
balances[msg.sender] += received;  // 使用实际到账量

// ✅ approve race condition：先清零再设置
IERC20(token).safeApprove(spender, 0);
IERC20(token).safeApprove(spender, newAmount);
// 或使用 increaseAllowance
IERC20(token).safeIncreaseAllowance(spender, addedValue);

// ✅ 多 decimals 场景：规范化到 18 位
uint256 normalizedAmount = amount * (10 ** (18 - token.decimals()));
```

## 严重性
**High** - 非标准 ERC20 可导致资金卡死、协议内部记账错误，Fee-on-Transfer 可导致系统性亏空。
""",
)


SOLIDITY_AMM_SECURITY = KnowledgeDocument(
    id="vuln_solidity_amm_security",
    title="Solidity AMM 流动性池安全（AMM Security）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "amm", "uniswap", "defi", "liquidity", "first-depositor", "flash-loan", "invariant"],
    severity="critical",
    content="""
# AMM 流动性池安全

## 概述
AMM（自动做市商）协议面临多种特有攻击，包括首次流动性注入攻击、闪电贷储备操控、
手续费计算错误导致不变量破坏等。

## 漏洞模式

### 1. 首次流动性注入价格操控
```solidity
// ❌ 第一个 LP 可以以极端比例注入流动性，设定荒谬初始价格
function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
    if (totalSupply == 0) {
        liquidity = Math.sqrt(amount0 * amount1);  // 没有 MINIMUM_LIQUIDITY 锁定
    }
    // 攻击者可以 1:1e18 的比例注入，使后续 LP 注入比例失调
}
```

### 2. LP Token 膨胀攻击（闪电贷）
```solidity
// ❌ 使用 balanceOf 计算储备量，可被直接转入 token 操控
function getReserve() internal view returns (uint256) {
    return IERC20(token0).balanceOf(address(this));  // 可被直接转入膨胀
    // 应该使用内部 reserve 变量而非实时 balanceOf
}
```

### 3. 手续费未正确计入不变量
```solidity
// ❌ 手续费后计算导致 xy=k 不变量被轻微违反，可被累积利用
uint256 amountOut = (reserve1 * amountIn) / (reserve0 + amountIn);
// 正确：应先扣除手续费再计算 amountOut
```

### 4. 同区块多笔操作绕过保护
```solidity
// ❌ 无区块锁定，同一区块内可多次操作绕过价格影响检测
uint256 lastInteractionBlock;
require(block.number > lastInteractionBlock, "Same block");  // 可被绕过
```

## 修复方案

```solidity
// ✅ 首次 LP 锁定 MINIMUM_LIQUIDITY（Uniswap V2 做法）
uint256 constant MINIMUM_LIQUIDITY = 1000;
if (totalSupply == 0) {
    liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
    _mint(address(0), MINIMUM_LIQUIDITY);  // 永久锁定，防止精度操控
}

// ✅ 使用内部 reserve 变量而非实时 balanceOf
uint112 private reserve0;
uint112 private reserve1;
function _update(uint256 balance0, uint256 balance1) private {
    reserve0 = uint112(balance0);
    reserve1 = uint112(balance1);
}

// ✅ Uniswap V2 标准：手续费先扣除再计算
uint256 amountInWithFee = amountIn * 997;  // 0.3% 手续费
uint256 amountOut = (reserve1 * amountInWithFee) / (reserve0 * 1000 + amountInWithFee);

// ✅ 使用 TWAP 而非 spot price 做价格预言机
```

## 严重性
**Critical** - AMM 攻击可导致流动性池资产被完全抽空，历史上已有多起千万美元级别的损失。
""",
)


SOLIDITY_LENDING_SECURITY = KnowledgeDocument(
    id="vuln_solidity_lending_security",
    title="Solidity 借贷协议清算安全（Lending & Liquidation）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "lending", "liquidation", "health-factor", "oracle", "defi", "compound", "aave"],
    severity="critical",
    content="""
# 借贷协议清算安全

## 概述
借贷协议的清算机制是抵御坏账的最后防线。清算逻辑中的价格依赖、激励设计、
并发处理等问题可能导致清算失效或被恶意操控。

## 漏洞模式

### 1. 健康因子使用现货价格（闪贷操控）
```solidity
// ❌ 使用 AMM 现货价格计算健康因子，可被闪贷瞬间操控
function getHealthFactor(address user) public view returns (uint256) {
    uint256 price = getSpotPrice();  // 闪电贷可操控此值
    uint256 collateralValue = collateral[user] * price / 1e18;
    return collateralValue * 1e18 / debt[user];
}
```

### 2. 清算奖励不足（无人清算）
```solidity
// ❌ 清算奖励过低，Gas 成本超过奖励，导致抵押不足头寸无人处理
uint256 liquidationBonus = 1%;  // 太低，Gas 成本可能超过 1%
```

### 3. 清算被恶意借款人阻止
```solidity
// ❌ 借款人 receive() 函数故意 revert，阻止清算
function liquidate(address borrower) external {
    // 偿还债务给借款人
    (bool ok,) = borrower.call{value: repayAmount}("");  // 可被 revert 阻断
    require(ok, "Repay failed");
}
```

### 4. 清算边界条件计算错误
```solidity
// ❌ 部分清算后健康因子反而更低
function partialLiquidate(address user, uint256 repayAmount) external {
    // 未验证清算后 healthFactor > MIN_HEALTH_FACTOR
    debt[user] -= repayAmount;
    // 如果清算比例过大导致抵押率倒挂，用户变成净债务人
}
```

## 修复方案

```solidity
// ✅ 健康因子使用 Chainlink 喂价（不可被单块操控）
function getHealthFactor(address user) public view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(updatedAt >= block.timestamp - 3600, "Stale price");
    require(price > 0, "Invalid price");

    uint256 collateralValue = collateral[user] * uint256(price) / 1e8;
    return collateralValue * LTV_PRECISION / debt[user];
}

// ✅ 合理的清算奖励（5-15%）
uint256 constant LIQUIDATION_BONUS = 105e16;  // 5% bonus

// ✅ 清算不依赖外部调用成功（推拉模式）
function liquidate(address borrower) external nonReentrant {
    require(getHealthFactor(borrower) < MIN_HEALTH_FACTOR, "Not liquidatable");
    uint256 seize = computeSeizeAmount(repayAmount);

    debt[borrower] -= repayAmount;
    collateral[borrower] -= seize;
    collateral[msg.sender] += seize;  // 清算人收到抵押物，无需外部调用
}

// ✅ 清算后验证健康因子改善
require(getHealthFactor(borrower) > MIN_HEALTH_FACTOR_POST_LIQUIDATION, "Bad liquidation");

// ✅ 引入坏账社会化机制（极端行情时）
```

## 严重性
**Critical** - 清算失效导致协议积累坏账，最终可能导致协议资不抵债（历史案例：Venus、Euler 等）。
""",
)


SOLIDITY_DEFI_DOS = KnowledgeDocument(
    id="vuln_solidity_defi_dos",
    title="Solidity DoS 攻击（拒绝服务 / Gas Limit）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "dos", "gas-limit", "push-payment", "pull-payment", "unbounded-loop"],
    severity="high",
    cwe_ids=["CWE-400", "CWE-703"],
    content="""
# DoS 攻击（拒绝服务）

## 概述
智能合约 DoS 分为两类：
1. **Gas Limit DoS**：单笔交易 Gas 消耗超出区块上限，操作无法完成
2. **强制 Revert DoS**：合约依赖外部调用成功，攻击者让外部调用故意失败使合约卡死

## 漏洞模式

### 1. Push 分红模式（循环转账）
```solidity
// ❌ 所有持币人列表可被无限增长，最终一次 distribute 超过区块 Gas 上限
address[] public holders;

function distribute() external {
    uint256 share = address(this).balance / holders.length;
    for (uint i = 0; i < holders.length; i++) {
        payable(holders[i]).transfer(share);  // 任意一个 revert 则全部失败
    }
}
```

### 2. 依赖外部调用成功（强制 Revert）
```solidity
// ❌ 竞拍退款：若当前最高出价者的 receive() revert，则所有人无法继续出价
function bid() external payable {
    require(msg.value > highestBid);
    require(payable(previousBidder).send(previousBid), "Refund failed");  // 攻击点
    highestBidder = msg.sender;
    highestBid = msg.value;
}
```

### 3. 无界数组遍历
```solidity
// ❌ 用户可无限 stake，totalUsers 增长后 claimAll 超 Gas 上限
function claimAll() external onlyOwner {
    for (uint i = 0; i < users.length; i++) {  // users 无界
        _claim(users[i]);
    }
}
```

## 检测要点
- `for` 循环中包含 `.transfer()` / `.send()` / `.call{value}`
- `require(payable(x).send(...))` 强依赖外部转账成功
- 地址数组（holders/users/stakers）作为循环目标且无上界限制
- 单笔操作 Gas 与用户数量线性正相关

## 修复方案

```solidity
// ✅ 方案一：Pull Payment 模式（用户自己 claim）
mapping(address => uint256) public pendingRewards;

function distribute() external {
    for (uint i = 0; i < holders.length; i++) {
        pendingRewards[holders[i]] += share;  // 只更新账本，不转账
    }
}

function claim() external {
    uint256 amount = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}

// ✅ 方案二：分页操作（设置最大迭代次数）
function distributeRange(uint256 start, uint256 end) external {
    require(end <= holders.length && end - start <= MAX_BATCH, "Too large");
    for (uint i = start; i < end; i++) {
        pendingRewards[holders[i]] += share;
    }
}

// ✅ 方案三：外部调用失败时跳过（不阻断全流程）
for (uint i = 0; i < holders.length; i++) {
    (bool ok,) = payable(holders[i]).call{value: share}("");
    if (!ok) {
        pendingRewards[holders[i]] += share;  // 失败则记录待提取
    }
}
```

## 严重性
**High** - DoS 可永久锁定合约核心功能（分红/竞拍/清算），在竞拍/借贷协议中尤为危险。
""",
)


SOLIDITY_GOVERNANCE_SECURITY = KnowledgeDocument(
    id="vuln_solidity_governance_security",
    title="Solidity 治理攻击（Governance Attack）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "governance", "dao", "flash-loan", "snapshot", "voting", "quorum", "timelock"],
    severity="high",
    content="""
# 治理攻击

## 概述
链上治理合约通过代币投票决定协议升级和参数变更。若设计不当，攻击者可通过
闪贷刷高投票权、低门槛通过恶意提案、绕过 Timelock 即时执行高权限操作。

## 漏洞模式

### 1. 基于实时余额投票（闪贷刷票）
```solidity
// ❌ 攻击者借闪贷获得大量 Token，在同一区块投票通过恶意提案
function getVotes(address account) public view returns (uint256) {
    return governanceToken.balanceOf(account);  // 实时余额，闪贷可操控
}
```

### 2. 无投票延迟（Voting Delay = 0）
```solidity
// ❌ 提案一创建立即可投票，攻击者可准备好票仓后创建+投票一气呵成
function votingDelay() public pure override returns (uint256) {
    return 0;  // 无缓冲期
}
```

### 3. Quorum 过低或为零
```solidity
// ❌ 仅需极少数票就能通过提案
function quorum(uint256) public pure override returns (uint256) {
    return 1 ether;  // 仅 1 个 Token 即可满足法定人数
}
```

### 4. 提案可附带任意调用（无内容审查）
```solidity
// ❌ 提案的 targets/calldatas 可以是任意函数调用，包括 mint 给攻击者
function propose(
    address[] memory targets,    // 可以是任意合约
    uint256[] memory values,
    bytes[] memory calldatas,    // 可以是任意函数调用
    string memory description
) public returns (uint256) {}
```

## 历史案例
- **Beanstalk（2022）**：攻击者通过闪贷获得多数投票权，通过恶意提案将协议资金全部转走，损失约 1.8 亿美元

## 修复方案

```solidity
// ✅ 使用历史快照防止闪贷刷票（OpenZeppelin Governor + ERC20Votes）
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
// ERC20Votes.getPastVotes(account, block.number - 1) 使用历史快照

// ✅ 合理的 votingDelay（至少 1-2 天，约 7200 区块）
function votingDelay() public pure override returns (uint256) {
    return 7200;  // ~1 day
}

// ✅ 合理 quorum（如总供应量的 4%）
function quorum(uint256 blockNumber) public view override returns (uint256) {
    return governanceToken.getPastTotalSupply(blockNumber) * 4 / 100;
}

// ✅ 提案执行通过 TimelockController（至少 48h 延迟）
import "@openzeppelin/contracts/governance/TimelockController.sol";
// 用户有 48h 观察提案内容并撤离资金

// ✅ 对关键操作设置更高门槛（双重验证）
function _execute(uint256 proposalId, ...) internal override {
    // 高危操作需要额外的 Guardian 多签批准
}
```

## 严重性
**High** - 治理攻击可导致协议被完全接管，所有资产被转走。
""",
)


SOLIDITY_NFT_SECURITY = KnowledgeDocument(
    id="vuln_solidity_nft_security",
    title="Solidity NFT 安全漏洞",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "nft", "erc721", "erc1155", "mint", "safeTransferFrom", "metadata", "royalty"],
    severity="high",
    content="""
# NFT 安全漏洞

## 概述
NFT 合约面临多种特有安全问题：safeTransferFrom 触发重入、可预测 tokenId 被抢跑、
铸造无上限、元数据被篡改、版税绕过等。

## 漏洞模式

### 1. safeTransferFrom 触发重入（onERC721Received 回调）
```solidity
// ❌ safeTransferFrom 会调用接收方 onERC721Received，可被恶意合约重入
function mint(uint256 tokenId) external payable {
    _safeMint(msg.sender, tokenId);  // 触发 onERC721Received 回调
    // 若后续还有状态更新，可在回调中重入提前完成
}

// 攻击合约
contract Attack {
    function onERC721Received(...) external returns (bytes4) {
        // 在回调中再次调用 mint，此时前一个 mint 的状态未更新
        nft.mint{value: 0}(nextTokenId);
        return this.onERC721Received.selector;
    }
}
```

### 2. 可预测 tokenId（被抢跑）
```solidity
// ❌ tokenId 基于 block 数据，攻击者可提前计算并抢占特定 ID
uint256 tokenId = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
// 攻击者通过模拟计算出目标 ID，然后以更高 gas 抢跑
```

### 3. 无 maxSupply 限制（无限铸造）
```solidity
// ❌ 没有总量上限，mint 可被无限调用
function mint(address to) external onlyOwner {
    _mint(to, _tokenIdCounter++);  // 无 maxSupply 检查
}
```

### 4. 可变 baseURI（元数据可被篡改）
```solidity
// ❌ owner 可随时修改 baseURI，NFT 元数据变成"活的"
string private baseURI;
function setBaseURI(string memory newURI) external onlyOwner {
    baseURI = newURI;  // 购买者发现元数据已被替换
}
```

### 5. 版税绕过（EIP-2981 缺失）
```solidity
// ❌ 未实现 royaltyInfo，二级市场可绕过版税
// 交易市场通过检查 supportsInterface(0x2a55205a) 判断是否支持版税
```

## 修复方案

```solidity
// ✅ _safeMint 调用处添加 nonReentrant
function mint(uint256 quantity) external payable nonReentrant {
    require(totalSupply() + quantity <= MAX_SUPPLY, "Exceeds max supply");
    _safeMint(msg.sender, quantity);
}

// ✅ 使用单调递增计数器作为 tokenId（不可预测下一个 ID 的实际价值）
using Counters for Counters.Counter;
Counters.Counter private _tokenIdCounter;
function _nextTokenId() internal returns (uint256) {
    return _tokenIdCounter.increment();
}

// ✅ 严格的 maxSupply 检查
uint256 public constant MAX_SUPPLY = 10000;
function mint(uint256 qty) external {
    require(_totalMinted() + qty <= MAX_SUPPLY, "Exceeds max supply");
    require(_numberMinted(msg.sender) + qty <= MAX_PER_WALLET, "Exceeds wallet limit");
}

// ✅ 不可变 baseURI（发布后锁定，metadata 存 IPFS）
string private immutable _baseTokenURI;  // immutable 在构造函数设置后不可更改

// ✅ 实现 EIP-2981 版税
function royaltyInfo(uint256, uint256 salePrice)
    external view override returns (address receiver, uint256 royaltyAmount)
{
    return (royaltyRecipient, salePrice * royaltyBps / 10000);
}
```

## 严重性
**High** - NFT 重入可导致免费铸造多个 Token；无 maxSupply 导致稀缺性预期被打破；可变元数据影响持有者权益。
""",
)


SOLIDITY_STAKING_SECURITY = KnowledgeDocument(
    id="vuln_solidity_staking_security",
    title="Solidity 质押与奖励分配安全",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "staking", "reward", "synthetix", "rewardPerToken", "division-by-zero", "defi"],
    severity="high",
    content="""
# 质押与奖励分配安全

## 概述
质押合约的奖励分配逻辑（参考 Synthetix StakingRewards）中存在多种数学和并发安全问题：
除零崩溃、奖励与质押同代币导致重入、外部 balanceOf 被破坏、闪电单块套利等。

## 漏洞模式

### 1. rewardPerToken 除零崩溃
```solidity
// ❌ totalSupply = 0 时崩溃
function rewardPerToken() public view returns (uint256) {
    return rewardPerTokenStored + (
        (block.timestamp - lastUpdateTime) * rewardRate * 1e18
        / totalSupply  // totalSupply = 0 时 revert！
    );
}
```

### 2. 奖励 Token 与质押 Token 相同
```solidity
// ❌ 若 stakingToken == rewardToken，getReward 的 transfer 可重入 stake
contract BrokenStaking {
    IERC20 public stakingToken;
    IERC20 public rewardToken = stakingToken;  // 相同！

    function getReward() external {
        uint256 reward = earned(msg.sender);
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
        // ↑ 若 rewardToken 是 ERC777，transfer 触发 tokensReceived
        //   攻击者在 tokensReceived 中再次调用 stake，此时 rewards 已清零但 totalSupply 已增
    }
}
```

### 3. balanceOf 计账被破坏
```solidity
// ❌ 使用实时 balanceOf 计算 totalSupply，直接转入 token 可破坏所有奖励计算
uint256 totalSupply = stakingToken.balanceOf(address(this));  // 可被外部转入操控

// ✅ 应使用内部变量
uint256 private _totalSupply;
mapping(address => uint256) private _balances;
```

### 4. 单区块闪电套利（Stake → Claim → Unstake）
```solidity
// ❌ 没有 lock period，攻击者可在同一区块 stake → 领取奖励 → unstake
function stake(uint256 amount) external {
    _totalSupply += amount;
    _balances[msg.sender] += amount;
    // 无最小锁仓时间
}
```

## 修复方案（Synthetix 标准模式）

```solidity
// ✅ totalSupply = 0 时跳过奖励更新
function rewardPerToken() public view returns (uint256) {
    if (_totalSupply == 0) {
        return rewardPerTokenStored;  // 无人质押时不累积
    }
    return rewardPerTokenStored + (
        (lastTimeRewardApplicable() - lastUpdateTime) * rewardRate * 1e18 / _totalSupply
    );
}

// ✅ 使用内部变量追踪余额，不用 balanceOf
mapping(address => uint256) private _balances;
uint256 private _totalSupply;

function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
    require(amount > 0, "Cannot stake 0");
    _totalSupply += amount;
    _balances[msg.sender] += amount;
    stakingToken.safeTransferFrom(msg.sender, address(this), amount);
}

// ✅ getReward 独立 nonReentrant
function getReward() external nonReentrant updateReward(msg.sender) {
    uint256 reward = rewards[msg.sender];
    if (reward > 0) {
        rewards[msg.sender] = 0;
        rewardToken.safeTransfer(msg.sender, reward);
    }
}

// ✅ 奖励 Token 与质押 Token 必须不同，或使用 nonReentrant 全覆盖
require(address(rewardToken) != address(stakingToken), "Tokens must differ");

// ✅ 可选：最小锁仓时间防止闪电套利
mapping(address => uint256) public lastStakeTime;
function getReward() external {
    require(block.timestamp >= lastStakeTime[msg.sender] + MIN_LOCK_PERIOD, "Still locked");
    // ...
}
```

## 严重性
**High** - 除零崩溃可导致合约完全不可用；重入攻击可多次领取奖励；balanceOf 破坏导致奖励计算失真。
""",
)


SOLIDITY_MULTISIG_SECURITY = KnowledgeDocument(
    id="vuln_solidity_multisig_security",
    title="Solidity 多签钱包安全（Multisig Security）",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["solidity", "multisig", "gnosis-safe", "duplicate-signature", "nonce", "threshold", "delegatecall"],
    severity="critical",
    content="""
# 多签钱包安全

## 概述
自实现的多签合约中存在重复签名计数、阈值可被单独降低、nonce 绕过、
delegatecall 任意目标等严重问题。推荐直接使用经过审计的 Gnosis Safe。

## 漏洞模式

### 1. 重复签名被计为多票
```solidity
// ❌ 同一签名者提交多次，被计为多个有效签名
function execute(bytes[] memory signatures) external {
    uint256 count = 0;
    for (uint i = 0; i < signatures.length; i++) {
        address signer = recoverSigner(txHash, signatures[i]);
        if (isOwner[signer]) {
            count++;  // 没有检查 signer 是否已被计数
        }
    }
    require(count >= threshold);
}
```

### 2. 阈值可被单一 owner 降至 1
```solidity
// ❌ 单个 owner 可调用 changeThreshold 降低到 1，再单独执行任意操作
function changeThreshold(uint256 newThreshold) external onlyOwner {
    threshold = newThreshold;  // 应要求满足当前 threshold 的多签批准
}
```

### 3. Nonce 绕过
```solidity
// ❌ nonce 未严格递增，允许跳跃或重用
function execute(uint256 nonce, ...) external {
    require(nonce >= usedNonces[nonce], "Nonce used");  // 错！nonce 可跳跃
    usedNonces[nonce] = true;
}
// 正确：require(nonce == expectedNonce++) 严格递增
```

### 4. delegatecall 对任意目标开放
```solidity
// ❌ 多签可以 delegatecall 任意合约，包括恶意升级合约
function execute(address to, bytes memory data, bool isDelegateCall) external {
    if (isDelegateCall) {
        (bool ok,) = to.delegatecall(data);  // to 无白名单限制
    }
}
```

### 5. 签名未含 chainId 和合约地址
```solidity
// ❌ 签名可在其他链或其他多签合约重放
bytes32 txHash = keccak256(abi.encode(to, value, data, nonce));
// 缺少 chainId 和 address(this)
```

## 修复方案

```solidity
// ✅ 签名去重（按地址排序后验证单调递增）
function execute(bytes memory signatures) external {
    bytes32 txHash = getTransactionHash(to, value, data, nonce++);
    address lastSigner = address(0);
    uint256 count = 0;
    for (uint i = 0; i < signatures.length; i += 65) {
        address signer = recoverSigner(txHash, signatures, i);
        require(signer > lastSigner, "Duplicate or unsorted signers");  // 去重
        require(isOwner[signer], "Not owner");
        lastSigner = signer;
        count++;
    }
    require(count >= threshold, "Below threshold");
}

// ✅ 阈值变更需满足当前 threshold
function changeThreshold(uint256 newThreshold, bytes memory sigs) external {
    require(_verifySignatures(sigs, threshold), "Insufficient signatures");
    threshold = newThreshold;
}

// ✅ 签名包含 chainId + 合约地址
bytes32 txHash = keccak256(abi.encode(
    block.chainid, address(this), to, value, data, nonce
));

// ✅ delegatecall 目标白名单
mapping(address => bool) public approvedTargets;
function execute(..., bool isDelegateCall) external {
    if (isDelegateCall) {
        require(approvedTargets[to], "Target not approved");
    }
}

// ✅ 推荐直接使用 Gnosis Safe（已经过多轮审计）
```

## 严重性
**Critical** - 多签安全漏洞可导致攻击者绕过多签保护，独自完成高权限操作，协议资产全损。
""",
)


__all__ = [
    "SOLIDITY_REENTRANCY",
    "SOLIDITY_INTEGER_OVERFLOW",
    "SOLIDITY_ACCESS_CONTROL",
    "SOLIDITY_ORACLE_MANIPULATION",
    "SOLIDITY_SIGNATURE_REPLAY",
    "SOLIDITY_SIGNATURE_MALLEABILITY",
    "SOLIDITY_PROXY_SECURITY",
    "SOLIDITY_PRECISION_LOSS",
    "SOLIDITY_FRONT_RUNNING",
    "SOLIDITY_CROSSCHAIN_SECURITY",
    "SOLIDITY_ERC20_SAFETY",
    "SOLIDITY_AMM_SECURITY",
    "SOLIDITY_LENDING_SECURITY",
    "SOLIDITY_DEFI_DOS",
    "SOLIDITY_GOVERNANCE_SECURITY",
    "SOLIDITY_NFT_SECURITY",
    "SOLIDITY_STAKING_SECURITY",
    "SOLIDITY_MULTISIG_SECURITY",
]
