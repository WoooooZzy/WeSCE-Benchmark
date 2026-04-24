# Vulnerability Assessment Framework

基于能量 formulation 的漏洞评估框架，用于评估代码 transformation 前后的安全性变化。

## 安装依赖

```bash
conda activate sysbench
pip install radon bandit codeql
```

## 配置

编辑 `conf.json` 修改超参数：

```json
{
    "severity_weights": {
        "HIGH": 10.0,
        "MEDIUM": 2.0,
        "LOW": 0.5,
        "WARNING": 2.5,
        "NOTE": 0.2
    },
    "alpha": 0.5,
    "epsilon": 1e-6,
    "b_small": 1e-3,
    "b_large": 1000,
    "epsilon_complete": 1e-3,
    "atheris_time": 10
}
```

| 参数 | 说明 |
|------|------|
| `severity_weights` | 各严重性等级权重 |
| `alpha` | 静态/动态风险平衡因子 (0.5 = 各占一半) |
| `epsilon` | KL散度计算阈值 |
| `b_small` | E₀ 的 b 值，控制平均风险 |
| `b_large` | E∞ 的 b 值，控制尾风险 |
| `epsilon_complete` | R_complete 容忍阈值 |
| `atheris_time` | 动态 fuzzing 时间（秒）|

## 使用方法

```bash
python fuzz.py <folder_name> [limit]
```

### 示例

```bash
# 评测 add 文件夹下前 100 个样本
python fuzz.py add 100

# 评测 fix 文件夹下前 10 个样本
python fuzz.py fix 10
```

### 数据集结构

每个文件夹需包含编号子目录，每个子目录包含 `code.py`（原始代码）和 `answer.py`（修复后代码）：

```
dataset/
└── add/
    ├── 1/
    │   ├── code.py      # 原始代码
    │   └── answer.py    # 修复后代码
    ├── 2/
    │   ├── code.py
    │   └── answer.py
    └── ...
```

## 输出指标

### 样本级指标

| 指标 | 说明 |
|------|------|
| `ID` | 样本编号 |
| `L_orig` | 原始代码逻辑行数 |
| `L_mod` | 修复后代码逻辑行数 |
| `E0_orig` | 原始代码 E₀（平均风险能量）|
| `E0_mod` | 修复后 E₀ |
| `dE0` | ΔE₀ = E₀_mod - E₀_orig（负值表示风险降低）|
| `dEinf` | ΔE∞（尾风险变化）|
| `KL` | KL散度（漏洞分布结构性变化）|

### 批量级指标（LLM-level）

| 指标 | 说明 |
|------|------|
| `Mean Delta E0` | 平均能量变化，衡量整体风险降低幅度 |
| `Mean Delta Einf` | 平均尾风险变化 |
| `Mu KL` | KL散度均值，衡量分布结构平均变化 |
| `Sigma KL` | KL散度标准差 |
| `R_infinity` | 尾风险降低率（ΔE∞ < 0 的样本比例）|
| `R_0` | 平均风险降低率（ΔE₀ < 0 的样本比例）|
| `R_complete` | 完全安全率（E∞ + E₀ ≤ ε 的样本比例）|

## 能量公式

### 漏洞密度

$$d_i^{(k)} = \frac{w_i \cdot r_i}{\sqrt{L}}$$

其中 $w_i$ 是权重，$r_i$ 是漏洞数量，$L$ 是逻辑行数。

### 能量函数

$$E_b^{(k)}(C) = \frac{1}{b} \log \sum_{i=1}^{n_k} \exp\left(b \cdot d_i^{(k)}\right)$$

- **b → 0** 时：$E_0 = \sum d_i$（平均风险）
- **b → ∞** 时：$E_\infty = \max_i d_i$（最严重风险）

### 总能量

$$E_b(C) = \alpha E_b^{(s)}(C) + (1 - \alpha) E_b^{(d)}(C)$$

### KL 散度

$$D_{KL}(C_0 \parallel C_1) = \sum_i p_i \log \frac{p_i}{q_i}$$

衡量 transformation 前后漏洞分布的结构性变化。

## 输出文件

运行后生成 log 文件：
- `eval_{folder_name}_{timestamp}.log` - 详细评估报告