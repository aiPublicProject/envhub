# keyfort

**简体中文** | [English](README.md)

> 加密本地密钥文件，启动时注入环境变量，无代码侵入一键启用，避免密钥信息泄露。

2026 年，xAI 的 Grok Build 和智谱的 ZCode 先后被曝**静默上传用户整个代码库**——
Git 历史、本地记录、明文密钥一并打包上云。keyfort 把敏感密钥加密成一个
`.keyfort` 文件：就算哪天被工具打包传走，传走的也只是密文。

`DB_PASS`、`API_KEY` 这类敏感配置不再以明文躺在项目里；开发时进入项目目录，
密钥自动注入环境变量——`npm run dev`、`python main.py` 原样执行，
**代码一行都不用改**。

纯本地工具：不需要账号、不连服务器、不做任何网络请求。给个人开发者。

## 快速一览

```console
$ pip install keyfort

$ cd 我的项目
$ keyfort .env.local 我的密码
加密范围？[1] 全部（回车默认） [2] 部分（编辑器里只保留要加密的行）: 2
   ↳ 弹出你的编辑器：只留下要加密的行，保存关闭
原文件 .env.local 的配置怎么处理？[1] 从原文件隐藏密钥（回车默认） ...: 1

$ npm run dev            # 密钥已在环境里，正常跑

# ---- 下次开工 ----
$ cd 我的项目            # 新开终端，cd 进来即自动注入，什么都不用敲
```

没有装终端集成的终端里，敲一个词 `keyfort` 也能进入注入环境（exit 返回）。

## 为什么是 keyfort

- **纯本地**——零账号、零服务、零网络请求，断网完整可用
- **代码零改动**——注入的是环境变量（操作系统父子进程继承），node / python / 任何语言通用
- **密码只输一次**——存进系统密码管理器（Windows 凭据管理器 / macOS 钥匙串 / Linux Secret Service），磁盘上不落明文
- **密钥隐藏在原地**——`DB_PASS` 的值变成 `<keyfort:DB_PASS>` 占位符（**文件可提交 git**），`PORT=3000` 留明文给框架照常读
- **可审计**——核心逻辑 3 个文件约 950 行，半小时能读完；依赖只有 `cryptography` 和 `keyring`

## 安装

```console
$ pip install keyfort          # 发布前：pip install git+https://github.com/aiPublicProject/keyfort.git
```

Python ≥ 3.9；Windows / macOS / Linux。

## 快速开始

```console
$ cd 你的项目
$ keyfort .env.local 你的密码
```

依次问你两件事：**加密范围**（全部，或在编辑器里只保留要加密的行——留下的就是选择，
怎么改行数都不影响）；**原文件的配置怎么处理**（从原文件隐藏密钥——值替换为
`<keyfort:同名>` 占位符，回车默认 / 你自己操作）。然后自动装终端集成、进入注入环境。

日常就三个动作：

```console
$ keyfort edit           # 弹编辑器改密钥，关闭自动重新加密（需输密码）
$ keyfort set KEY value  # 加一个密钥（免密码）
$ keyfort restore        # 一键还原回明文文件，删除 .keyfort 与缓存密码
```

跑完之后，电脑上多了什么：

| 位置 | 是什么 |
|---|---|
| 项目里的 `.keyfort` | 密文文件（自动加进 `.gitignore`） |
| 项目里的 `.env.local` | 密钥值替换为 `<keyfort:名>` 占位符，其余原样——**可以提交 git** |
| `C:\Users\你\.keyfort\`（macOS/Linux：`~/.keyfort/`） | cmd 自动激活用的小脚本，`keyfort uninit` 删掉 |
| 系统密码管理器 | 加密密码，**不是文件** |

## 命令

| 命令 | 作用 |
|---|---|
| `keyfort .env.local 密码` | 加密登记：选范围 → 拆分加密 → 装终端集成 → 进入注入环境 |
| `keyfort` | 进入注入环境（装了终端集成的终端里 = 就地激活，无需 exit） |
| `keyfort edit` | 用系统默认编辑器编辑密钥（需密码，关闭后自动重新加密） |
| `keyfort set KEY value` | 设置/更新一个密钥（免密码） |
| `keyfort unset KEY` | 删除一个密钥 |
| `keyfort print KEY` | 查看单个密钥的值（需密码） |
| `keyfort list` | 列出密钥名（不显示值） |
| `keyfort passwd` | 更换加密密码 |
| `keyfort run <命令>` | 以注入环境执行单条命令（脚本/CI 用；CI 里配 `KEYFORT_PASSWORD` 免交互） |
| `keyfort restore` | 明文还原：密钥合回 env 文件，删除 `.keyfort` 与缓存密码 |
| `keyfort init` / `uninit` | 安装 / 移除终端集成（幂等，可完整摘除） |

终端集成装的是：PowerShell 5.1/7 的 profile、bash 的 `.bashrc`、cmd 的 AutoRun 各一小段
带标记的脚本。PowerShell 若因执行策略 Restricted 不生效：
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`。

## 工作原理

**加密**。`.keyfort` 存的是你选中那几行 `KEY=VALUE` 文本的密文：

```
KEYFORT1
<base64(salt 16字节 + nonce 12字节 + AES-256-GCM 密文)>
```

密钥由密码经 PBKDF2-HMAC-SHA256（20 万次迭代）派生，盐每次随机；AES-256-GCM 带认证，
文件被篡改会解密失败而不是解出假值。存储的只是原始字节，`KEY=VALUE` 的解析只发生在
注入那一刻。

**占位符**。登记时原文件里被选密钥的值替换为 `<keyfort:同名>`——文件只剩
占位符与普通变量，**可以提交 git**（配置可见，值不可见）。注入时真实值以同名
环境变量先就位，dotenv 家族默认不覆盖已存在的环境变量，所以占位符永远不会被
应用读到。

**注入**。环境变量是操作系统"父进程传子进程"的机制——`keyfort` 解密后派生子 shell，
把变量放进它的环境块，所以任何语言都拿得到。终端集成是另一条路：shell 函数调用
`keyfort activate --emit` 拿到一段赋值脚本，在**当前**会话里执行（shell 函数不是子进程，
改得了当前环境）；`KEYFORT_ACTIVE_KEYS` 标记防重复注入、供清除用。

**换电脑**：把 `.keyfort` 拷过去，输一次密码即可——密文与操作系统无关，无需重新加密。

## 安全

**为什么这些保证值得在意——两个真实发生的事故：**

- **2026 年 7 月，xAI 的 Grok Build 被曝静默上传用户代码库**：独立研究员逆向发现，
  这个 AI 编程工具会把用户完整的 Git 仓库与提交历史上传到云端，关掉隐私设置也拦不住；
  马斯克随后承诺删除数据并开源 Grok Build
- **2026 年 9 月，智谱 ZCode 被曝静默上传用户工作区**：登录即打包上传整个工作区
  （含 Git 提交历史与本地操作记录），界面上没有真正可用的关闭开关；智谱随后致歉
  并承诺开源、接受第三方审计

两起事故的共同点：用户都是靠**逆向**才知道工具在自己电脑上传了什么，而明文
`.env` 会跟着工作区一起上云。keyfort 的答案是双向的——`.keyfort` 里只有密文，
传走也不怕；且 keyfort 零网络请求、代码开源，不需要逆向就能知道它做了什么。

**它保证的**：

- 无任何网络请求：代码不 import 任何网络模块，不联网、不注册、不收集数据
- 开源可审（MIT）：核心逻辑 cli.py 522 + shells.py 331 + store.py 101 行
- 明文只出现在两处：终端会话、`keyfort edit` 的临时文件（关闭即删）

**它不防的（如实）**：

- 同账户恶意软件能读到你注入的环境变量和凭据库——与 1Password CLI、sops、ssh-agent
  一致；keyfort 防的是"密钥文件被提交到 git / 被拷走"
- 密码丢失即数据丢失——没有后门，请把密码和 `.keyfort` 一起备份
- `git add -f` 强推——`.gitignore` 只防误提交，防不了故意绕过

## 开发

```console
$ git clone https://github.com/aiPublicProject/keyfort.git
$ cd keyfort && pip install -e .
$ python tests/cli_flow.py      # 全流程测试，应全部 PASS
$ python -m build               # 构建到 dist/
```

规划中的功能与设计取舍（占位符模型、代理模式、明确不做的清单）见
[ROADMAP.md](ROADMAP.md)。

## 许可证

MIT © aiPublicProject
