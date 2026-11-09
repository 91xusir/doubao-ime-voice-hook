# AGENT.md — 豆包输入法语音输入触发逆向

> 给下一次接手的 agent 看。目标：让你**不必从零逆向**，5–10 分钟内完成升级后的重新打补丁。
> 若只需日常维护，读 §1 §2 §5 即可；要重定位补丁点，读 §3 §4。

---

## 1. 任务是什么

豆包输入法（DoubaoIME）的语音输入只响应物理按键。原因是 `ImeService.exe` 的底层键盘钩子
（`WH_KEYBOARD_LL`）检查 `KBDLLHOOKSTRUCT.flags & LLKHF_INJECTED (0x10)`，
凡 `SendInput` 等软件方式产生的按键都会被过滤。

**做法**：patch `ImeService.exe`，消除 4 处注入判定，让注入事件走与物理键相同的路径。

**为什么必须重新签名**：该进程提权运行，Windows 校验 Authenticode 签名，
改动后原签名失效 → 提权失败 → 服务起不来。

---

## 2. 当前状态（截至 2026-11-09）

| 项目 | 值 |
|---|---|
| 目标版本 | `v1.0.0.23` |
| 安装路径 | `C:\Program Files\DoubaoIME\versions\v1.0.0.23\ImeService.exe` |
| 原始大小 | 32,857,488 字节 |
| 补丁后大小 | 32,847,144 字节（证书表被替换，体积变小） |
| 原始 PE 时间戳 | `0x6AE856B7`（识别版本的依据） |
| 补丁后签名 | `Valid`，签名者 `CN=Local Doubao IME Code Signing` |
| 运行身份 | 用户账户（非 SYSTEM），会话 1，有进程保护 |

> ⚠️ 该进程启用了自我保护：`OpenProcess(VM_READ|VM_WRITE)` 被拒绝。
> **不要尝试跨进程注入或调试附加**，改文件前先结束进程。

---

## 3. 关键结构（必读）

### 3.1 地址换算

```
ImageBase = 0x140000000
.text: RVA 0x1000,  PointerToRawData 0x400
VA = 0x140000000 + 0x1000 + (FileOffset - 0x400)
FileOffset = VA - 0x140000000 - 0x1000 + 0x400
```

### 3.2 钩子函数

```
VoiceKeyHookProc（IDA 显示为 sub_1407DDD90）
  函数入口        0x1407DDD90   (FileOffset 0x7DD190, prolog: 4c 8b dc 53 56 57 41 54 = mov r11,rsp / push...)
  函数范围        0x1407DDD90 – 0x1407DF2A7
  签名            LRESULT (DWORD code, WPARAM wParam, unsigned int* lParam)
```

> 别把 `0x1407DE550` 当成函数入口——它只是函数中部（加载日志对象的位置）。
> 早期分析文档里出现的这个地址有误导性，以 `0x1407DDD90` 为准。

`lParam` 是 `KBDLLHOOKSTRUCT`：
`lParam[0]=vkCode, lParam[1]=scanCode, lParam[2]=flags, lParam[3]=time, lParam[4]=dwExtraInfo`

定位线索（**比地址更稳定，优先用这些**）：
- 源文件路径串：`C:\Workfolder\oime\obric-ime5\src\server\server_main.cpp`
- 函数名串：`` `anonymous-namespace'::VoiceKeyHookProc ``
- 日志标签：`[VHK][LLRaw]`、`[VHK][bypass]`、`[SysChEnHotkey]`、`"injected"`

---

## 4. 四个补丁点（本版本）

注入标志先从 `flags` 算出，再由后续分支使用。改写后语义：注入标志恒为 0，所有分支都按物理键处理。

| # | VA | FileOff | 原始字节 | 补丁字节 | 语义 |
|---|---|---|---|---|---|
| 1 | `0x1407DE5B5` | `0x7DD9B5` | `45 8b 75 00 41 c1 ee 04` | `45 31 f6` + `90`×5 | `r14d = (flags>>4)&1` → `xor r14d,r14d` |
| 2 | `0x1407DE576` | `0x7DD976` | `0f 85 16 0c 00 00` | `90`×6 | `jnz → CallNextHookEx` 改成 `nop`，不再提前跳过 |
| 3 | `0x1407DE62E` | `0x7DDA2E` | `45 84 f6 75 2f` | `eb 32` + `90`×3 | `test r14b,r14b/jnz` → 恒跳转 |
| 4 | `0x1407DEC11` | `0x7DE011` | `a8 10 74 29` | `eb 2b` + `90`×2 | 注入检测 `jz` → 恒跳转 |

> 补丁点 2 的 `test r14d,r14d` 位于 `0x1407DE573`（3 字节），`jnz` 从 `0x1407DE576` 开始。

**注意指令长度**（最容易踩的坑）：
- #2：`test r14d,r14d`（3 字节）**保留不动**，只替换其后 6 字节的 `jnz`。
- #3：整条是 **5 字节**（`test` 3 + `jne rel8` 2）。只写 4 字节会在 `0x7DDA32` 留下孤立的 `2f`，后续指令流整个错位。

**跳转目标**（重定位时按新地址重算，不要照抄字节）：
```
#3 → 0x1407DE662   (rel8 从指令自身起点算：target - (0x1407DE62E + 2))
#4 → 0x1407DEC3E
```
> 反汇编器里看到 `jne 0x1407DE662` 时，别把目标记成 `0x...661`——那是按指令**末尾**算的，会差 1 字节。

---

## 5. 升级后如何重定位

### 5.1 唯一锚点

**`45 8b 75 00 41 c1 ee 04 41 80 e6 01`**（`mov r14d,[rsi+8]` + `shr r14d,4` + `and r14b,1`）

经核验，这条序列在原始文件中 **全文唯一**（命中 1 次）。其余三个特征码都不唯一：

| 特征码 | 全文命中次数 |
|---|---|
| `45 8b 75 00 41 c1 ee 04` | **1** ← 用这个 |
| `45 85 f6 0f 85` (test r14d/jnz) | 25 |
| `45 84 f6 75` (test r14b/jnz) | 75 |
| `a8 10 74` (test al,10h/jz) | 53 |

### 5.2 重定位步骤

> ⚠️ **方向很重要**：补丁点 2 在锚点**之前**，补丁点 3、4 在锚点**之后**。
> 本版本布局：`P2(0x7DD973) → 锚点(0x7DD9B5) → P3(0x7DDA2E) → P4(0x7DE011)`

1. 用锚点定位 → 得到 `A`（补丁点 1，`mov r14d,[rsi+8]/shr r14d,4/and r14b,1` 的起点）。
2. **向前**找**最后一个** `45 85 f6 0f 85`（`test r14d,r14d` / `jnz rel32`）→ 补丁点 2。
   - 本版本它是 `0x7DD973`，即 `A` 之前最近的命中。
   - 验证：该 `jnz` 目标应指向钩子出口 `mov edx,r14d` + `call CallNextHookEx` 处（本版本 `0x1407DF192`）。
3. **向后**找**第一个** `45 84 f6 75` → 补丁点 3（本版本 `0x7DDA2E`）。
   - 验证：其 `jne` 目标块里有 `mov r15d, cs:TlsIndex`（本版本 `0x1407DE662`）。
4. **向后**找**第一个** `a8 10 74` → 补丁点 4（本版本 `0x7DE011`）。
   - 验证：命中后的 `je` 目标块是 `call sub_1407DDAD0` 开头的正常处理路径。
5. 按新地址重算 `rel8`，更新 `apply_patch.py` 的 `PATCHES` 表。
6. 跑 `python apply_patch.py --verify` —— 逐点字节校验，不匹配会中止，不会写出坏文件。

### 5.3 升级后检查清单

- [ ] 锚点仍唯一？若命中 >1，说明编译器变了，需要手工回 IDA 确认
- [ ] 寄存器是否仍是 `r14`？（`xor r14d,r14d` 依赖它）
- [ ] `TEXT_RAW` 是否仍是 `0x400`？（节表布局变了要改）
- [ ] 安装目录版本号变了 → `sign-imeservice.ps1` 已能自动探测最新版本目录；若目录结构不同，用 `-Exe <路径>` 手动指定

---

## 6. 打补丁 + 签名流程

```powershell
# 1) 备份新版本并置为输入
copy "C:\Program Files\DoubaoIME\versions\<new>\ImeService.exe" .\ImeService-org.exe

# 2) 生成（会逐点校验原始字节）
python apply_patch.py

# 3) 复制到安装目录（管理员）
#    注意：若 ImeService 正在运行，文件被锁定，先结束进程
copy .\ImeService-patch-v2.exe "C:\Program Files\DoubaoIME\versions\<new>\ImeService.exe"

# 4) 签名（管理员，自动建证书+导入信任链+备份）
#    默认自动选安装目录下版本号最高的 ImeService.exe
powershell -ExecutionPolicy Bypass -File .\sign-imeservice.ps1
#    或手动指定：
#    powershell -ExecutionPolicy Bypass -File .\sign-imeservice.ps1 -Exe "C:\...\ImeService.exe"
```

### 6.1 PE CheckSum 计算要点

算法：对**整个文件**按 16-bit 小端累加（CheckSum 字段按 0 计），每 word 折叠进位，最后加文件长度。

校验方法：用该算法复算**未修改的原始文件**，必须精确等于 `0x01F5D384`。对不上就是实现错了。

> PowerShell 陷阱：字面量 `0xFFFFFFFF` 是 `Int32` 的 `-1`，与 `UInt64` 做 `-band` 会退化成无掩码。
> 必须写 `[uint64]0x00000000FFFFFFFF`。

### 6.2 签名要点

- `sign-imeservice.ps1` 存盘必须是 **UTF-8 with BOM**，否则 PowerShell 5.1 按 ANSI 解析中文串会语法报错。
- `New-SelfSignedCertificate -Type CodeSigningCert` 在部分系统上**写不出 EKU**，`signtool` 会报
  "No certificates were found"。改用：
  ```powershell
  New-SelfSignedCertificate -Type Custom -Subject "CN=Local Doubao IME Code Signing" `
    -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
  ```
- PE CheckSum 字段**不在**签名哈希范围内，所以签名后修校验和不会破坏签名。
- 修改 `Program Files` 下的文件前必须先结束 `ImeService.exe`，否则 `PermissionError`。

### 6.3 验证

```powershell
$dst = "C:\Program Files\DoubaoIME\versions\<new>\ImeService.exe"
(Get-AuthenticodeSignature $dst).Status       # 期望 Valid
```
再用 `capstone` 对钩子函数做线性反汇编，确认原始版与补丁版**解码到同一结束地址**
（说明没有破坏指令边界）。本版本的参考值：原始 1041 条指令、补丁 1053 条，均结束于 `0x1407DF1D1`。

---

## 7. 已否决的方案（不要重走）

### 7.1 RPC 直调 —— 试过，**不通**

已完成逆向的部分（信息真实，可复用）：

| 项目 | 值 |
|---|---|
| 管道 | `\\.\pipe\ObricIme\oime-server`（外部进程可打开，读写模式 OK） |
| 客户端 DLL | `doubaoime-rpc-new.dll`（474 导出 / 48 命名） |
| 关键导出 | `CreateRpcClient`, `RpcPipe_SimpleMessage`, `RpcPipe_EnsureServerRunning`, `RpcPipe_FocusIn`, `RpcPipe_RegisterTsfNotifySink` |
| 服务端分发函数 | `slot_SimpleMessage` = **`0x14088F790`**（23637 字节，`switch(a2)`，3790 行反编译） |
| └ 函数名字符串 | `0x1415E5CB0`（用它的 xref 可反查到上面那个函数，别把两者搞混） |
| 语音启动命令 | **`0x3F4`**（`a3==1` → `single_click`，否则 `long_click`） |
| 标点恢复命令 | `0x3F7` |

`RpcPipe_SimpleMessage` 真实原型（x64 fastcall）：
```
int RpcPipe_SimpleMessage(const char* pipeName, uint32 cmd, uint32 a3, uint32 a4, void* out)
//   rcx=管道名(可为NULL)  rdx=命令码  r8d=a3  r9d=a4  [rsp+20]=输出缓冲
```

**失败原因**（关键，别重复踩）：
1. **返回值不可信**。`rc=0` 只表示"写进管道没报错"——连非法命令 `0xFFFF` 也返回 0。
2. 用非法命令发 20 条，`ImeService` CPU 增量 **0 ms**，证明服务端**根本没处理**。
3. 缺会话上下文。TSF 的调用链是 `FocusIn → RegisterTsfNotifySink → UpdateHostContextUtf8 → SimpleMessage`，
   直接发 `0x3F4` 会因 `session_null` 被丢弃。
4. 还有 `our ime not active (global voice off)` 这类前置校验，依赖**真实焦点状态**，外部伪造困难。

结论：要跑通还需逆向 `FocusIn`/`RegisterTsfNotifySink` 的私有结构 + 维持长连接 +
`PeekVoiceCommit` 轮询 + `AckVoiceCommit`，成本远高于 patch，且未必成功。

测试脚本保留在 `rpc_min_test.py` / `rpc_probe.py` / `dis_rpc.py`。

### 7.2 Hook SendInput / SetWindowsHookEx 注入 —— 不可行

- `LLKHF_INJECTED` 由**内核**在消息投递路径上置位，用户态无法伪造。
- 目标进程有自我保护，`OpenProcess(VM_WRITE)` 被拒，注入类方案全部走不通。

### 7.3 Interception 驱动 —— 未实施（备选）

若将来不想每次升级重打补丁，可考虑在驱动层注入键盘事件（如 Interception），
产生的 `flags` 天然不带 `INJECTED`，与物理键完全等价。
好处：**完全不用碰 `ImeService.exe`，升级无关**。代价：需装驱动。

---

## 8. 文件清单

| 文件 | 说明 |
|---|---|
| `apply_patch.py` | 补丁生成器，含逐点字节校验。`--verify` 只校验不落盘 |
| `ImeService-org.exe` | 原始文件（厂商签名 `Valid`），回滚用 |
| `ImeService-patch-v2.exe` | 补丁输出（未签名） |
| `sign-imeservice.ps1` | 签名 + 验证 + 安装证书信任链 |
| `remove-cert.ps1` | 卸载自签名证书 |
| `report.md` | 完整逆向报告（给人看） |
| `fn5399.c` | `VoiceKeyHookProc` 的 Hex-Rays 反编译 |
| `slot_simplemsg.c` | `slot_SimpleMessage` 反编译（RPC 研究遗留） |
| `rpc_client.c` | `ServerRpcThread` 反编译（RPC 研究遗留） |
| `ImeService-org.exe.i64` | IDA 数据库（直接打开可续用分析） |

**回滚**：把 `ImeService-org.exe` 覆盖回安装目录即可，厂商签名仍有效。

---

## 9. 环境备忘

- IDA Pro 9.5，MCP 服务 `ida-*`（`open_database` → `execute_python`）
- `capstone` 用于独立验证反汇编：`uv run --with capstone python ...`
- 反编译大函数（如 `slot_SimpleMessage` 3790 行）先存成 `.c` 文件再用 grep 查，别直接灌进上下文
- `ImeService` 的日志在 `%APPDATA%\DoubaoIme\log\alog\`，是二进制格式，**外部解析不出可读文本**，
  排查行为优先用"CPU 增量 / 窗口快照 / 进程状态"这类外部可观测信号
