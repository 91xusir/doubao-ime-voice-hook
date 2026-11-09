# doubao-ime-voice-hook

豆包输入法（DoubaoIME）语音输入触发绕过 —— 让软件映射的快捷键也能唤起语音输入。

## 🚨 版本限定（最重要）

**本仓库的补丁脚本只适用于 `ImeService.exe` 版本 1.0.0.23。**

`apply_patch.py` 里的偏移和字节是按这个版本写死的。换到其它版本，脚本会在校验阶段直接报错中止（不会误改），此时必须按 `AGENT.md` §5 重新定位。

### 如何确认你的版本

**方法一：看目录名**

```
C:\Program Files\DoubaoIME\versions\v1.0.0.23\ImeService.exe
                                    ^^^^^^^^^^ 必须是这个
```

**方法二：看 PE 时间戳（最可靠）**

```powershell
python -c "import struct;d=open(r'C:\Program Files\DoubaoIME\versions\v1.0.0.23\ImeService.exe','rb').read();pe=struct.unpack_from('<I',d,0x3c)[0];print('0x%08X'%struct.unpack_from('<I',d,pe+8)[0])"
```

| 文件 | PE TimeDateStamp |
|---|---|
| ✅ 匹配本仓库的版本 | **`0x6AE856B7`** |
| 你本机的值不等于上面 → | **不匹配，脚本会失败** |

**方法三：看文件大小**

| 状态 | 大小（字节） |
|---|---|
| 厂商原始文件 | `32,857,488` |
| 打过补丁后（本仓库） | `32,847,144` |

> 其它版本即使目录名碰巧相同，只要 PE 时间戳或大小对不上，就不要用本仓库的偏移。

## ⚠️ 先读这句

**请不要自己阅读 `AGENT.md` 里的逆向细节然后动手改。**

直接把你用的 AI agent（Claude Code / Codex / Cursor 等）指向这个仓库，让它读 `AGENT.md` 并替你完成分析和打补丁。原因：

- 补丁偏移与具体版本强绑定，人肉对照容易改错；
- 改错字节会破坏指令边界，程序直接起不来；
- 改完必须重新签名，否则提权失败。

给 agent 的话术：

```
读一下这个仓库的 AGENT.md，按里面的说明帮我处理 DoubaoIME 的语音快捷键问题。
先确认当前版本是不是 1.0.0.23（核对 PE TimeDateStamp = 0x6AE856B7）。
如果匹配就直接打补丁；不匹配就按 AGENT.md §5 的锚点重新定位后再改。
```

## 背景

输入法在底层键盘钩子里检查 `LLKHF_INJECTED` 标记，把软件模拟的按键全部过滤掉了。
`apply_patch.py` 负责把 `ImeService.exe` 里 4 处注入判定改掉，`sign-imeservice.ps1` 负责重新签名。

## 文件

| 文件 | 作用 |
|---|---|
| `AGENT.md` | **给 agent 看的完整说明书**（含重定位算法、踩坑记录、已否决方案） |
| `apply_patch.py` | 补丁生成器，逐点字节校验，不匹配就中止 |
| `sign-imeservice.ps1` | 签名 + 验证 + 导入证书信任链 |
| `remove-cert.ps1` | 卸载自签名证书 |

## 你需要自己准备

`ImeService.exe` 原版文件（从你本机的豆包输入法安装目录复制），仓库不提供。

改动前请备份。出问题用备份覆盖回去即可，厂商原有签名仍然有效。
