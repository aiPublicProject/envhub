"""shell 集成：init / uninit / activate --emit / deactivate --emit。

init 向检测到的 shell 写入带标记的集成块（幂等，uninit 完整摘除）：
  - PowerShell 5.1 / 7：profile.ps1 里的 keyfort 函数 + 进入项目目录自动激活
  - bash（Git Bash / WSL / Linux / macOS）：.bashrc 里的 keyfort 函数 + 自动激活
  - cmd：HKCU AutoRun 挂 keyfort-cmd.bat（向上探测 .keyfort，仅交互式窗口激活）

函数语义：裸 `keyfort` / `activate` / `deactivate` 就地改当前会话环境
（--emit 发射脚本，由函数 eval）；其余子命令原样透传给 keyfort 可执行文件。
KEYFORT_HOME 重定向全部落盘位置（测试隔离，绝不碰真实 profile/注册表）。
"""
import os
import pathlib
import re
import shutil

MARK_BEGIN = "# >>> keyfort init >>>"
MARK_END = "# <<< keyfort init <<<"
CMD_HOOK_NAME = "keyfort-cmd.bat"
AUTORUN_KEY = r"Software\Microsoft\Command Processor"


# ---------------------------------------------------------------- 落盘位置
def _home() -> pathlib.Path:
    if os.environ.get("KEYFORT_HOME"):
        return pathlib.Path(os.environ["KEYFORT_HOME"])
    return pathlib.Path.home()


def state_dir() -> pathlib.Path:
    return _home() / ".keyfort"


def _documents() -> pathlib.Path:
    """真实 Documents（OneDrive 重定向也拿得对）；KEYFORT_HOME 隔离时用假 home。"""
    if os.environ.get("KEYFORT_HOME"):
        return _home() / "Documents"
    if os.name == "nt":
        try:
            import winreg
            key = (r"Software\Microsoft\Windows\CurrentVersion"
                   r"\Explorer\User Shell Folders")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                raw, _ = winreg.QueryValueEx(k, "Personal")
                return pathlib.Path(os.path.expandvars(raw))
        except Exception:
            pass
    return pathlib.Path.home() / "Documents"


def ps_profiles() -> list:
    if os.name == "nt":
        doc = _documents()
        return [doc / "WindowsPowerShell" / "profile.ps1",   # 5.1
                doc / "PowerShell" / "profile.ps1"]          # 7
    return [_home() / ".config" / "powershell" / "profile.ps1"]


def bashrc() -> pathlib.Path:
    return _home() / ".bashrc"


# ---------------------------------------------------------------- 集成块
def ps_block() -> str:
    return MARK_BEGIN + """
function keyfort {
  if ($args.Count -eq 0 -or $args[0] -in @('activate','deactivate')) {
    $a = if ($args.Count -eq 0) { @('activate') } else { $args }
    $out = & keyfort.exe @($a + @('--emit','ps'))
    if ($LASTEXITCODE -eq 0 -and $out) { Invoke-Expression ($out -join "`n"); __keyfort_mark }
  } else {
    & keyfort.exe @args
  }
}
function __keyfort_find {
  $d = $PWD.Path
  while ($d -and -not (Test-Path (Join-Path $d '.keyfort') -PathType Leaf)) {
    $up = Split-Path $d
    if (-not $up -or $up -eq $d) { return $null }
    $d = $up
  }
  if ($d) { $d } else { $null }
}
function __keyfort_hook {
  $d = __keyfort_find
  if ("$d" -eq "$env:KEYFORT_DIR") { return }
  if ($env:KEYFORT_ACTIVE_KEYS) {
    foreach ($k in $env:KEYFORT_ACTIVE_KEYS.Split(',')) {
      if ($k) { Remove-Item Env:$k -ErrorAction SilentlyContinue }
    }
    Remove-Item Env:KEYFORT_ACTIVE_KEYS -ErrorAction SilentlyContinue
  }
  Remove-Item Env:KEYFORT_DIR -ErrorAction SilentlyContinue
  if (-not $d) { return }
  $out = & keyfort.exe activate --emit ps --quiet 2>$null
  if ($LASTEXITCODE -eq 0 -and $out) {
    Invoke-Expression ($out -join "`n")
    $env:KEYFORT_DIR = "$d"
  } else {
    Write-Host "keyfort: 本目录的密钥库未解锁——敲一次 keyfort 解锁后自动接管"
    $env:KEYFORT_DIR = "$d"
  }
}
function __keyfort_mark {
  $d = __keyfort_find
  if ($d) { $env:KEYFORT_DIR = "$d" }
}
if (-not $global:__keyfort_prompt_wrapped) {
  $global:__keyfort_prompt_wrapped = $true
  $global:__keyfort_orig_prompt = $function:prompt
  function global:prompt { __keyfort_hook; & $global:__keyfort_orig_prompt }
}
__keyfort_hook
""" + MARK_END + "\n"


def sh_block() -> str:
    return MARK_BEGIN + """
keyfort() {
  [ $# -eq 0 ] && set -- activate
  if [ "$1" = "activate" ] || [ "$1" = "deactivate" ]; then
    local out
    out=$(command keyfort "$@" --emit sh) || return
    [ -n "$out" ] && eval "$out" && __keyfort_mark
  else
    command keyfort "$@"
  fi
}
__keyfort_hook() {
  local d="$PWD" up
  while :; do
    [ -f "$d/.keyfort" ] && break
    up="${d%/*}"
    [ "$up" = "$d" ] && { d=""; break; }
    d="$up"
  done
  [ "$d" = "$KEYFORT_DIR" ] && return
  if [ -n "$KEYFORT_ACTIVE_KEYS" ]; then
    local old IFS=','
    for old in $KEYFORT_ACTIVE_KEYS; do unset "$old" 2>/dev/null; done
    unset KEYFORT_ACTIVE_KEYS
  fi
  KEYFORT_DIR=""
  [ -z "$d" ] && return
  local out
  if out=$(command keyfort activate --emit sh --quiet 2>/dev/null); then
    [ -n "$out" ] && eval "$out"
    KEYFORT_DIR="$d"
  else
    echo "keyfort: 本目录的密钥库未解锁——敲一次 keyfort 解锁后自动接管" >&2
    KEYFORT_DIR="$d"
  fi
}
__keyfort_mark() {
  local d="$PWD" up
  while :; do
    [ -f "$d/.keyfort" ] && { KEYFORT_DIR="$d"; return; }
    up="${d%/*}"
    [ "$up" = "$d" ] && return
    d="$up"
  done
}
case ";$PROMPT_COMMAND;" in
  *";__keyfort_hook;"*) ;;
  *) PROMPT_COMMAND="__keyfort_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
__keyfort_hook
""" + MARK_END + "\n"


def _cmd_hook_bat() -> str:
    """AutoRun 钩子：纯 ASCII，向上探测 .keyfort，交互式窗口才激活。"""
    lines = [
        "@echo off",
        "rem keyfort auto-activation; remove with: keyfort uninit",
        "if defined KEYFORT_ACTIVE_KEYS goto :eof",
        'if not "%cmdcmdline%"=="" echo(%cmdcmdline%| findstr /i /c:" /c" >nul && goto :eof',
        'set "d=%CD%"',
        ":walk",
        'if not exist "%d%\\.keyfort\\*" if exist "%d%\\.keyfort" goto activate',
        'for %%i in ("%d%\\..") do set "up=%%~fi"',
        'if "%up%"=="%d%" goto :eof',
        'set "d=%up%"',
        "goto walk",
        ":activate",
        'set "eh_tmp=%TEMP%\\keyfort-cmd-%RANDOM%%RANDOM%.bat"',
        'keyfort.exe activate --quiet --emit cmd > "%eh_tmp%" 2>nul',
        'if not errorlevel 1 call "%eh_tmp%"',
        'del "%eh_tmp%" 2>nul',
        "goto :eof",
    ]
    return "\r\n".join(lines) + "\r\n"


# ---------------------------------------------------------------- profile 读写
def _read_profile(path: pathlib.Path):
    """PS profile 可能是 BOM-UTF8 / ANSI(GBK)，按能读的编码读，写回同编码。"""
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "mbcs", "gbk"):
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8"


def _ensure_block(path: pathlib.Path, block: str, encoding: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw, enc = _read_profile(path)
        if MARK_BEGIN in raw:
            return False                                   # 幂等
        sep = "" if raw.endswith("\n") else "\n"
        path.write_text(raw + sep + block + "\n", encoding=enc)
        return True
    path.write_text(block + "\n", encoding=encoding)
    return True


def _remove_block(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    raw, enc = _read_profile(path)
    i, j = raw.find(MARK_BEGIN), raw.find(MARK_END)
    if i == -1 or j == -1:
        return False
    cleaned = raw[:i] + raw[j + len(MARK_END):].lstrip("\n")
    if cleaned.strip():
        path.write_text(cleaned, encoding=enc)
    else:
        path.unlink()                       # 整个文件只有我们的块 → 删文件
    return True


# ---------------------------------------------------------------- cmd AutoRun
def _autorun_file() -> pathlib.Path:
    return state_dir() / "autorun.txt"


def _cmd_autorun_read() -> str:
    if os.environ.get("KEYFORT_HOME"):       # 测试隔离：用文件模拟注册表
        f = _autorun_file()
        return f.read_text(encoding="utf-8") if f.exists() else ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY) as k:
            v, _ = winreg.QueryValueEx(k, "AutoRun")
            return v or ""
    except OSError:
        return ""


def _cmd_autorun_write(value: str) -> None:
    if os.environ.get("KEYFORT_HOME"):
        f = _autorun_file()
        if value:
            f.write_text(value, encoding="utf-8")
        elif f.exists():
            f.unlink()
        return
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
        if value:
            winreg.SetValueEx(k, "AutoRun", 0, winreg.REG_SZ, value)
        else:
            try:
                winreg.DeleteValue(k, "AutoRun")
            except FileNotFoundError:
                pass


def _cmd_hook_path() -> pathlib.Path:
    return state_dir() / CMD_HOOK_NAME


def _cmd_init() -> list:
    state_dir().mkdir(parents=True, exist_ok=True)
    hook = _cmd_hook_path()
    hook.write_bytes(_cmd_hook_bat().encode("ascii"))
    cur = _cmd_autorun_read()
    call = f'if exist "{hook}" call "{hook}"'
    if call in cur:
        return []                                        # 幂等（只刷新 bat）
    new = (cur + " & " + call).strip(" &") if cur else call
    _cmd_autorun_write(new)                              # 保留用户已有的 AutoRun
    return [f"cmd AutoRun + {hook}"]


def _cmd_uninit() -> list:
    out = []
    cur = _cmd_autorun_read()
    hook = _cmd_hook_path()
    call = f'if exist "{hook}" call "{hook}"'
    if call in cur:
        parts = [x.strip() for x in cur.split("&") if x.strip()]
        kept = [x for x in parts if call not in x]
        _cmd_autorun_write(" & ".join(kept))
        out.append("cmd AutoRun")
    if hook.exists():
        hook.unlink()
        out.append(str(hook))
    try:
        state_dir().rmdir()          # 空了就整个删掉，不留残目录
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- init / uninit
def init_all() -> list:
    out = []
    if os.name == "nt" or shutil.which("pwsh"):
        for prof in ps_profiles():
            if _ensure_block(prof, ps_block(), "utf-8-sig"):
                out.append(str(prof))
    if shutil.which("bash"):
        if _ensure_block(bashrc(), sh_block(), "utf-8"):
            out.append(str(bashrc()))
    if os.name == "nt":
        out += _cmd_init()
    return out


def uninit_all() -> list:
    out = []
    for prof in ps_profiles():
        if _remove_block(prof):
            out.append(str(prof))
    if _remove_block(bashrc()):
        out.append(str(bashrc()))
    if os.name == "nt":
        out += _cmd_uninit()
    return out


# ---------------------------------------------------------------- emit 脚本
def _ps_quote(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def _sh_quote(v: str) -> str:
    return "'" + v.replace("'", "'\\''") + "'"


_KEY_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def activate_script(fmt: str, vars: dict, quiet: bool) -> str:
    """生成把 vars 注入当前会话的脚本（ps / sh / cmd）。
    非法密钥名直接跳过（防线：入口已校验，这里防历史脏数据生成可注入语句）。"""
    vars = {k: v for k, v in vars.items() if _KEY_OK.match(k)}
    keys = ",".join(vars)
    lines = []
    if fmt == "ps":
        for k, v in vars.items():
            lines.append(f"$env:{k}={_ps_quote(v)}")
        lines.append(f"$env:KEYFORT_ACTIVE_KEYS={_ps_quote(keys)}")
        if not quiet:
            lines.append(f"Write-Host 'keyfort: 已注入 {len(vars)} 个变量'")
    elif fmt == "sh":
        for k, v in vars.items():
            lines.append(f"export {k}={_sh_quote(v)}")
        lines.append(f"export KEYFORT_ACTIVE_KEYS={_sh_quote(keys)}")
        if not quiet:                       # 提示语 ASCII：经 $() 捕获再 eval 不乱码
            lines.append("echo '[keyfort] %d vars injected'" % len(vars))
    else:                                               # cmd
        for k, v in vars.items():
            lines.append(f'set "{k}={v}"')
        lines.append(f'set "KEYFORT_ACTIVE_KEYS={keys}"')
        if not quiet:
            lines.append(f"echo [keyfort] {len(vars)} vars injected")
    return "\n".join(lines)


def deactivate_script(fmt: str, keys: list, quiet: bool) -> str:
    """生成清除注入变量的脚本；keys 来自 KEYFORT_ACTIVE_KEYS 标记。"""
    keys = [k for k in keys if _KEY_OK.match(k)]
    all_keys = list(keys) + ["KEYFORT_ACTIVE_KEYS", "KEYFORT_DIR"]
    lines = []
    if fmt == "ps":
        for k in all_keys:
            lines.append(f"Remove-Item Env:{k} -ErrorAction SilentlyContinue")
        if not quiet:
            lines.append("Write-Host 'keyfort: 已退出注入环境'")
    elif fmt == "sh":
        lines.append("unset " + " ".join(all_keys))
        if not quiet:
            lines.append("echo '[keyfort] deactivated'")
    else:                                               # cmd
        for k in all_keys:
            lines.append(f'set "{k}="')
        if not quiet:
            lines.append("echo [keyfort] deactivated")
    return "\n".join(lines)
