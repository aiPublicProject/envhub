"""keyfort：最简单的密钥环境管理。

一行命令加密登记；一个词进入注入环境；装了终端集成后连一个词都不用敲
（进入项目目录自动注入）；编辑/修改/查看/还原各一条命令。
密码存 keyring（OS 凭据库，按账户加密）；环境注入 = 派生 shell 时
把解密出的变量放进它的环境块（操作系统父子继承，语言无关）。
"""
import argparse
import getpass
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import time

from . import shells, store

AUTH_SERVICE = "keyfort"

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _value_problem(v: str):
    """dotenv 语义下无法原样往返的值（存进去再读出来会变样）。"""
    if "\n" in v or "\r" in v:
        return "包含换行"
    if v != v.strip():
        return "首尾有空格"
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return "被引号包裹（读取时会被剥掉引号）"
    return None


def _vars_problems(vars: dict) -> str:
    ps = []
    for k, v in vars.items():
        if not _KEY_RE.fullmatch(k):
            ps.append(f"非法密钥名 {k}")
        p = _value_problem(v)
        if p:
            ps.append(f"{k} 的值{p}")
    return "；".join(ps)


# ---------------------------------------------------------------- keyring 包装
def _kr_get(username: str):
    try:
        import keyring
        return keyring.get_password(AUTH_SERVICE, username)
    except Exception:
        return None


def _kr_set(username: str, pw: str) -> bool:
    try:
        import keyring
        keyring.set_password(AUTH_SERVICE, username, pw)
        return True
    except Exception:
        return False


def _kr_delete(username: str) -> bool:
    try:
        import keyring
        keyring.delete_password(AUTH_SERVICE, username)
        return True
    except Exception:
        return False


def _cached_pw(root: str):
    """缓存密码：keyring 优先，KEYFORT_PASSWORD（CI/无人值守）兜底。"""
    return _kr_get(root) or os.environ.get("KEYFORT_PASSWORD")


# ---------------------------------------------------------------- 核心动作
def _resolve_file(file_arg=None):
    """定位加密文件：显式参数 / 向上查找。一律返回绝对路径
    （keyring 的 username = 项目根路径，必须与查找时的绝对路径一致）。"""
    if file_arg:
        p = pathlib.Path(file_arg).resolve()
        if p.is_file():
            return p
        cand = p / store.FILENAME
        if cand.is_file():
            return cand
        sys.exit(f"找不到加密文件：{file_arg}")
    enc = store.find()
    if enc is None:
        sys.exit("本目录及上级没有 .keyfort 加密文件。\n"
                 "先把明文 env 文件加密：keyfort .env.local 你的密码")
    return enc


def _read_password(prompt="文件密码: "):
    pw = os.environ.get("KEYFORT_PASSWORD")
    if pw:          # 无人值守：调用方已持有密码（该变量本身就是密码），不再询问
        return pw
    return getpass.getpass(prompt)


def _read_text_tol(path: pathlib.Path) -> str:
    """按能读的编码读（utf-8 / gbk），编辑器存成 ANSI 也不炸；
    UTF-16 明确拒绝（继续解析只会静默乱码入库）。"""
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        sys.exit(f"{path.name} 是 UTF-16 编码，keyfort 支持 UTF-8 / GBK："
                 "请用编辑器另存为 UTF-8 后重试")
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _ask(prompt: str, default: str = "1") -> str:
    try:
        raw = input(prompt).strip()
    except EOFError:
        raw = ""
    return raw or default


def _entries_from(data: bytes, pw: str, name: str) -> dict:
    try:
        return store.parse_env_text(
            store.decrypt_bytes(data, pw).decode("utf-8"))
    except store.NotKeyfortFile as e:
        sys.exit(f"{name} {e}")


def _decrypt_entries(enc: pathlib.Path, pw=None, allow_prompt=True):
    """返回 (vars: dict, pw: str)。取密顺序：显式传入 → KEYFORT_PASSWORD（CI，
    显式给错即快速失败）→ keyring（错且可交互则进入重输，成功即纠正缓存）
    → 交互询问（最多三次）。非交互且没有可用密码 → 明确退出。"""
    root = str(enc.parent)
    data = enc.read_bytes()
    if pw is not None:
        return _entries_from(data, pw, enc.name), pw
    env_pw = os.environ.get("KEYFORT_PASSWORD")
    if env_pw:
        try:
            vars = _entries_from(data, env_pw, enc.name)
            _kr_set(root, env_pw)               # 顺手治愈陈旧的 keyring 缓存
            return vars, env_pw
        except store.WrongPassword:
            sys.exit("KEYFORT_PASSWORD 与加密文件不匹配")
    cached = _kr_get(root)
    if cached:
        try:
            return _entries_from(data, cached, enc.name), cached
        except store.WrongPassword:
            if not allow_prompt:
                sys.exit("keyring 缓存的密码已失效（密码在别处被更换过）。\n"
                         "交互运行一次 keyfort 重输新密码即可更新缓存")
            print("缓存的密码不正确，请重新输入")
    if not allow_prompt:
        sys.exit("密码不可用（keyring 无记录且未设 KEYFORT_PASSWORD）。先运行 keyfort 解锁一次")
    for _ in range(3):
        pw = _read_password()
        try:
            vars = _entries_from(data, pw, enc.name)
            _kr_set(root, pw)
            return vars, pw
        except store.WrongPassword:
            print("密码不正确，再试一次")
    sys.exit("连续三次密码错误")


def _write_encrypted(enc: pathlib.Path, text: str, pw: str) -> None:
    enc.write_bytes(store.encrypt_bytes(text.encode("utf-8"), pw))


def _save_auth(root: pathlib.Path, pw: str) -> None:
    if not _kr_set(str(root), pw):
        print("⚠ keyring 不可用：本终端内已解锁，但密码未缓存"
              "（下次会话需要重新输入）")


def _detect_shell() -> list:
    if os.environ.get("SHELL"):
        return [os.environ["SHELL"]]
    if os.environ.get("PSMODULEPATH"):
        return ["powershell.exe", "-NoLogo"]
    return [os.environ.get("ComSpec") or "cmd.exe"]


def _spawn_injected(vars: dict) -> None:
    env = dict(os.environ)
    env.update(vars)
    env["KEYFORT_ACTIVE_KEYS"] = ",".join(vars)   # 子 shell 集成看到标记不再重复激活
    sh = _detect_shell()
    print(f"keyfort: 已进入注入环境（{len(vars)} 个变量，exit 返回）")
    sys.exit(subprocess.call(sh, env=env))


# ---------------------------------------------------------------- 子命令
def cmd_bare(args):
    enc = _resolve_file()
    vars, _ = _decrypt_entries(enc)
    _spawn_injected(vars)


def _detect_editor():
    """从环境识别宿主编辑器：VS Code 系集成终端会设置 TERM_PROGRAM。"""
    tp = (os.environ.get("TERM_PROGRAM") or "").lower()
    return {"vscode": "code", "cursor": "cursor",
            "windsurf": "windsurf"}.get(tp)


def _editor_base() -> str:
    if os.environ.get("EDITOR"):
        return os.environ["EDITOR"]
    return _detect_editor() or ("notepad" if os.name == "nt" else "vi")


def _split_editor(editor: str) -> list:
    """编辑器描述拆成 argv，支持带参数（如 "code --wait"）与带空格路径。"""
    try:
        toks = shlex.split(editor, posix=(os.name != "nt"))
    except ValueError:
        return [editor]
    return [t.strip('"') for t in toks] if os.name == "nt" else toks


_NEEDS_WAIT = {          # GUI 编辑器：不阻塞直到关闭就必须补 --wait
    "code", "code-insiders", "cursor", "windsurf", "subl",
    "idea", "pycharm", "webstorm", "goland", "clion", "rider",
}


def _editor_argv(editor: str) -> list:
    """拆 argv 并为已知 GUI 编辑器自动补 --wait（用户已写则不重复）。"""
    toks = _split_editor(editor)
    base = pathlib.Path(toks[0]).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base in _NEEDS_WAIT and "--wait" not in toks:
        toks.append("--wait")
    return toks


def _pick_by_editor(src: pathlib.Path, text: str):
    """弹出编辑器：只保留要加密的行，其余行删掉。
    返回 (用户留下的文本, 选中的变量)。不做前后差异对比——用户留下什么，
    什么就被加密；行怎么增删、顺序怎么调都不影响。"""
    fd, tmp = tempfile.mkstemp(prefix="keyfort-pick-",
                               suffix=src.suffix or ".env")
    os.close(fd)
    tmp = pathlib.Path(tmp)
    tmp.write_text(text, encoding="utf-8")
    print("已打开编辑器：只保留要加密的行，其余行删掉；保存并关闭后继续")
    print(f"（临时文件：{tmp}）")
    try:
        subprocess.call(_editor_argv(_editor_base()) + [str(tmp)])
    except FileNotFoundError:
        tmp.unlink()
        sys.exit(f"找不到编辑器：{_editor_base()}")
    kept = _read_text_tol(tmp)
    tmp.unlink()
    return kept, store.parse_env_text(kept)


def _hide_keys_in_text(text: str, keys: set) -> str:
    """把选中密钥的值原位替换为 <keyfort:同名> 占位符；行/注释/其余行原样保留
    （含每行的行尾风格），文件从此可提交 git。"""
    out = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        stripped = body.strip()
        k = (stripped.partition("=")[0].strip()
             if not stripped.startswith("#") and "=" in stripped else None)
        out.append(f"{k}=<keyfort:{k}>{line[len(body):]}" if k in keys else line)
    return "".join(out)


def _unhide_keys_in_text(text: str, vars: dict) -> str:
    """把 <keyfort:名> 占位符换回真实值（保留行尾风格）；
    库里有而文件没有的密钥追加到末尾。"""
    out, seen, last_eol = [], set(), "\n"
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body):]
        if eol:
            last_eol = eol
        stripped = body.strip()
        k, _, v = (stripped.partition("=") if "=" in stripped else ("", "", ""))
        v = v.strip()
        if (not stripped.startswith("#") and k.strip()
                and v.startswith("<keyfort:") and v.endswith(">")):
            name = v[len("<keyfort:"):-1]
            if name in vars:
                out.append(f"{name}={vars[name]}{eol}")
                seen.add(name)
                continue
        out.append(line)
    body_txt = "".join(out)
    missing = [k for k in vars if k not in seen]
    if missing:
        if body_txt and not body_txt.endswith(("\n", "\r")):
            body_txt += last_eol
        body_txt += "".join(f"{k}={vars[k]}{last_eol}" for k in missing)
    return body_txt


def cmd_create(args):
    """keyfort create [密码]：直接创建空密钥库——不需要已有明文文件，
    建库后用 set 添加 / edit 批量编辑。"""
    found = store.find()
    if found is not None:
        sys.exit(f"已有密钥库：{found}（直接 keyfort set 添加密钥）")
    pw = args.password or _read_password("加密密码: ")
    if len(pw) < 4:
        sys.exit("密码至少 4 位")
    root = pathlib.Path.cwd()
    enc = root / store.FILENAME
    enc.write_bytes(store.encrypt_bytes(b"", pw))
    _save_auth(root, pw)
    print(f"✓ 已创建空密钥库 {enc}")
    print("  keyfort set KEY value   添加密钥（免密码）")
    print("  keyfort edit            批量编辑（需密码）")
    print("  .env.local 里可写 KEY=<keyfort:KEY> 占位符（可选，框架需要时）")
    changed = shells.init_all()
    if changed:
        for c in changed:
            print(f"✓ 终端集成：{c}")
    print("✓ 新开终端进入本目录即自动注入（set 之后就有变量）")


def cmd_encrypt(args):
    """keyfort <明文文件> [密码]：选范围（全部/部分）→ 加密 → 进入注入环境。
    部分加密 = 编辑器里只保留要加密的行（不做差异对比，留下的就是选择）；
    原文件中被选密钥的值原位替换为 <keyfort:同名> 占位符——永不删除原文件，
    文件只剩占位符与普通变量，可提交 git。"""
    src = pathlib.Path(args.file).resolve()   # 绝对路径：keyring 按项目根路径存
    if not src.is_file():
        sys.exit(f"文件不存在：{src}")
    if src.name == store.FILENAME:
        return cmd_bare(args)
    existing = src.parent / store.FILENAME
    if existing.is_file():                    # 已有密钥库：拦截，防止静默覆盖丢密钥
        sys.exit(f"已存在密钥库 {existing}。要重新登记先 keyfort restore 还原，"
                 f"或确认不需要旧密钥后删除 {existing.name}")
    text = _read_text_tol(src)
    all_vars = store.parse_env_text(text)
    if not all_vars:
        sys.exit("没有解析出任何 KEY=VALUE 行")

    pw = args.password or _read_password("加密密码: ")
    if len(pw) < 4:
        sys.exit("密码至少 4 位")

    scope = _ask("加密范围？[1] 全部（回车默认） "
                 "[2] 部分（编辑器里只保留要加密的行）: ")
    if scope != "2":
        secret_vars = all_vars
        src.write_text(_hide_keys_in_text(text, set(all_vars)), encoding="utf-8")
        print(f"✓ 已隐藏全部 {len(all_vars)} 个密钥（值替换为占位符，原文件可提交 git）")
    else:
        kept_text, secret_vars = _pick_by_editor(src, text)
        if not secret_vars:
            sys.exit("编辑器里没有保留任何 KEY=VALUE 行，已取消")
        selected = set(secret_vars)
        print(f"✓ 已选中 {len(selected)} 个密钥：{'、'.join(sorted(selected))}")
        action = _ask(f"原文件 {src.name} 的配置怎么处理？"
                      "[1] 从原文件隐藏密钥（回车默认）"
                      " [2] 你自己操作: ")
        if action == "2":
            print(f"✓ {src.name} 未改动（明文密钥仍在，请自行处理）")
        else:
            src.write_text(_hide_keys_in_text(text, selected), encoding="utf-8")
            print(f"✓ 已在 {src.name} 隐藏 {len(selected)} 个密钥"
                  f"（值替换为 <keyfort:名> 占位符，文件可提交 git）")

    secret_text = store.dump_env_text(secret_vars)
    enc = src.parent / store.FILENAME
    enc.write_bytes(store.encrypt_bytes(secret_text.encode("utf-8"), pw))
    _save_auth(enc.parent, pw)
    print(f"✓ 密文已写入 {enc}")
    print("✓ 密文与占位符文件均可提交 git（团队 clone 即得）")

    changed = shells.init_all()
    if changed:
        for c in changed:
            print(f"✓ 终端集成：{c}")
        print("✓ 新开终端进入本目录即自动注入（keyfort uninit 可移除）")
    else:
        print("✓ 终端集成已就绪（新开终端进入本目录即自动注入）")

    vars, _ = _decrypt_entries(enc, pw=pw, allow_prompt=False)
    _spawn_injected(vars)


def cmd_edit(args):
    enc = _resolve_file(args.file)
    pw = _read_password("查看/编辑需要密码: ")   # 定稿设计：编辑每次确认，不走缓存
    try:
        text = store.decrypt_bytes(enc.read_bytes(), pw).decode("utf-8")
    except store.WrongPassword:
        sys.exit("密码不正确")
    fd, tmp = tempfile.mkstemp(prefix="keyfort-edit-", suffix=".env")
    os.close(fd)
    tmp = pathlib.Path(tmp)
    tmp.write_text(text, encoding="utf-8")
    editor = args.editor or _editor_base()
    print(f"已打开编辑器：保存即重新加密（{tmp}）")
    try:
        proc = subprocess.Popen(_editor_argv(editor) + [str(tmp)])
    except FileNotFoundError:
        tmp.unlink()
        sys.exit(f"找不到编辑器：{editor}")
    last = text
    warned = None
    try:
        while proc.poll() is None:            # 编辑器开着：每次保存立刻回写密文
            time.sleep(0.4)
            cur = _read_text_tol(tmp) if tmp.exists() else None
            if cur is not None and cur != last:
                _probs = _vars_problems(store.parse_env_text(cur))
                if _probs:                    # 非法内容不入库，改正后自动恢复
                    if cur != warned:
                        print(f"⚠ 本次保存未入库（{_probs}），改正后再保存")
                        warned = cur
                    continue
                _write_encrypted(enc, cur, pw)
                last = cur
        cur = _read_text_tol(tmp) if tmp.exists() else None
        if cur is not None and cur != last:   # 退出瞬间的那次保存
            _probs = _vars_problems(store.parse_env_text(cur))
            if _probs:
                print(f"⚠ 最后一次保存未入库（{_probs}）")
            else:
                _write_encrypted(enc, cur, pw)
                last = cur
    finally:
        proc.wait()
        if tmp.exists():
            tmp.unlink()
    if last == text:
        print("keyfort: 内容未变化，不重写")
    else:
        print("keyfort: 已保存并重新加密")


def _vars_with_cached_pw(enc: pathlib.Path) -> dict:
    pw = _cached_pw(str(enc.parent))
    if not pw:
        sys.exit("keyring 里没有本项目的密码：先运行 keyfort 重新解锁一次")
    try:
        return _entries_from(enc.read_bytes(), pw, enc.name)
    except store.WrongPassword:
        sys.exit("缓存的密码不正确：请 keyfort edit 或 keyfort passwd 校正")


def cmd_set(args):
    if not _KEY_RE.fullmatch(args.key):
        sys.exit(f"非法密钥名（只允许字母/数字/下划线，不以数字开头）：{args.key}")
    _p = _value_problem(args.value)
    if _p:
        sys.exit(f"值无法原样保存（{_p}），请调整后重试")
    enc = _resolve_file(args.file)
    vars = _vars_with_cached_pw(enc)
    vars[args.key] = args.value
    _write_encrypted(enc, store.dump_env_text(vars), _cached_pw(str(enc.parent)))
    print(f"keyfort: 已写入 {args.key}（重新进入 keyfort 环境后生效）")


def cmd_unset(args):
    enc = _resolve_file(args.file)
    vars = _vars_with_cached_pw(enc)
    if args.key not in vars:
        sys.exit(f"{args.key} 不存在")
    del vars[args.key]
    _write_encrypted(enc, store.dump_env_text(vars), _cached_pw(str(enc.parent)))
    print(f"keyfort: 已删除 {args.key}")


def cmd_get(args):
    enc = _resolve_file(args.file)
    pw = _read_password("查看需要密码: ")
    try:
        vars = _entries_from(enc.read_bytes(), pw, enc.name)
    except store.WrongPassword:
        sys.exit("密码不正确")
    if args.key not in vars:
        sys.exit(f"{args.key} 不存在")
    print(vars[args.key])


def cmd_list(args):
    enc = _resolve_file(args.file)
    pw = _cached_pw(str(enc.parent)) or _read_password("文件密码: ")
    try:
        names = list(_entries_from(enc.read_bytes(), pw, enc.name))
    except store.WrongPassword:
        sys.exit("密码不正确")
    print(f"{enc}（{len(names)} 个密钥）")
    for n in sorted(names):
        print(" ", n)


def cmd_passwd(args):
    enc = _resolve_file(args.file)
    old = _read_password("旧密码: ")
    try:
        vars = _entries_from(enc.read_bytes(), old, enc.name)
    except store.WrongPassword:
        sys.exit("旧密码不正确")
    text = store.dump_env_text(vars)
    new = getpass.getpass("新密码: ")
    if len(new) < 4:
        sys.exit("新密码至少 4 位")
    if new != getpass.getpass("再输一次新密码: "):
        sys.exit("两次输入不一致")
    _write_encrypted(enc, text, new)
    _save_auth(enc.parent, new)
    print(f"keyfort: {enc.name} 已用新密码重新加密")


def cmd_run(args):
    enc = _resolve_file()
    vars, _ = _decrypt_entries(enc, allow_prompt=False)
    env = dict(os.environ)
    env.update(vars)
    env["KEYFORT_ACTIVE_KEYS"] = ",".join(vars)
    if not args.rargs:
        sys.exit("用法: keyfort run <命令> [参数...]")
    sys.exit(subprocess.call(args.rargs, env=env))


def cmd_init(args):
    changed = shells.init_all()
    for c in changed:
        print(f"✓ {c}")
    if changed:
        print("keyfort: 新开终端进入有 .keyfort 的目录即自动注入")
    else:
        print("keyfort: 终端集成已是最新，无需修改")


def cmd_uninit(args):
    changed = shells.uninit_all()
    for c in changed:
        print(f"✓ 已移除：{c}")
    if not changed:
        print("keyfort: 没有需要移除的终端集成")


def _emit_script(script: str) -> None:
    """发射 eval 脚本：强制 LF——Windows 文本模式默认输出 \r\n，
    会被 sh 的 eval 拼进值里污染密钥。"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(newline="\n")
    print(script)


def cmd_activate(args):
    enc = _resolve_file(args.file)
    vars, _ = _decrypt_entries(enc)
    if args.emit:
        _emit_script(shells.activate_script(args.emit, vars, args.quiet))
        return
    print("activate 需要在当前 shell 里 eval 才能生效：")
    print("  PowerShell:  keyfort activate --emit ps | iex")
    print('  bash:        eval "$(keyfort activate --emit sh)"')
    print("或运行 keyfort init 安装终端集成（之后自动激活，无需手动 eval）")


def cmd_deactivate(args):
    keys = [k for k in os.environ.get("KEYFORT_ACTIVE_KEYS", "").split(",") if k]
    if not keys:
        sys.exit("当前会话没有 keyfort 注入的变量")
    if args.emit:
        _emit_script(shells.deactivate_script(args.emit, keys, args.quiet))
        return
    print("deactivate 需要在当前 shell 里 eval 才能生效：")
    print("  PowerShell:  keyfort deactivate --emit ps | iex")
    print('  bash:        eval "$(keyfort deactivate --emit sh)"')


def cmd_restore(args):
    """明文还原：解密 .keyfort → 合回明文 env 文件 → 删除 .keyfort 与缓存密码。"""
    enc = store.find()
    if enc is None:
        sys.exit("本目录及上级没有 .keyfort 加密文件")
    root = enc.parent
    if args.file:
        target = pathlib.Path(args.file)
        if not target.is_absolute():
            target = pathlib.Path.cwd() / target
    else:
        target = root / ".env.local"
        for name in (".env.local", ".env", ".env.development", ".env.production"):
            cand = root / name
            if cand.is_file():
                target = cand
                break
    vars, _ = _decrypt_entries(enc)
    if target.exists():
        target.write_text(
            _unhide_keys_in_text(_read_text_tol(target), vars), encoding="utf-8")
    else:
        target.write_text(store.dump_env_text(vars), encoding="utf-8")
    enc.unlink()
    _kr_delete(str(root))
    print(f"✓ {len(vars)} 个密钥已还原 → {target}")
    print(f"✓ 已删除 {enc.name}，并清除系统凭据库里的缓存密码")
    print("注意：明文已回到磁盘，不要再提交到 git")


# ---------------------------------------------------------------- 入口
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"edit", "set", "unset", "get", "list", "passwd", "run", "create",
             "init", "uninit", "activate", "deactivate", "restore"}
    if argv and not argv[0].startswith("-") and argv[0] not in known:
        # keyfort <明文文件> [密码]：加密登记并进入注入环境
        return cmd_encrypt(argparse.Namespace(
            file=argv[0], password=argv[1] if len(argv) > 1 else None))

    ap = argparse.ArgumentParser(
        prog="keyfort",
        description="最简单的密钥环境管理：一行加密，一个词进入注入环境")
    sub = ap.add_subparsers(dest="cmd", required=False)

    p = sub.add_parser("edit", help="用编辑器编辑密钥（需密码，保存即重新加密）")
    p.add_argument("file", nargs="?", help="加密文件或目录（默认向上查找）")
    p.add_argument("--editor", "-E",
                   help="指定编辑器（常见编辑器只写名字即可，如 -e code，"
                        "自动补 --wait 保持阻塞）")

    p = sub.add_parser("set", help="设置/更新一个密钥（无需输入密码）")
    p.add_argument("key")
    p.add_argument("value")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("unset", help="删除一个密钥")
    p.add_argument("key")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("get", help="查看单个密钥的值（需输入密码）")
    p.add_argument("key")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("list", help="列出全部密钥名（不显示值）")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("passwd", help="更换加密密码")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("run", help="以注入环境执行单条命令（脚本/CI 用）")
    p.add_argument("rargs", nargs=argparse.REMAINDER)

    p = sub.add_parser("create", help="创建空密钥库（不需要已有明文文件）")
    p.add_argument("password", nargs="?")

    p = sub.add_parser("init", help="安装终端集成：进入项目目录自动注入")
    p = sub.add_parser("uninit", help="移除终端集成（完整摘除 profile/AutoRun）")

    p = sub.add_parser("activate",
                       help="把密钥注入当前会话（终端集成内部使用）")
    p.add_argument("file", nargs="?")
    p.add_argument("--emit", "-e", choices=["ps", "sh", "cmd"],
                   help="发射对应 shell 的 eval 脚本")
    p.add_argument("--quiet", "-q", action="store_true")

    p = sub.add_parser("deactivate",
                       help="清除当前会话注入的变量（终端集成内部使用）")
    p.add_argument("--emit", "-e", choices=["ps", "sh", "cmd"])
    p.add_argument("--quiet", "-q", action="store_true")

    p = sub.add_parser("restore", help="明文还原：密钥合回 env 文件并取消登记")
    p.add_argument("file", nargs="?", help="目标明文文件（默认 .env.local/.env）")

    args = ap.parse_args(argv)

    if args.cmd is None:
        # 裸 keyfort：一个词进入注入环境
        enc = _resolve_file()
        vars, _ = _decrypt_entries(enc)
        _spawn_injected(vars)
    else:
        globals()[f"cmd_{args.cmd}"](args)


if __name__ == "__main__":
    main()
