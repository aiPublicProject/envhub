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
import subprocess
import sys
import tempfile

from . import shells, store

AUTH_SERVICE = "keyfort"


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
    return getpass.getpass(prompt)


def _read_text_tol(path: pathlib.Path) -> str:
    """按能读的编码读（utf-8 / gbk），编辑器存成 ANSI 也不炸。"""
    raw = path.read_bytes()
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
    """返回 (vars: dict, pw: str)。取密顺序：显式传入 → KEYFORT_PASSWORD（CI）
    → keyring → 交互询问（最多三次）。非交互且没有可用密码 → 明确退出。"""
    root = str(enc.parent)
    data = enc.read_bytes()
    if pw is None:
        pw = _cached_pw(root)
        if pw:
            allow_prompt = False
    if pw is None:
        pw = _kr_get(root)
        if pw:
            allow_prompt = False
    if pw is not None:
        try:
            return _entries_from(data, pw, enc.name), pw
        except store.WrongPassword:
            if not allow_prompt:
                sys.exit("KEYFORT_PASSWORD 与加密文件不匹配")
            print("缓存的密码不正确，请重新输入")
            pw = None
    if not allow_prompt:
        sys.exit("密码不可用（keyring 无记录或已失效）。先运行 keyfort 重新解锁。")
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
    editor = os.environ.get("EDITOR") or ("notepad" if os.name == "nt" else "vi")
    subprocess.call([editor, str(tmp)])
    kept = _read_text_tol(tmp)
    tmp.unlink()
    return kept, store.parse_env_text(kept)


def _hide_keys_in_text(text: str, keys: set) -> str:
    """把选中密钥的值原位替换为 <keyfort:同名> 占位符；行/注释/其余行原样保留，
    文件从此可提交 git。"""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        k = (stripped.partition("=")[0].strip()
             if not stripped.startswith("#") and "=" in stripped else None)
        out.append(f"{k}=<keyfort:{k}>" if k in keys else line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _unhide_keys_in_text(text: str, vars: dict) -> str:
    """把 <keyfort:名> 占位符换回真实值；库里有而文件没有的密钥追加到末尾。"""
    out, seen = [], set()
    for line in text.splitlines():
        stripped = line.strip()
        k, _, v = (stripped.partition("=") if "=" in stripped else ("", "", ""))
        v = v.strip()
        if (not stripped.startswith("#") and k.strip()
                and v.startswith("<keyfort:") and v.endswith(">")):
            name = v[len("<keyfort:"):-1]
            if name in vars:
                out.append(f"{name}={vars[name]}")
                seen.add(name)
                continue
        out.append(line)
    body = "\n".join(out)
    missing = [k for k in vars if k not in seen]
    if missing:
        if body and not body.endswith("\n"):
            body += "\n"
        body += "".join(f"{k}={vars[k]}\n" for k in missing)
    elif text.endswith("\n"):
        body += "\n"
    return body


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
    store.ensure_gitignore(src.parent, store.FILENAME)
    print("✓ .gitignore 已更新（仅 .keyfort；原文件只剩占位符，可提交）")

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
    pw = _cached_pw(str(enc.parent))
    if pw:
        try:
            text = store.decrypt_bytes(enc.read_bytes(), pw).decode("utf-8")
        except store.WrongPassword:
            pw = None
    if pw is None:                        # 查看需要密码：每次确认
        pw = _read_password("查看/编辑需要密码: ")
        try:
            text = store.decrypt_bytes(enc.read_bytes(), pw).decode("utf-8")
        except store.WrongPassword:
            sys.exit("密码不正确")
    fd, tmp = tempfile.mkstemp(prefix="keyfort-edit-", suffix=".env")
    os.close(fd)
    tmp = pathlib.Path(tmp)
    tmp.write_text(text, encoding="utf-8")
    editor = os.environ.get("EDITOR") or ("notepad" if os.name == "nt" else "vi")
    before = _read_text_tol(tmp)
    subprocess.call([editor, str(tmp)])
    after = _read_text_tol(tmp)
    if after == before:
        print("keyfort: 内容未变化，不重写")
    else:
        _write_encrypted(enc, after, pw)
        print("keyfort: 已重新加密")
    tmp.unlink()
    store.ensure_gitignore(enc.parent, store.FILENAME)


def _vars_with_cached_pw(enc: pathlib.Path) -> dict:
    pw = _cached_pw(str(enc.parent))
    if not pw:
        sys.exit("keyring 里没有本项目的密码：先运行 keyfort 重新解锁一次")
    try:
        return _entries_from(enc.read_bytes(), pw, enc.name)
    except store.WrongPassword:
        sys.exit("缓存的密码不正确：请 keyfort edit 或 keyfort passwd 校正")


def cmd_set(args):
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


def cmd_print(args):
    enc = _resolve_file(args.file)
    pw = _read_password("查看需要密码: ")
    try:
        vars = _entries_from(enc.read_bytes(), pw, enc.name)
    except store.WrongPassword:
        sys.exit("密码不正确")
    for k in sorted(vars):
        print(f"{k}={vars[k]}")


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


def cmd_activate(args):
    enc = _resolve_file(args.file)
    vars, _ = _decrypt_entries(enc)
    if args.emit:
        print(shells.activate_script(args.emit, vars, args.quiet))
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
        print(shells.deactivate_script(args.emit, keys, args.quiet))
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
    known = {"edit", "set", "unset", "print", "list", "passwd", "run",
             "init", "uninit", "activate", "deactivate", "restore"}
    if argv and not argv[0].startswith("-") and argv[0] not in known:
        # keyfort <明文文件> [密码]：加密登记并进入注入环境
        return cmd_encrypt(argparse.Namespace(
            file=argv[0], password=argv[1] if len(argv) > 1 else None))

    ap = argparse.ArgumentParser(
        prog="keyfort",
        description="最简单的密钥环境管理：一行加密，一个词进入注入环境")
    sub = ap.add_subparsers(dest="cmd", required=False)

    p = sub.add_parser("edit", help="用系统默认编辑器编辑密钥（需输入密码）")
    p.add_argument("file", nargs="?", help="加密文件或目录（默认向上查找）")

    p = sub.add_parser("set", help="设置/更新一个密钥（无需输入密码）")
    p.add_argument("key")
    p.add_argument("value")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("unset", help="删除一个密钥")
    p.add_argument("key")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("print", help="打印全部密钥（需输入密码）")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("list", help="列出全部密钥名（不显示值）")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("passwd", help="更换加密密码")
    p.add_argument("file", nargs="?")

    p = sub.add_parser("run", help="以注入环境执行单条命令（脚本/CI 用）")
    p.add_argument("rargs", nargs=argparse.REMAINDER)

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
