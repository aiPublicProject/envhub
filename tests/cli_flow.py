"""最终极简形态的全流程测试。

覆盖：一次性加密登记（全部/部分选择）、注入运行、get/set/unset/edit、
passwd、错误密码路径、目录外指引、终端集成 init/uninit（幂等/摘除）、
activate/deactivate --emit、明文还原 restore。
keyring 用内存后端（进程内）+ KEYFORT_PASSWORD（子进程），绝不碰真实凭据库；
KEYFORT_HOME 重定向 shell 集成落盘位置，绝不碰真实 profile/注册表。
"""
import io
import json
import base64
import contextlib
import getpass
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = pathlib.Path(tempfile.mkdtemp(prefix="keyfort-cli-"))
for k in ("KEYFORT_PASSWORD", "NODE_OPTIONS", "PYTHONPATH"):
    os.environ.pop(k, None)
# shell 集成全部落在这个假 home 里（profile / .bashrc / cmd AutoRun 均不碰真实位置）
os.environ["KEYFORT_HOME"] = str(pathlib.Path(tempfile.mkdtemp(prefix="keyfort-home-")))

from keyfort import cli, store  # noqa: E402
import keyring  # noqa: E402
import keyring.backend  # noqa: E402


class MemKR(keyring.backend.KeyringBackend):
    store = {}
    priority = 1

    def set_password(self, s, u, p):
        type(self).store[(s, u)] = p

    def get_password(self, s, u):
        return type(self).store.get((s, u))

    def delete_password(self, s, u):
        type(self).store.pop((s, u), None)


keyring.set_keyring(MemKR())

captured = {}


def fake_spawn(vars):
    captured["vars"] = vars            # 不真正派生 shell


cli._spawn_injected = fake_spawn

PASS = FAIL = 0


def case(name, good, detail=""):
    global PASS, FAIL
    PASS += bool(good)
    FAIL += not good
    print(f"[{'PASS' if good else 'FAIL'}] {name}  "
          f"{detail if not good else ''}", flush=True)


def capture_print(func, *a):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            func(*a)
    except SystemExit as e:
        buf.write(f"[exit {e.code}]")
    return buf.getvalue()


PROJ = pathlib.Path(tempfile.mkdtemp(prefix="keyfort-cli-proj-"))
PLAIN = PROJ / ".env.local"
PLAIN.write_text(
    "DB_PASS=secret123\n"
    "PORT=3000\n"
    "# 注释行\n"
    "API_KEY=sk-abc\n"
    "DEBUG=1\n", encoding="utf-8")

# ---- 一次性加密登记：部分加密 = 编辑器里只保留要加密的行 ----
cli._read_password = lambda prompt="": "pw-1234"
import builtins  # noqa: E402
ANSWERS = []                                # 交互回答队列：范围 → 原文件处理
builtins.input = lambda prompt="": (ANSWERS.pop(0) if ANSWERS else "")

# 假编辑器：只保留 PICK_KEEP 指定前缀的行（留下的 = 要加密的）
_picker = PROJ / "_picker.py"
_picker.write_text(
    "import os, sys\n"
    "p = sys.argv[1]\n"
    "pref = tuple(os.environ['PICK_KEEP'].split(','))\n"
    "lines = open(p, encoding='utf-8').read().splitlines(True)\n"
    "keep = [l for l in lines if l.startswith(pref)]\n"
    "open(p, 'w', encoding='utf-8').write(''.join(keep))\n", encoding="utf-8")
_picker_bat = PROJ / "_picker.bat"
_picker_bat.write_text(f'@echo off\r\n"{sys.executable}" "{_picker}" %*\r\n',
                       encoding="gbk")
os.environ["EDITOR"] = str(_picker_bat)
os.environ["PICK_KEEP"] = "DB_PASS=,API_KEY="

ANSWERS.extend(["2", "1"])          # 2=部分加密 → 编辑器 → 1=移除已加密的 key
cli.main([str(PLAIN), "pw-1234"])
case("部分加密：进入注入环境",
     captured.get("vars", {}).get("DB_PASS") == "secret123",
     repr(captured))
enc = PROJ / ".keyfort"
case("部分加密：.keyfort 生成", enc.is_file())
plain_now = PLAIN.read_text(encoding="utf-8")
case("部分加密：值替换为占位符",
     "DB_PASS=<keyfort:DB_PASS>" in plain_now
     and "API_KEY=<keyfort:API_KEY>" in plain_now
     and "secret123" not in plain_now, plain_now)
case("部分加密：明文保留其余变量",
     "PORT=3000" in plain_now and "DEBUG=1" in plain_now)
case("部分加密：注释与格式原样保留", "# 注释行" in plain_now)
_gi = (PROJ / ".gitignore").read_text(encoding="utf-8")
case("gitignore 仅加 .keyfort（原文件可提交）",
     ".keyfort" in _gi and ".env.local" not in _gi)
case("密码已入 keyring", "pw-1234" in MemKR.store.values())
EH_HOME = pathlib.Path(os.environ["KEYFORT_HOME"])
PS_PROF = EH_HOME / "Documents" / "WindowsPowerShell" / "profile.ps1"
case("一次性命令自动安装终端集成",
     PS_PROF.exists() and "function keyfort" in PS_PROF.read_text(encoding="utf-8-sig"))

# ---- 注入运行（子进程 + KEYFORT_PASSWORD 兜底）----
env = dict(os.environ)
env["KEYFORT_PASSWORD"] = "pw-1234"
p = subprocess.run(["cmd", "/c", "set DB_"],
                   cwd=PROJ, env=env, capture_output=True, text=True,
                   errors="replace", timeout=60)
p = subprocess.run([sys.executable, "-m", "keyfort", "run", "cmd", "/c", "set DB_PASS"],
                   cwd=PROJ, env=env, capture_output=True, text=True,
                   errors="replace", timeout=60)
case("keyfort run 注入（子进程）", "DB_PASS=secret123" in p.stdout,
     f"out={p.stdout!r} err={p.stderr[:150]!r}")

# ---- set / unset / get ----
cli.main(["set", "NEW_KEY", "new-value", str(PROJ)])
out = capture_print(cli.main, ["get", "DB_PASS", str(PROJ)])
case("get 查看单个密钥（只输出值）", out.strip() == "secret123", out)
out = capture_print(cli.main, ["get", "NEW_KEY", str(PROJ)])
case("get 含新增密钥", out.strip() == "new-value", out)
cli.main(["unset", "NEW_KEY", str(PROJ)])
out = capture_print(cli.main, ["get", "NEW_KEY", str(PROJ)])
case("unset 后查看该密钥已不存在", "不存在" in out, out)

# ---- edit：用假编辑器改临时文件 ----
(PROJ / "_fake_editor.py").write_text(
    "import sys\n"
    "p = sys.argv[1]\n"
    "s = open(p, encoding='utf-8').read().replace('secret123', 'rotated456')\n"
    "open(p, 'w', encoding='utf-8').write(s)\n", encoding="utf-8")
os.environ["EDITOR"] = sys.executable
# 简化：EDITOR 直接指向带参数的场景复杂，改用一个包装 bat
wrapper = PROJ / "_editor.bat"
wrapper.write_text(f'@echo off\r\n"{sys.executable}" '
                   f'"{PROJ / "_fake_editor.py"}" %*\r\n', encoding="gbk")
os.environ["EDITOR"] = str(wrapper)
cli.main(["edit", str(PROJ)])
out = capture_print(cli.main, ["get", "DB_PASS", str(PROJ)])
case("edit 编辑后回加密", out.strip() == "rotated456", out[:150])
(PROJ / "_fake_editor.py").unlink()
wrapper.unlink()
os.environ["EDITOR"] = str(_picker_bat)      # 恢复给后续部分加密用例

# ---- passwd 换密码（旧→新，新密码生效、旧密码失效）----
answers = {"旧密码: ": "pw-1234", "新密码: ": "new-pw-99",
           "再输一次新密码: ": "new-pw-99", "查看需要密码: ": "new-pw-99"}
cli._read_password = lambda prompt="": answers.get(prompt, "new-pw-99")
_orig_getpass = getpass.getpass
getpass.getpass = lambda prompt="": answers.get(prompt, "")
cli.main(["passwd", str(PROJ)])
getpass.getpass = _orig_getpass
out = capture_print(cli.main, ["get", "DB_PASS", str(PROJ)])
case("passwd 后新密码可解", out.strip() == "rotated456", out)
answers["查看需要密码: "] = "pw-1234"
out = capture_print(cli.main, ["get", "DB_PASS", str(PROJ)])
case("passwd 后旧密码失效", "密码不正确" in out)

# ---- 全部加密：明文删除 ----
PROJ2 = pathlib.Path(tempfile.mkdtemp(prefix="keyfort-cli-all-"))
f2 = PROJ2 / ".env"
f2.write_text("A=1\nB=2\n", encoding="utf-8")
ANSWERS.clear()                     # 无输入 → 回车默认 = 全部加密
cli.main([str(f2), "pw-all"])
case("全部加密：值替换为占位符",
     f2.exists() and "A=<keyfort:A>" in f2.read_text(encoding="utf-8")
     and (PROJ2 / ".keyfort").is_file())

# ---- 部分加密选项 3：原文件原样保留 ----
PROJ3 = pathlib.Path(tempfile.mkdtemp(prefix="keyfort-cli-keep-"))
f3 = PROJ3 / ".env"
f3.write_text("SECRET_X=hidden\nPORT=8080\n", encoding="utf-8")
os.environ["PICK_KEEP"] = "SECRET_X="
ANSWERS.clear()
ANSWERS.extend(["2", "2"])          # 部分 → 只留 SECRET_X → 2=原样保留
cli.main([str(f3), "pw-keep"])
case("原样保留：明文文件未动",
     "SECRET_X=hidden" in f3.read_text(encoding="utf-8")
     and "PORT=8080" in f3.read_text(encoding="utf-8"))
_v3 = cli._entries_from((PROJ3 / ".keyfort").read_bytes(), "pw-keep", ".keyfort")
case("原样保留：密文只含留下的 key", sorted(_v3) == ["SECRET_X"], repr(_v3))

# ---- 目录外透明指引 ----
outside = pathlib.Path(tempfile.mkdtemp(prefix="keyfort-cli-out-"))
lenv2 = dict(env)
lenv2.pop("KEYFORT_PASSWORD", None)
p = subprocess.run([sys.executable, "-m", "keyfort", "run", "cmd", "/c", "echo x"],
                   cwd=outside, env=lenv2, capture_output=True, text=True,
                   errors="replace", timeout=60)
case("目录外给出明确指引", "没有 .keyfort" in (p.stdout + p.stderr),
     f"out={p.stdout!r} err={p.stderr[:150]!r}")

# ---- 终端集成：init 幂等 / uninit 完整摘除 ----
cli.main(["init"])
_once = PS_PROF.read_text(encoding="utf-8-sig")
cli.main(["init"])
case("init 幂等（集成块只写一次）",
     PS_PROF.read_text(encoding="utf-8-sig") == _once
     and _once.count("# >>> keyfort init >>>") == 1)
AUTORUN = EH_HOME / ".keyfort" / "autorun.txt"
case("init 写入 cmd AutoRun（隔离文件）",
     AUTORUN.exists() and "keyfort-cmd.bat" in AUTORUN.read_text(encoding="utf-8"))
case("init 生成 cmd 钩子 bat", (EH_HOME / ".keyfort" / "keyfort-cmd.bat").exists())
case("init 写入 .bashrc", "keyfort()" in (EH_HOME / ".bashrc").read_text(encoding="utf-8"))
cli.main(["uninit"])
_left = PS_PROF.read_text(encoding="utf-8-sig") if PS_PROF.exists() else ""
case("uninit 完整摘除",
     "keyfort init >>>" not in _left
     and (not AUTORUN.exists()
          or "keyfort-cmd" not in AUTORUN.read_text(encoding="utf-8"))
     and not (EH_HOME / ".keyfort" / "keyfort-cmd.bat").exists())

# ---- activate / deactivate --emit（子进程，KEYFORT_PASSWORD 兜底）----
env2 = dict(os.environ)
env2["KEYFORT_PASSWORD"] = "new-pw-99"
p = subprocess.run(
    [sys.executable, "-m", "keyfort", "activate", "--emit", "sh", "--quiet"],
    cwd=PROJ, env=env2, capture_output=True, text=True,
    errors="replace", timeout=60)
case("activate --emit sh",
     p.returncode == 0 and "export DB_PASS='rotated456'" in p.stdout
     and "export API_KEY=" in p.stdout
     and "export KEYFORT_ACTIVE_KEYS=" in p.stdout,
     f"out={p.stdout!r} err={p.stderr[:150]!r}")
p = subprocess.run(
    [sys.executable, "-m", "keyfort", "activate", "--emit", "ps", "--quiet"],
    cwd=PROJ, env=env2, capture_output=True, text=True,
    errors="replace", timeout=60)
case("activate --emit ps",
     "$env:DB_PASS='rotated456'" in p.stdout
     and "$env:KEYFORT_ACTIVE_KEYS=" in p.stdout,
     f"out={p.stdout!r} err={p.stderr[:150]!r}")
p = subprocess.run(
    [sys.executable, "-m", "keyfort", "activate", "--emit", "cmd", "--quiet"],
    cwd=PROJ, env=env2, capture_output=True, text=True,
    errors="replace", timeout=60)
case("activate --emit cmd",
     'set "DB_PASS=rotated456"' in p.stdout
     and 'set "KEYFORT_ACTIVE_KEYS=' in p.stdout,
     f"out={p.stdout!r} err={p.stderr[:150]!r}")
env3 = dict(env2)
env3["KEYFORT_ACTIVE_KEYS"] = "DB_PASS,API_KEY"
p = subprocess.run(
    [sys.executable, "-m", "keyfort", "deactivate", "--emit", "sh"],
    cwd=PROJ, env=env3, capture_output=True, text=True,
    errors="replace", timeout=60)
case("deactivate --emit sh",
     p.stdout.startswith("unset ")
     and all(k in p.stdout for k in ("DB_PASS", "API_KEY",
                                     "KEYFORT_ACTIVE_KEYS")),
     f"out={p.stdout!r} err={p.stderr[:150]!r}")

# ---- restore 明文还原（进程内，chdir 到项目）----
_old_cwd = os.getcwd()
os.chdir(PROJ)
try:
    cli.main(["restore"])
finally:
    os.chdir(_old_cwd)
_restored = PLAIN.read_text(encoding="utf-8")
case("restore 密钥合回明文",
     "DB_PASS=rotated456" in _restored and "API_KEY=sk-abc" in _restored
     and "PORT=3000" in _restored and "DEBUG=1" in _restored, _restored)
case("restore 删除 .keyfort", not enc.exists())
case("restore 清除 keyring 缓存", ("keyfort", str(PROJ)) not in MemKR.store)

print(f"\n=== {PASS} PASS / {FAIL} FAIL ===", flush=True)
sys.exit(1 if FAIL else 0)
