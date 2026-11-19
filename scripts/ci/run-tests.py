#!/usr/bin/env python3
"""Build and run every test binary and doc-test serially with per-target timeouts.

Each `profile.test` binary from `cargo test --locked --no-run --message-format=json`
runs in its own session or Windows process group so a timeout kills the whole
child process tree. All binaries and `cargo test --locked --doc` run even after
an earlier failure so `ci-test.log` records every failing target in one pass.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

LOG_NAME = "ci-test.log"


def say(line, handle):
    print(line, flush=True)
    handle.write(line + "\n")
    handle.flush()


def test_executables(handle):
    command = ["cargo", "test", "--locked", "--no-run", "--message-format=json"]
    say(f"$ {' '.join(command)}", handle)
    build = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    if build.stderr:
        say(build.stderr.rstrip("\n"), handle)
    if build.returncode != 0:
        say("FAIL: the test suite did not compile", handle)
        sys.exit(1)
    executables = []
    for line in build.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and (message.get("profile") or {}).get("test") is True
            and message.get("executable")
            and message["executable"] not in executables
        ):
            executables.append(message["executable"])
    if not executables:
        say("FAIL: cargo reported no profile.test executables", handle)
        sys.exit(1)
    return executables


def kill_process_tree(process):
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            pass
    try:
        process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_target(command, timeout, env, log_path, handle):
    say(f"$ {' '.join(command)}", handle)
    started = time.time()
    child_env = dict(os.environ, **env)
    # CREATE_NEW_PROCESS_GROUP (0x200) isolates tree termination on Windows; start_new_session creates a Unix process group.
    creationflags = 0x00000200 if os.name == "nt" else 0
    with open(log_path, "w", errors="replace") as output:
        process = subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=child_env,
            start_new_session=(os.name != "nt"),
            creationflags=creationflags,
        )
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status = None
            kill_process_tree(process)
    with open(log_path, errors="replace") as output:
        content = output.read().rstrip("\n")
        if content:
            say(content, handle)
    say(f"exit {status} after {time.time() - started:.1f}s", handle)
    return status


def stem_of(path):
    name = os.path.basename(path)
    base, extension = os.path.splitext(name)
    return base if extension in (".exe", ".dylib", ".so") else name


def collect_ignored(log_paths):
    ignored = []
    for log_path in log_paths:
        with open(log_path, errors="replace") as log:
            for line in log:
                stripped = line.strip()
                if re.search(r"^test .+ \.\.\. ignored\b", stripped):
                    ignored.append(stripped)
    return ignored


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=600, help="seconds allowed per target")
    parser.add_argument("--only", action="append", default=[], help="run only matching name stems")
    parser.add_argument("--env", action="append", default=[], help="KEY=VALUE override per target")
    parser.add_argument(
        "--log-dir",
        default=os.environ.get("CI_LOG_DIR", "."),
        help="directory for ci-test.log and ci-<stem>.log",
    )
    parser.add_argument("tests", nargs="*", help="extra arguments passed to each test target")
    argv = sys.argv[1:]
    extra_args = []
    if "--" in argv:
        split_at = argv.index("--")
        extra_args = argv[split_at + 1 :]
        argv = argv[:split_at]
    options = parser.parse_args(argv)
    test_args = [*options.tests, *extra_args]

    for item in options.env:
        if "=" not in item:
            parser.error(f"--env expects KEY=VALUE, got {item!r}")
    env = dict(item.split("=", 1) for item in options.env)

    os.makedirs(options.log_dir, exist_ok=True)
    main_log = os.path.join(options.log_dir, LOG_NAME)

    with open(main_log, "a", errors="replace") as handle:
        say(f"=== run-tests.py: {sys.platform} {' '.join(sys.argv[1:])}", handle)
        every = test_executables(handle)
        chosen = [
            path
            for path in every
            if not options.only or any(stem_of(path).startswith(stem) for stem in options.only)
        ]
        run_doctests = not options.only or any(
            "doctest".startswith(stem) for stem in options.only
        )
        if options.only and not chosen and not run_doctests:
            say(f"FAIL: no test target matched {', '.join(options.only)}", handle)
            sys.exit(1)

        log_paths = []
        failures = []

        for path in chosen:
            log_path = os.path.join(options.log_dir, f"ci-{stem_of(path)}.log")
            log_paths.append(log_path)
            status = run_target([path, *test_args], options.timeout, env, log_path, handle)
            if status is None:
                failures.append(f"{os.path.basename(path)} timed out after {options.timeout}s")
            elif status != 0:
                failures.append(f"{os.path.basename(path)} exit {status}")

        if run_doctests:
            doc_log = os.path.join(options.log_dir, "ci-doctest.log")
            log_paths.append(doc_log)
            doc_cmd = ["cargo", "test", "--locked", "--doc"]
            if test_args:
                doc_cmd += ["--", *test_args]
            status = run_target(doc_cmd, options.timeout, env, doc_log, handle)
            if status is None:
                failures.append(f"doctests timed out after {options.timeout}s")
            elif status != 0:
                failures.append(f"doctests exit {status}")

        ignored = collect_ignored(log_paths)
        say(f"ignored tests on {sys.platform}: {len(ignored)}", handle)
        for line in ignored:
            say(f"  {line}", handle)

        if failures:
            say(f"FAIL: {'; '.join(failures)}", handle)
            sys.exit(1)
        say("PASS", handle)


if __name__ == "__main__":
    main()
