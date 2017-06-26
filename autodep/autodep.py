#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import tempfile

def error(output):
    """
        Report an error and exit.
    """
    print("\033[1mautodep\033[0m \033[31merror:\033[0m %s" % output, file=sys.stderr)
    sys.exit(1)

def warning(output):
    """
        Report a warning.
    """
    print("\033[1mautodep\033[0m \033[33mwarning:\033[0m %s" % output, file=sys.stderr)

def info(output):
    """
        Report status output.
    """
    print("\033[1mautodep\033[0m \033[32minfo:\033[0m %s" % output, file=sys.stderr, flush=True)

def choose(choices):
    """
        Let the user choose from a given list of choices, returning the chosen
        value.
    """
    choices = list(choices)
    for i, choice in enumerate(choices):
        print(" %02d) %s" % (i + 1, choice), file=sys.stderr)
    while True:
        choice = input(">>> ")
        try:
            return choices[int(choice)-1]
        except:
            pass

def parse_output_to_missing_files(output):
    """
        Extract a list of missing files from a command's output.
    """
    missing_files = set()

    # pkg-config (with optional cmake prefix)
    for missing_file in re.findall("(?m)^(?:--)?\s*No package '(.+)' found", output):
        missing_files.add("%s.pc" % missing_file)

    # Missing headers (GCC)
    for missing_file in re.findall("fatal error: '(.+)': No such file or directory", output):
        missing_files.add(missing_file)
    for missing_file in re.findall("fatal error: ([^'].+): No such file or directory", output):
        missing_files.add(missing_file)

    # Missing headers (llvm)
    for missing_file in re.findall("fatal error: '(.+)' file not found", output):
        missing_files.add(missing_file)
    for missing_file in re.findall("fatal error: ([^'].+) file not found", output):
        missing_files.add(missing_file)

    return missing_files

def missing_files_to_missing_packages(missing_files):
    """
        Find packages to which missing files belong.

        This implementation works only on Debian'ish systems and relies on
        apt-file.
    """
    missing_packages = set()
    for missing_file in missing_files:
        candidates = set(filter(None, [ x.split(": ")[0] for x in subprocess.check_output(["apt-file", "find", missing_file]).decode().split("\n") ]))
        if not candidates:
            error("Failed to find a package which offers \033[1m%s\033[0m." % missing_file)
        if len(candidates) > 1:
            warning("Undecided which package offers \033[1m%s\033[0m best." % (missing_file))
            candidates = (choose(candidates),)
        missing_packages.add(next(iter(candidates)))
    return missing_packages

def install_missing_packages(missing_packages):
    """
        Install missing packages.

        This implementation works only on Debian'ish systems.
    """
    subprocess.check_call(["sudo", "apt-get", "-y", "install"] + list(missing_packages))

def try_build(command_line):
    """
        Execute a command, tee its standard output to stdout, and return a
        tuple of (exit code, output).
    """
    build_command = subprocess.Popen(command_line, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout_data = []
    while True:
        line = build_command.stdout.readline().decode()
        print(line, end="")
        stdout_data.append(line)
        if build_command.poll() is not None:
            break
    line = build_command.stdout.read().decode()
    stdout_data.append(line)
    print(line, end="")
    return build_command.returncode, "".join(stdout_data)

class PkgConfigEnforcer():
    """
        Place a fake pkg-config early in PATH to ensure that we can read its
        output.
    """
    def __init__(self):
        if os.path.basename(sys.argv[0]) == "pkg-config":
            args = sys.argv[1:]
            if "--exists" in args and "--print-errors" not in args:
                args.insert(0, "--print-errors")
            pkg_config_output = subprocess.run(["/usr/bin/pkg-config"] + args, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            open(os.environ["PKG_CONFIG_TEE_TARGET"], "ab").write(pkg_config_output.stdout)
            os.execl("/usr/bin/pkg-config", "/usr/bin/pkg-config", *sys.argv[1:])
            sys.exit(-1)
        self.orig_path = os.environ["PATH"]
        self.tempdir = tempfile.TemporaryDirectory()
        self.tee_target = os.path.join(self.tempdir.name, "tee_target")
        os.symlink(os.path.abspath(sys.argv[0]), os.path.join(self.tempdir.name, "pkg-config"))
        os.environ["PATH"] = "%s:%s" % (self.tempdir.name, os.environ["PATH"])
        os.environ["PKG_CONFIG_TEE_TARGET"] = self.tee_target

    def undo(self):
        if hasattr(self, "tempdir"):
            os.environ["PATH"] = self.orig_path
            del self.tempdir

    def get_output(self, clean=True):
        if not os.path.isfile(self.tee_target):
            return ""
        retval = open(self.tee_target).read()
        if clean:
            os.unlink(self.tee_target)
        return retval

    def __del__(self):
        self.undo()

def main():
    pkg_config_enforcer = PkgConfigEnforcer()

    if len(sys.argv) == 1:
        print("autodep - automatically install missing dependencies")
        print("Syntax: autodep <command line of make process>")
        print()
        print("This tool currently works with apt based systems only and requires apt-file.")
        sys.exit(0)

    new_packages_installed = set()
    try:
        while True:
            info("Trying to compile")
            exit_code, stdout_data = try_build(sys.argv[1:])
            if not exit_code:
                break
            stdout_data += pkg_config_enforcer.get_output()
            missing_files = parse_output_to_missing_files(stdout_data)
            if not missing_files:
                error("Failed to find any missing files in compiler output")
            info("Found missing files")
            for file_name in missing_files:
                print(" - %s" % file_name, file=sys.stderr)
            print(end="", flush=True)
            missing_packages = missing_files_to_missing_packages(missing_files)
            info("Found missing packages")
            for package_name in missing_packages:
                print(" - %s" % package_name, file=sys.stderr)
                new_packages_installed.add(package_name)
            print(end="", flush=True)
            info("Installing missing packages")
            install_missing_packages(missing_packages)
    except:
        if new_packages_installed:
            info("The following packages have been installed: %s" % " ".join(iter(new_packages_installed)))
        raise

    info("Compiled sucessfully.")
    if new_packages_installed:
        info("The following packages have been installed: %s" % " ".join(iter(new_packages_installed)))

if __name__ == "__main__":
    main()
