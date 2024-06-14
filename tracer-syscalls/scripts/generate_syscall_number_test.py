import system_calls
import os


def generate_syscall_number_test(rust_arch, arch):
    test_header = f"""
  #[cfg(target_arch = "{rust_arch}")]
  #[test]
  fn test_{rust_arch}_syscall_numbers() \u007b
"""
    test_footer = """
  }
    """
    test_body = ""
    for name, value in getattr(system_calls, f"syscalls_{arch}").items():
        if name not in {"epoll_ctl_old", "epoll_wait_old"}:
            test_body += f"    assert_eq!(tracer_syscalls::SYS_{name}, {value});\n"
    return test_header + test_body + test_footer

def write_syscall_number_test():
    me = __file__
    test_file = os.path.realpath(f"{me}/../../tests/syscall_number_tests.rs")
    header = """
/// Automatically generated syscall number tests by generate_syscall_number_test.py
#[cfg(test)]
mod syscall_number_tests \u007b
    """
    footer = """
}
"""
    with open(test_file, "w+") as f:
        f.write(header)
        for (rust_arch, arch) in [("riscv64", "riscv64"), ("x86_64", "x86_64"), ("aarch64", "arm64")]:
            print(f"Generating syscall number test for {arch} (rust: {rust_arch})")
            f.write(generate_syscall_number_test(rust_arch, arch))
        f.write(footer)

if __name__ == '__main__':
    write_syscall_number_test()
    