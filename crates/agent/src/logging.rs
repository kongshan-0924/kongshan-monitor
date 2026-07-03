//! 极简日志(输出到 stderr,由 systemd/journald 收集加时间戳)。
//! 有意不引入日志框架:agent 追求最小依赖与最小内存。
//! 安全约束:任何日志行都不得包含 token / 密钥(评审时全局检查调用点)。

macro_rules! log_info {
    ($($arg:tt)*) => { eprintln!("[info] {}", format_args!($($arg)*)) };
}
macro_rules! log_warn {
    ($($arg:tt)*) => { eprintln!("[warn] {}", format_args!($($arg)*)) };
}
macro_rules! log_error {
    ($($arg:tt)*) => { eprintln!("[error] {}", format_args!($($arg)*)) };
}
