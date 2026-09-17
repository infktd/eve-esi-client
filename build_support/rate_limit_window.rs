// Parses an ESI rate-limit window size ("15m", "1h") into seconds. This file
// is `include!`d by both build.rs (the spec's `x-rate-limit.window-size`) and
// src/rate_limit.rs (the `X-Ratelimit-Limit` header, e.g. "150/15m"), so the
// two can never disagree. CCP documents `m` and `h`; `s` is accepted too.

fn parse_window_size(value: &str) -> Option<u64> {
    let value = value.trim();
    let unit_at = value.find(|c: char| !c.is_ascii_digit())?;
    let (count, unit) = value.split_at(unit_at);
    let count: u64 = count.parse().ok()?;
    let seconds_per_unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };
    count.checked_mul(seconds_per_unit).filter(|&secs| secs > 0)
}
