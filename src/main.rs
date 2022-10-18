#![no_main]

use std::fs;
use std::io::{self, Write};
use utmp_rs::UtmpEntry;
use utmp_rs::UtmpParser;
use whoami::username; 


const MONTHS: [&[u8;3];12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

const JALIO: &[u8] = b"\x1b[1;38;5;2m      THIS IS A \x1b[38;5;1mPRIVATE\
              \x1b[38;5;2m SERVER. ALL CONNECTIONS ARE MONITORED AND \
              RECORDED\n           DISCONNECT \x1b[38;5;1mIMMEDIATELY\
              \x1b[38;5;2m IF YOU ARE NOT AN AUTHORIZED USER!
              \x1b[38;5;12m
                       d88b  .d8b.  db      d888888b  .d88b.  
                       `8P' d8' `8b 88        `88'   .8P  Y8. 
                        88  88ooo88 88         88    88    88 
                        88  88~~~88 88         88    88    88 
                    db. 88  88   88 88booo.   .88.   `8b  d8' 
                    Y8888P  YP   YP Y88888P Y888888P  `Y88P'\n
              \x1b[0;38;5;5m\n  ";

#[no_mangle]
pub fn main(_argc: i32, _argv: *const *const u8) {
    io::stdout().write_all(JALIO).unwrap();

    let username = username();
    print_last_login(&username);
    print_uptime();
    print_logins(&username);
}

#[inline(always)]
fn wtmp(username: &String) -> (time::OffsetDateTime, String) {

    let new_entries = utmp_rs::parse_from_path("/var/log/wtmp")
        .unwrap()
        .into_iter()
        .rev()
        .filter(|entry| is_curr_user(entry, &username))
        .take(2)
        .last()
        .unwrap();

    return match new_entries {
        UtmpEntry::UserProcess {
            pid: _,
            line: _,
            user: _,
            host,
            session: _,
            time,
        } => (time, host),
        _ => {
            panic!();
        }
    };
}

#[inline(always)]
fn utmp(username: &String) -> usize {

    return UtmpParser::from_path("/var/run/utmp")
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| is_curr_user(entry, &username))
        .count();
}

#[inline(always)]
fn uptime() -> u64 {
    fs::read("/proc/uptime")
        .unwrap()
        .into_iter()
        .take_while(|x| *x != b'.')
        .fold(0, |acc: u64, x: u8| {
            let m: u64 = (x & 15).into();
            10 * acc + m
        })
}

#[inline(always)]
fn is_curr_user(entry: &UtmpEntry, username: &String) -> bool {
    return match entry {
        UtmpEntry::UserProcess {
            pid: _,
            line: _,
            user,
            host: _,
            session: _,
            time: _,
        } => user == username,
        _ => false,
    };
}

#[inline(always)]
fn duration_to_dhms(d: u64) -> (u64, u8, u8, u8) {
    let sec: u8 = (d % 60) as u8;
    let min: u8 = (d / 60 % 60) as u8;
    let hour: u8 = (d / 3600 % 24) as u8;
    let day = d / (3600*24);

    (day, hour, min, sec)
}

fn u8_to_month(m: u8) -> &'static[u8;3] { 
    MONTHS[m as usize - 1]
}

fn pad(n: u8) -> [u8; 2] {
    match n {
        0..=9 => [b'0', n.to_string().as_bytes()[0]],
        10.. => n.to_string().as_bytes().try_into().unwrap()
    }
}

#[inline(always)]
fn print_last_login(username: &String) {

    let (ut, host) = wtmp(&username);

    let day = ut.day();
    let month = u8_to_month(ut.month() as u8);
    let hour = pad(ut.hour() as u8);
    let minute = pad(ut.minute() as u8);
    let second = pad(ut.second() as u8);
    let weekday = ut.weekday();

    io::stdout().write_all(b"Last login....: \x1b[38;5;6m").unwrap();


    io::stdout().write_all(weekday.to_string().as_bytes()).unwrap();
    io::stdout().write_all(b" ").unwrap();
    io::stdout().write_all(month).unwrap();
    io::stdout().write_all(b" ").unwrap();
    io::stdout().write_all(day.to_string().as_bytes()).unwrap();
    io::stdout().write_all(b", ").unwrap();
    io::stdout().write_all(&hour).unwrap();
    io::stdout().write_all(b":").unwrap();
    io::stdout().write_all(&minute).unwrap();
    io::stdout().write_all(b":").unwrap();
    io::stdout().write_all(&second).unwrap();

    io::stdout().write_all(b" from ").unwrap();
    io::stdout().write_all(host.as_bytes()).unwrap();
}

#[inline(always)]
fn print_uptime() {
    let (days, hours, mins, secs) = duration_to_dhms(uptime());

    io::stdout().write_all(b"\n  \x1b[38;5;5mUptime........: \x1b[38;5;6m").unwrap();
    io::stdout().write_all(days.to_string().as_bytes()).unwrap();
    if days == 1
    {    io::stdout().write_all(b" day ").unwrap(); }
    else
    {    io::stdout().write_all(b" days ").unwrap(); }
    io::stdout().write_all(hours.to_string().as_bytes()).unwrap();
    io::stdout().write_all(b":").unwrap();
    io::stdout().write_all(&pad(mins)).unwrap();
    io::stdout().write_all(b":").unwrap();
    io::stdout().write_all(&pad(secs)).unwrap();
}

#[inline(always)]
fn print_logins(username: &String) {


    let no_users = utmp(&username);


    io::stdout().write_all(b"\n  \x1b[38;5;5mSSH Logins....: \x1b[38;5;6mThere").unwrap();
    if no_users == 1
    {    io::stdout().write_all(b" is ").unwrap(); }
    else
    {    io::stdout().write_all(b" are ").unwrap(); }
    io::stdout().write_all(b"currently ").unwrap();
    io::stdout().write_all(no_users.to_string().as_bytes()).unwrap();
    if no_users == 1
    {    io::stdout().write_all(b" user ").unwrap(); }
    else
    {    io::stdout().write_all(b" users ").unwrap(); }
    io::stdout().write_all(b"logged in\n").unwrap();
}
