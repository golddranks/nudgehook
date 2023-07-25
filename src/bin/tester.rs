#![feature(concat_bytes)]
use std::{net::TcpStream, io::{Write, Read}};

const CLIENT_ID: [u8; 21] = [83, 83, 72, 45, 50, 46, 48, 45, 79, 112, 101, 110, 83, 83, 72, 95, 57, 46, 48, 13, 10];

#[rustfmt::skip]
const SSH_MSG_KEXINIT: &[u8; 1328] = concat_bytes!(
    [0, 0, 5, 44,
    5,
    20],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [0, 0, 0, 241],
    b"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c",
    [0, 0, 1, 65],
    b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256",
    [0, 0, 0, 108],
    b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    [0, 0, 0, 108],
    b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    [0, 0, 0, 213],
    b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    [0, 0, 0, 213],
    b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    [0, 0, 0, 26],
    b"none,zlib@openssh.com,zlib",
    [0, 0, 0, 26],
    b"none,zlib@openssh.com,zlib",
    [0, 0, 0, 0,
    0, 0, 0, 0,
    0,
    0, 0, 0, 0,
    0, 1, 2, 3, 4]);

#[rustfmt::skip]
const SSH_MSG_KEX_ECDH_INIT: [u8; 48] = [
    0, 0, 0, 44,
    6,
    30,
    0, 0, 0, 32,
    151, 10, 230, 243, 245, 252, 249, 255,
    199, 197, 167, 90, 56, 213, 228, 214,
    152, 66, 235, 165, 38, 19, 120, 43,
    64, 253, 142, 188, 241, 105, 61, 74,
    0, 0, 0, 0, 0, 0];

fn main() {
    let mut buf = [0; 35036];
    let mut connection = TcpStream::connect("65.21.253.190:22").unwrap();
    connection.write_all(&CLIENT_ID).unwrap();
    let n = connection.read(&mut buf).unwrap();
    println!("{:?}", &buf[..n]);
    connection.write_all(SSH_MSG_KEXINIT).unwrap();
    let n = connection.read(&mut buf).unwrap();
    println!("{:?}", &buf[..n]);
    connection.write_all(&SSH_MSG_KEX_ECDH_INIT).unwrap();
    let n = connection.read(&mut buf).unwrap();
    println!("{:?}", &buf[..n]);
}
