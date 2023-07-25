#![feature(concat_bytes)]
use std::array::TryFromSliceError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::str::Utf8Error;
use ring::agreement::{EphemeralPrivateKey, X25519, UnparsedPublicKey, agree_ephemeral};
use ring::error::Unspecified;
use ring::rand::SystemRandom;

pub enum Error {
    Io(std::io::Error),
    Utf8(Utf8Error),
    TryFromSliceError(TryFromSliceError),
    RingError(Unspecified),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Error::Utf8(value)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(value: TryFromSliceError) -> Self {
        Error::TryFromSliceError(value)
    }
}

impl From<Unspecified> for Error {
    fn from(value: Unspecified) -> Self {
        Error::RingError(value)
    }
}

fn print_if_text(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(&bytes) {
        println!("{:?}", text);
    }
}

#[rustfmt::skip]
const SSH_MSG_KEXINIT: &[u8; 160] = concat_bytes!(
    [0, 0, 0, 156],
    [11], // padding length
    [20],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [0, 0, 0, 17], b"curve25519-sha256",
    [0, 0, 0, 11], b"ssh-ed25519",
    [0, 0, 0, 10], b"aes128-ctr",
    [0, 0, 0, 10], b"aes128-ctr",
    [0, 0, 0, 13], b"hmac-sha2-256",
    [0, 0, 0, 13], b"hmac-sha2-256",
    [0, 0, 0, 4], b"none",
    [0, 0, 0, 4], b"none",
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0],
    [0, 0, 0, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], // padding
);

#[rustfmt::skip]
const SSH_MSG_KEXINIT2: &[u8; 1328] = concat_bytes!(
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
const SSH_MSG_KEX_ECDH_REPLY: &[u8; 120] = &[
    0, 0, 0, 116,
    6, // padding length
    31,
    0, 0, 0, 32,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    0, 0, 0, 32,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    0, 0, 0, 32,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    0, 1, 2, 3, 4, 5, // padding
];

pub fn serve() -> Result<(), Error> {
    let listener = TcpListener::bind("127.0.0.1:1234")?;

    let nazo = [
        115, 110, 116, 114, 117, 112, 55, 54, 49, 120, 50, 53, 53, 49, 57, 45, 115, 104, 97, 53,
        49, 50, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 99, 117, 114, 118,
        101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 44, 99, 117, 114, 118, 101, 50, 53,
        53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 64, 108, 105, 98, 115, 115, 104, 46, 111, 114,
        103, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54,
        44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 44,
        101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 44, 100,
        105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112,
        45, 101, 120, 99, 104, 97, 110, 103, 101, 45, 115, 104, 97, 50, 53, 54, 44, 100, 105, 102,
        102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 54,
        45, 115, 104, 97, 53, 49, 50, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108,
        109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 56, 45, 115, 104, 97, 53, 49, 50, 44, 100,
        105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112,
        49, 52, 45, 115, 104, 97, 50, 53, 54, 44, 101, 120, 116, 45, 105, 110, 102, 111, 45, 99,
    ];
    print_if_text(nazo.as_slice());

    let nazo = [
        115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 45, 99, 101, 114, 116, 45, 118, 48, 49,
        64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100, 115, 97, 45,
        115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 45, 99, 101, 114, 116, 45, 118,
        48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100, 115, 97,
        45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 45, 99, 101, 114, 116, 45,
        118, 48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 101, 99, 100,
        115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 45, 99, 101, 114,
        116, 45, 118, 48, 49, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 114,
        115, 97, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64,
        111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 114, 115, 97, 45, 115, 104, 97,
        50, 45, 50, 53, 54, 45, 99, 101, 114, 116, 45, 118, 48, 49, 64, 111, 112, 101, 110, 115,
        115, 104, 46, 99, 111, 109, 44, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 44, 101,
        99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 44, 101,
        99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 44, 101,
        99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 44, 114,
        115, 97, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45,
        50, 53, 54,
    ];
    print_if_text(nazo.as_slice());

    let nazo = [
        99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64, 111, 112,
        101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 49, 50, 56, 45, 99, 116, 114,
        44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44, 97, 101, 115, 50, 53, 54, 45, 99, 116,
        114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104,
        46, 99, 111, 109, 44, 97, 101, 115, 50, 53, 54, 45, 103, 99, 109, 64, 111, 112, 101, 110,
        115, 115, 104, 46, 99, 111, 109,
    ];
    print_if_text(nazo.as_slice());

    let nazo = [
        99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64, 111, 112,
        101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 49, 50, 56, 45, 99, 116, 114,
        44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44, 97, 101, 115, 50, 53, 54, 45, 99, 116,
        114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104,
        46, 99, 111, 109, 44, 97, 101, 115, 50, 53, 54, 45, 103, 99, 109, 64, 111, 112, 101, 110,
        115, 115, 104, 46, 99, 111, 109,
    ];
    print_if_text(nazo.as_slice());
    let nazo = [
        117, 109, 97, 99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46,
        99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116, 109, 64, 111, 112, 101,
        110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50,
        53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44,
        104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 101, 116, 109, 64, 111, 112,
        101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 45,
        101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97,
        99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97,
        99, 45, 49, 50, 56, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109,
        97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50,
        45, 53, 49, 50, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49,
    ];
    print_if_text(nazo.as_slice());
    let nazo = [
        117, 109, 97, 99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46,
        99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116, 109, 64, 111, 112, 101,
        110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50,
        53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44,
        104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 101, 116, 109, 64, 111, 112,
        101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 45,
        101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97,
        99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97,
        99, 45, 49, 50, 56, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109,
        97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50,
        45, 53, 49, 50, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49,
    ];
    print_if_text(nazo.as_slice());
    let nazo = [
        110, 111, 110, 101, 44, 122, 108, 105, 98, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99,
        111, 109, 44, 122, 108, 105, 98,
    ];
    print_if_text(nazo.as_slice());
    let nazo = [
        110, 111, 110, 101, 44, 122, 108, 105, 98, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99,
        111, 109, 44, 122, 108, 105, 98,
    ];
    print_if_text(nazo.as_slice());
    println!("Listening at 127.0.0.1:1234");

    for stream in listener.incoming() {
        let mut stream = stream?;
        println!("New connection from {:?}", stream.peer_addr());
        let mut buf = [0; 35036];
        let n = stream.read(&mut buf)?;
        let client_id_string = buf[..n].to_owned();
        println!("{:?}", client_id_string);
        print_if_text(&client_id_string);
        stream.write_all("SSH-2.0-NudgeHook_1.0\r\n".as_bytes())?;
        let n = stream.read(&mut buf)?;
        println!("{:?}", &buf[..n]);
        print_if_text(&buf[..n]);
        
        stream.write_all(SSH_MSG_KEXINIT2)?;
        stream.flush()?;
        let n = stream.read(&mut buf)?;
        assert_ne!(n, 0);
        println!("{:?}", &buf[..n]);
        print_if_text(&buf[..n]);
        let client_public_bytes = &buf[10..42];
        assert_eq!(client_public_bytes.len(), 32);
        println!("{:?}", client_public_bytes);
        let client_public = UnparsedPublicKey::new(&X25519, client_public_bytes);

        let mut reply = SSH_MSG_KEX_ECDH_REPLY.to_owned();
        let rng = SystemRandom::new();
        let server_secret = EphemeralPrivateKey::generate(&X25519, &rng)?;
        let server_public = server_secret.compute_public_key();
        let shared_secret = agree_ephemeral(server_secret, &client_public, Unspecified, |k| {
            println!("wohoo {:?}", k);
            Ok(k.to_vec())
        })?;

        let mut hash = vec![];
        hash.extend_from_slice(&client_id_string[..client_id_string.len()-2]);

        stream.write_all(reply.as_slice())?;
        let n = stream.read(&mut buf)?;
        println!("{:?}", &buf[..n]);
        print_if_text(&buf[..n]);
    }
    Ok(())
}

#[repr(C)]
struct Packet {
    size: u32,
    padding_length: u8,
}
