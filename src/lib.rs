use std::{
    borrow::{Borrow, Cow},
    collections::HashSet,
    convert::TryInto,
    fmt::Display,
    io,
    iter::repeat,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    string::FromUtf8Error,
    time::Duration,
};

use aes::Aes128;
use block_modes::{block_padding::NoPadding, BlockModeError};
use block_modes::{BlockMode, Cbc};
use rand::{thread_rng, Rng};
use smol_timeout::TimeoutExt;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

use futures::{
    future::{ready, Either},
    stream::{once, unfold},
    Stream, StreamExt,
};
use hex_literal::hex;
use serde::Serialize;
use smol::{Async, Timer};
use std::net::UdpSocket;
use thiserror::Error;

#[derive(Debug)]
struct Device {
    name: String,
    devtype: u16,
    addr: SocketAddr,
    mac: [u8; 6],
    local_addr: SocketAddr,
}

#[derive(Debug)]
pub struct Light {
    name: String,
    local_addr: SocketAddr,
    addr: SocketAddr,
    mac: [u8; 6],
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("the local address is ipv6, which is unsupported")]
    Ipv6,
    #[error("utf-8 parse error: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("AES error: {0}")]
    Aes(#[from] BlockModeError),
    #[error("bad checksum in response: expected {expected}, got {got}")]
    ChecksumError { expected: u16, got: u16 },
    #[error("response too short: expected at least 48 bytes, got {got}")]
    LengthError { got: usize },
    #[error("got error code from device: {got}")]
    DeviceError { got: BroadlinkException },
    #[error("serde error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug)]
pub enum BroadlinkException {
    DataValidationError,
    AuthorizationError,
    Unknown(i16),
}

impl Display for BroadlinkException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BroadlinkException::AuthorizationError => write!(f, "control key invalid"),
            BroadlinkException::DataValidationError => write!(f, "structure is abnormal"),
            BroadlinkException::Unknown(e) => write!(f, "unknown exception {}", e),
        }
    }
}

impl From<i16> for BroadlinkException {
    fn from(code: i16) -> Self {
        match code {
            -7 => BroadlinkException::AuthorizationError,
            -6 => BroadlinkException::DataValidationError,
            other => BroadlinkException::Unknown(other),
        }
    }
}

fn local_addr() -> Result<SocketAddrV4, Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(match socket.local_addr()? {
        SocketAddr::V6(_) => Err(Error::Ipv6)?,
        SocketAddr::V4(addr) => addr,
    })
}

struct DiscoveryPacket(SocketAddrV4);

fn sum<T: Borrow<u8>, I: IntoIterator<Item = T>>(data: I) -> u16 {
    (0xBEAF
        + data
            .into_iter()
            .map(|item| *item.borrow() as u32)
            .sum::<u32>()) as u16
}

impl DiscoveryPacket {
    fn to_buffer(&self) -> [u8; 0x30] {
        let mut packet = [0u8; 0x30];
        let addr = self.0.ip().octets();
        packet[0x18] = addr[3];
        packet[0x17] = addr[2];
        packet[0x16] = addr[1];
        packet[0x15] = addr[0];
        packet[0x1C..=0x1D].copy_from_slice(&self.0.port().to_le_bytes());
        packet[0x26] = 6;
        let sum = sum(&packet).to_le_bytes();
        packet[0x20..=0x21].copy_from_slice(&sum);
        packet
    }
}

const DEVTYPE: u16 = 0x60C8;

macro_rules! timeout {
    ($fut:expr) => {
        match $fut.timeout(Duration::from_millis(1000)).await {
            Some(value) => value,
            None => continue,
        }
    };
    ($fut:expr, $or:block) => {
        match $fut.timeout(Duration::from_millis(1000)).await {
            Some(value) => value,
            None => {
                $or;
                continue;
            }
        }
    };
}

pub fn discover() -> impl Stream<Item = Result<Light, Error>> {
    let local_addr = match local_addr() {
        Ok(addr) => addr,
        Err(e) => return Either::Left(once(ready(Err(e)))),
    };
    let socket = match UdpSocket::bind(local_addr) {
        Ok(addr) => addr,
        Err(e) => return Either::Left(once(ready(Err(e.into())))),
    };
    if let Err(e) = socket.set_broadcast(true) {
        return Either::Left(once(ready(Err(e.into()))));
    }
    let socket = match Async::new(socket) {
        Ok(addr) => addr,
        Err(e) => return Either::Left(once(ready(Err(e.into())))),
    };
    let broadcast_addr: SocketAddr = ([255, 255, 255, 255], 80).into();
    let packet = DiscoveryPacket(local_addr).to_buffer();
    Either::Right(
        unfold(
            (Some(socket), HashSet::new()),
            move |(socket, mut discovered)| async move {
                let socket = socket?;
                async {
                    socket.send_to(&packet, broadcast_addr).await?;
                    loop {
                        let mut buffer = [0u8; 1024];
                        let (_, addr) = timeout!(socket.recv_from(&mut buffer), {
                            socket.send_to(&packet, broadcast_addr).await?;
                        })?;
                        let devtype = u16::from_le_bytes(buffer[0x34..=0x35].try_into().unwrap());
                        let name = String::from_utf8(
                            buffer[0x40..]
                                .split(|item| *item == b'\x00')
                                .next()
                                .unwrap()
                                .to_vec(),
                        )?;
                        let mac = &mut buffer[0x3A..0x40];
                        mac.reverse();
                        let mac = (&*mac).try_into().unwrap();
                        if discovered.insert(addr.clone()) {
                            break Ok(Some(Device {
                                name,
                                devtype,
                                local_addr: local_addr.into(),
                                addr,
                                mac,
                            }));
                        }
                    }
                }
                .await
                .transpose()
                .map(|item| {
                    let is_err = item.is_err();
                    (
                        item,
                        if is_err {
                            (None, discovered)
                        } else {
                            (Some(socket), discovered)
                        },
                    )
                })
            },
        )
        .filter_map(|item| {
            ready(
                item.map(|device| {
                    if device.devtype != DEVTYPE {
                        return None;
                    }
                    Some(Light {
                        addr: device.addr,
                        local_addr: device.local_addr,
                        name: device.name,
                        mac: device.mac,
                    })
                })
                .transpose(),
            )
        }),
    )
}

pub struct Connection {
    addr: SocketAddr,
    id: [u8; 4],
    key: [u8; 16],
    iv: [u8; 16],
    socket: Async<UdpSocket>,
    mac: [u8; 6],
    count: u16,
}

enum Command {
    Auth,
    Control,
}

impl From<Command> for u8 {
    fn from(command: Command) -> Self {
        match command {
            Command::Auth => 0x65,
            Command::Control => 0x6A,
        }
    }
}

fn check(response: &[u8]) -> Result<(), Error> {
    let code = i16::from_le_bytes(response[0x22..=0x23].try_into().unwrap());
    if code == 0 {
        Ok(())
    } else {
        Err(Error::DeviceError { got: code.into() })
    }
}

impl Light {
    pub async fn connect(mut self) -> Result<Connection, Error> {
        self.mac.reverse();
        let mut connection = Connection {
            addr: self.addr,
            id: [0u8; 4],
            count: thread_rng().gen(),
            key: hex!("097628343fe99e23765c1513accf8b02"),
            iv: hex!("562e17996d093d28ddb3ba695a2e6f58"),
            mac: self.mac,
            socket: Async::new(UdpSocket::bind((self.local_addr.ip(), 0))?)?,
        };
        let mut payload = vec![0u8; 0x50];
        payload[0x04] = 0x31;
        payload[0x05] = 0x31;
        payload[0x06] = 0x31;
        payload[0x07] = 0x31;
        payload[0x08] = 0x31;
        payload[0x09] = 0x31;
        payload[0x0A] = 0x31;
        payload[0x0B] = 0x31;
        payload[0x0C] = 0x31;
        payload[0x0D] = 0x31;
        payload[0x0E] = 0x31;
        payload[0x0F] = 0x31;
        payload[0x10] = 0x31;
        payload[0x11] = 0x31;
        payload[0x12] = 0x31;
        payload[0x1E] = 0x01;
        payload[0x2D] = 0x01;
        payload[0x30] = b'T';
        payload[0x31] = b'e';
        payload[0x32] = b's';
        payload[0x33] = b't';
        payload[0x34] = b' ';
        payload[0x35] = b' ';
        payload[0x36] = b'1';
        let response = connection.send_packet(Command::Auth, &payload).await?;
        let payload = connection.decrypt(&response[0x38..])?;
        check(&response)?;
        connection.key = payload[0x04..0x14].try_into().unwrap();
        connection.count = u16::from_le_bytes(response[0x28..=0x29].try_into().unwrap());
        connection.id = payload[..=0x03]
            .iter()
            .rev()
            .map(|a| *a)
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap();
        Ok(connection)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn addr(&self) -> IpAddr {
        self.addr.ip()
    }
}

const HEADER: &'static [u8] = &[0x5A, 0xA5, 0xAA, 0x55, 0x5A, 0xA5, 0xAA, 0x55];
const DEVTYPE_BYTES: &'static [u8] = &DEVTYPE.to_le_bytes();
const MESSAGE_HEADER: &'static [u8] = &[0xA5, 0xA5, 0x5A, 0x5A];

#[derive(Serialize)]
struct PowerMessage {
    pwr: u8,
}

#[derive(Serialize)]
struct RgbMessage {
    bulb_colormode: u8,
    red: u8,
    green: u8,
    blue: u8,
}

#[derive(Serialize)]
struct WhiteMessage {
    bulb_colormode: u8,
}

#[derive(Serialize)]
struct BrightnessMessage {
    brightness: u8,
}

#[derive(Serialize)]
struct TransitionDurationMessage {
    transitionduration: u16,
}

#[derive(Clone, Copy)]
pub enum Color {
    White,
    Rgb { red: u8, green: u8, blue: u8 },
}

fn encode_message<T: Serialize>(data: &T, flag: u8) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_string(data)?;
    let mut message = vec![0u8; 14];
    let len = (12 + json.len()) as u16;
    message[..=0x01].copy_from_slice(&len.to_le_bytes());
    message[0x02..=0x05].copy_from_slice(MESSAGE_HEADER);
    message[0x08] = flag;
    message[0x09] = 0x0B;
    message[0x0A..=0x0D].copy_from_slice(&(json.len() as u32).to_le_bytes());
    message.extend(json.as_bytes());
    let checksum = message[0x08..].iter().map(|item| *item as u16).sum::<u16>() + 0xc0ad;
    message[0x06..=0x07].copy_from_slice(&checksum.to_le_bytes());
    Ok(message)
}

impl Connection {
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Aes128Cbc::new_var(&self.key, &self.iv).unwrap();
        let mut buffer = data.to_vec();
        cipher.decrypt(&mut buffer)?;
        Ok(buffer)
    }
    async fn send_packet(&mut self, command: Command, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0u8; 0x38];

        self.count = self.count.wrapping_add(1);

        packet[..HEADER.len()].copy_from_slice(HEADER);
        packet[0x24..=0x25].copy_from_slice(DEVTYPE_BYTES);
        packet[0x26] = command.into();
        packet[0x28..=0x29].copy_from_slice(&self.count.to_le_bytes());
        packet[0x2A..0x2A + self.mac.len()].copy_from_slice(&self.mac);
        packet[0x30..0x30 + self.id.len()].copy_from_slice(&self.id);

        let padding = (16 - payload.len() as isize).rem_euclid(16);
        let mut payload = Cow::from(payload);
        if padding != 0 {
            payload.to_mut().extend(repeat(0).take(padding as usize));
        }

        packet[0x34..=0x35].copy_from_slice(&sum(payload.as_ref()).to_le_bytes());

        let cipher = Aes128Cbc::new_var(&self.key, &self.iv).unwrap();
        let len = payload.len();
        let ciphertext = cipher.encrypt(payload.to_mut(), len)?;
        packet.extend(ciphertext);

        let packet_sum = sum(&packet).to_le_bytes();
        packet[0x20..=0x21].copy_from_slice(&packet_sum);
        let mut response = vec![0u8; 2048];

        let (len, _) = loop {
            self.socket.send_to(&packet, self.addr).await?;
            break timeout!(self.socket.recv_from(&mut response))?;
        };

        response.truncate(len);
        if len < 0x30 {
            Err(Error::LengthError { got: len })?;
        }

        let checksum = u16::from_le_bytes(response[0x20..=0x21].try_into().unwrap());
        let new_sum = sum(&response) - response[0x20] as u16 - response[0x21] as u16;
        if checksum != new_sum {
            Err(Error::ChecksumError {
                expected: new_sum,
                got: checksum,
            })?;
        }
        Ok(response)
    }
    pub async fn turn_off(&mut self) -> Result<(), Error> {
        let response = self
            .send_packet(
                Command::Control,
                &encode_message(&PowerMessage { pwr: 0 }, 2)?,
            )
            .await?;
        check(&response)?;
        Ok(())
    }
    pub async fn turn_on(&mut self) -> Result<(), Error> {
        let response = self
            .send_packet(
                Command::Control,
                &encode_message(&PowerMessage { pwr: 1 }, 2)?,
            )
            .await?;
        check(&response)?;
        Ok(())
    }
    pub async fn set_transition_duration(&mut self, duration: u32) -> Result<(), Error> {
        let response = self
            .send_packet(
                Command::Control,
                &encode_message(
                    &TransitionDurationMessage {
                        transitionduration: duration as u16,
                    },
                    2,
                )?,
            )
            .await?;
        check(&response)?;
        Ok(())
    }
    pub async fn set_brightness(&mut self, brightness: u8) -> Result<(), Error> {
        let response = self
            .send_packet(
                Command::Control,
                &encode_message(
                    &BrightnessMessage {
                        brightness: ((brightness as f32 / 255.) * 100.) as u8,
                    },
                    2,
                )?,
            )
            .await?;
        check(&response)?;
        Ok(())
    }
    pub async fn set_color(&mut self, color: Color) -> Result<(), Error> {
        let response = self
            .send_packet(
                Command::Control,
                &match color {
                    Color::Rgb { red, green, blue } => encode_message(
                        &RgbMessage {
                            red,
                            green,
                            blue,
                            bulb_colormode: 0,
                        },
                        2,
                    ),
                    Color::White => encode_message(&WhiteMessage { bulb_colormode: 1 }, 2),
                }?,
            )
            .await?;
        check(&response)?;
        Ok(())
    }
}
