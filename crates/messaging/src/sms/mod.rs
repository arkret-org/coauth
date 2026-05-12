//! SMS transport and sending for coauth authentication service.

mod aliyun;
mod sender;
mod tencent;
mod transport;

pub use self::{
    aliyun::AliyunSmsTransport,
    sender::SmsSender,
    tencent::TencentSmsTransport,
    transport::{SmsTransport, SmsTransportError},
};
