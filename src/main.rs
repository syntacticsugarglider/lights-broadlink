use std::net::IpAddr;

use futures::{pin_mut, StreamExt};
use lights_broadlink::discover;
use smol::block_on;

fn main() {
    block_on(async move {
        let stream = discover();
        pin_mut!(stream);
        let target_addr: IpAddr = "192.168.4.186".parse().unwrap();
        let mut light = None;
        while let Some(Ok(item)) = stream.next().await {
            if item.addr() == target_addr {
                light = Some(item);
                break;
            }
        }
        let light = light.unwrap();
        let mut connection = light.connect().await.unwrap();
        connection.set_color([255, 0, 255]).await.unwrap();
    })
}
