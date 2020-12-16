use std::net::IpAddr;

use futures::{pin_mut, StreamExt, TryStreamExt};
use lights_broadlink::discover;
use smol::block_on;

fn main() {
    block_on(async move {
        let stream = discover();
        pin_mut!(stream);

        let mut lights: Vec<_> = stream
            .and_then(|light| async move {
                let mut connection = light.connect().await.unwrap();
                connection.set_transition_duration(0).await.unwrap();
                Ok(connection)
            })
            .take(4)
            .try_collect()
            .await
            .unwrap();

        loop {
            for light in &mut lights {
                light.turn_on().await.unwrap();
            }
            for light in &mut lights {
                light.turn_off().await.unwrap();
            }
        }
    })
}
