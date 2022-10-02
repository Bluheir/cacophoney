use std::{error::Error, sync::Arc};

use futures::{channel::mpsc, StreamExt};
use quinn::{Endpoint, NewConnection, ServerConfig};

use crate::{
    config::Configuration,
    db::{DbApi, EmptyDb},
    helpers::ip::parse_ip,
};

use super::client::handle_connection;

pub async fn start_empty(conf: Arc<Configuration>, server_config: ServerConfig) {
    let mut node = NodeService::new(conf, EmptyDb {});

    let _ = node.server(server_config).await;
}

/// Represents a QUIC node service running
pub struct NodeService<T> {
    /// Configuration for the node service
    config: Arc<Configuration>,
    /// Database manager for the node
    db: T,
}

impl<T> NodeService<T> {
    pub fn new(config: Arc<Configuration>, db: T) -> Self {
        Self { config, db }
    }
}

impl<T: DbApi> NodeService<T> {
    pub async fn server(&mut self, server_config: ServerConfig) -> Result<(), Box<dyn Error>> {
        let addr = parse_ip(&self.config.quic.address, self.config.quic.port)?;

        let (_endpoint, mut incoming) = Endpoint::server(server_config, addr)?;

        // TODO: Make database request API. Right now, no messages or other data will be stored
        let (_db_send, _db_recv) = mpsc::unbounded::<String>();

        while let Some(conn) = incoming.next().await {
            let connection: NewConnection = conn.await?;

            // Handle a new connection
            tokio::spawn(async move {
                let _ = handle_connection(connection).await;
            });
        }

        return Ok(());
    }
}
