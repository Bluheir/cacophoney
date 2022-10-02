use async_trait::async_trait;

use crate::data::{crypto::PubKey, SubAccount};

#[async_trait]
pub trait DbApi {
    // TODO add error type
    async fn get_subaccounts(&mut self, key: &PubKey) -> Result<Vec<SubAccount>, ()>;
}
pub struct EmptyDb {}

#[async_trait]
impl DbApi for EmptyDb {
    async fn get_subaccounts(&mut self, _key: &PubKey) -> Result<Vec<SubAccount>, ()> {
        Err(())
    }
}
