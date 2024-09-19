use anyhow::Result;
use ic_agent::{agent::http_transport::reqwest_transport::ReqwestHttpReplicaV2Transport, Agent};

pub async fn create_agent(url: &str) -> Result<Agent> {
    let transport = ReqwestHttpReplicaV2Transport::create(url)?;

    let agent = Agent::builder().with_transport(transport).build()?;
    agent.fetch_root_key().await?;

    Ok(agent)
}
