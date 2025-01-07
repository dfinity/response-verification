use anyhow::Result;
use ic_agent::Agent;

pub async fn create_agent(url: &str) -> Result<Agent> {
    let agent = Agent::builder().with_url(url).build()?;
    agent.fetch_root_key().await?;

    Ok(agent)
}
