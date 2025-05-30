# Coding Style Notes
- Any non trivial task should be spawned with a JoinSet managed by the caller. 
- The closure passed to the JoinSet should always be a single function call to a function that returns the crate Result Type. (eyre::Result/anyhow::Result etc)

