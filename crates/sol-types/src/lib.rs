use alloy_sol_types::sol;
// This has to be pure, so it can be utilized by circuit code so no RPC derive traits here.
sol!(
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Default)]
    TypeExposer,
    "../../contracts/artifacts/TypeExposer.json"
);
