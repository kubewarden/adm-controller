use std::fs::File;

use anyhow::{Result, anyhow};
use flate2::{Compression, write::GzEncoder};
use policy_evaluator::policy_fetcher::store::{PolicyPath, Store};

// saves all policies in a tarball with the name provided as output.
// policies must be inside the default store.
pub(crate) fn save(policies: Vec<&String>, output: &str, store: &Store) -> Result<()> {
    let tar_gz =
        File::create(output).map_err(|e| anyhow!("cannot create file {}: {}", output, e))?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    for policy in policies {
        let uri = crate::utils::map_path_to_uri(policy.as_str(), store)?;
        let wasm_path = crate::utils::wasm_path(&uri, store)
            .map_err(|e| anyhow!("cannot find policy {}: {}", policy, e))?;
        let mut file = File::open(wasm_path)
            .map_err(|e| anyhow!("cannot open policy file {}: {}", policy, e))?;
        let policy_path = store
            .policy_path(&uri, PolicyPath::PrefixAndFilename)
            .map_err(|e| anyhow!("cannot find path for policy {}: {}", policy, e))?;
        tar.append_file(policy_path, &mut file)
            .map_err(|e| anyhow!("cannot append policy {} to tar file: {}", policy, e))?;
    }

    Ok(())
}
