use std::fs::File;

use anyhow::{Result, anyhow};
use flate2::read::GzDecoder;
use policy_evaluator::policy_fetcher::store::Store;
use tar::Archive;

// load policies inside the tarball provided by source_path into the store
pub(crate) fn load(source_path: &str, store: &Store) -> Result<()> {
    let tar_gz =
        File::open(source_path).map_err(|e| anyhow!("cannot open file {}: {}", source_path, e))?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive
        .unpack(&store.root)
        .map_err(|e| anyhow!("cannot unpack file {}: {}", source_path, e))?;

    Ok(())
}
