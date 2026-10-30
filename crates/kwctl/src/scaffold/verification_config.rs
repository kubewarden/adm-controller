use anyhow::Result;
use policy_evaluator::policy_fetcher::verify::config::{
    LatestVerificationConfig, Signature, VersionedVerificationConfig,
};

pub(crate) fn verification_config() -> Result<String> {
    let mut comment_header = r#"# Default Kubewarden verification config
#
# With this config, the only valid policies are those signed by Kubewarden
# infrastructure.
#
# This config can be saved to its default location (for this OS) with:
#   kwctl scaffold verification-config > "#
        .to_string();

    comment_header.push_str(
        crate::KWCTL_DEFAULT_VERIFICATION_CONFIG_PATH
            .to_owned()
            .as_str(),
    );
    comment_header.push_str(
        r#"
#
# Providing a config in the default location enables Sigstore verification.
# See https://docs.kubewarden.io/admission-controller/latest/en/howtos/security-hardening/secure-supply-chain.html
# for more Sigstore verification options."#,
    );

    let kubewarden_verification_config =
        VersionedVerificationConfig::V1(LatestVerificationConfig {
            all_of: Some(vec![Signature::GithubAction {
                owner: "kubewarden".to_string(),
                repo: None,
                annotations: None,
            }]),
            any_of: None,
        });

    Ok(format!(
        "{}\n{}",
        comment_header,
        serde_yaml::to_string(&kubewarden_verification_config)?
    ))
}
