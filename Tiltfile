tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

# Create the kubewarden namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("kubewarden")

# Install the unified Kubewarden admission controller chart
registry = settings.get("registry")
controller_image = settings.get("controller").get("image")
audit_scanner_image = settings.get("audit-scanner").get("image")
policy_server_image = settings.get("policy-server").get("image")

update_settings(
    k8s_upsert_timeout_secs=300,
    suppress_unused_image_warnings=[registry + "/" + policy_server_image],
)

kubewarden_yaml = helm(
    "./charts/admission-controller",
    name="kubewarden",
    namespace="kubewarden",
    set=[
        # The image references below already contain the registry,
        # so the chart must not add its own registry.
        "controller.image.registry=",
        "auditScanner.image.registry=",
        "policyServer.image.registry=",
        "controller.image.repository=" + registry + "/" + controller_image,
        "replicas=1",
        "logLevel=debug",
        "podSecurityContext=null",
        "containerSecurityContext=null",
        "auditScanner.image.repository=" + registry + "/" + audit_scanner_image,
        "auditScanner.logLevel=debug",
        "policyServer.enabled=true",
        "policyServer.image.repository=" + registry + "/" + policy_server_image,
        "policyServer.env[0].name=KUBEWARDEN_LOG_LEVEL",
        "policyServer.env[0].value=debug",
        "recommendedPolicies.defaultPoliciesRegistry=" + registry,
    ],
)
k8s_yaml(kubewarden_yaml)

# Group all CRDs under a single resource name for dependency tracking
k8s_resource(
    new_name='kubewarden-crds',
    objects=[
        'policyservers.policies.kubewarden.io:CustomResourceDefinition',
        'admissionpolicies.policies.kubewarden.io:CustomResourceDefinition',
        'clusteradmissionpolicies.policies.kubewarden.io:CustomResourceDefinition',
        'admissionpolicygroups.policies.kubewarden.io:CustomResourceDefinition',
        'clusteradmissionpolicygroups.policies.kubewarden.io:CustomResourceDefinition',
    ],
)

# Wait for controller deployment to be ready
# Object name comes from the fullname helper: <release>-<chart> = kubewarden-admission-controller.
# new_name is just the Tilt UI label and is kept stable for dependency references.
k8s_resource(
    'kubewarden-admission-controller',
    new_name='kubewarden-controller',
    resource_deps=['kubewarden-crds'],
)

# Tell tilt about the image used by the PolicyServer CRD
# so that it can update it when needed
k8s_kind("PolicyServer", image_json_path='{.spec.image}')


# Hot reloading containers
local_resource(
    "controller_tilt",
    "make controller",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/controller",
        "api",
        "internal/certs",
        "internal/constants",
        "internal/controller",
        "internal/featuregates",
        "internal/metrics",
    ],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    registry + "/" + controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/controller",
    ],
    live_update=[
        sync("./bin/controller", "/controller"),
    ],
)

local_resource(
    "audit_scanner_tilt",
    "make audit-scanner",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/audit-scanner",
        "api",
        "internal/audit-scanner",
        "internal/constants",
    ],
)

# We use a specific Dockerfile since tilt can't run on a scratch container.
dockerfile = "./hack/Dockerfile.audit-scanner.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build(
    registry + "/" + audit_scanner_image,
    ".",
    dockerfile=dockerfile,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/audit-scanner",
    ],
)


local_resource(
    "policy_server_tilt",
    "make policy-server",
    deps=[
        "Cargo.toml",
        "Cargo.lock",
        "crates/burrego",
        "crates/policy-evaluator",
        "crates/policy-fetcher",
        "crates/policy-server",
    ],
)

dockerfile = "./hack/Dockerfile.policy-server.tilt"

# Note: Using docker_build instead of docker_build_with_restart because PolicyServer
# is a CRD and Tilt cannot inject restart wrappers into CRD-managed containers
# Instead, we trigger a restart by updating the PolicyServer `.spec.annotation`
docker_build(
    registry + "/" + policy_server_image,
    ".",
    dockerfile=dockerfile,
    only=[
        "./bin/policy-server",
    ],
)

# Trigger PolicyServer pod restart by updating annotations when image changes
# The default PolicyServer is created by the controller from the defaults ConfigMap,
# so we depend on the controller being ready before patching.
local_resource(
    "restart_policy_server",
    "kubectl get policyserver default >/dev/null 2>&1 && kubectl patch policyserver default --type=merge -p '{\"spec\":{\"annotations\":{\"restart\":\"'$(date +%s)'\"}}}'  || true",
    resource_deps=["kubewarden-controller"],
    trigger_mode=TRIGGER_MODE_AUTO,
)
