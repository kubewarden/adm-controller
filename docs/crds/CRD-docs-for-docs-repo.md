# API Reference

## Packages
- [policies.kubewarden.io/v1](#policieskubewardeniov1)
- [policies.kubewarden.io/v1alpha2](#policieskubewardeniov1alpha2)


## policies.kubewarden.io/v1

Package v1 contains API Schema definitions for the policies v1 API group

### Resource Types
- [AdmissionPolicy](#admissionpolicy)
- [AdmissionPolicyGroup](#admissionpolicygroup)
- [AdmissionPolicyGroupList](#admissionpolicygrouplist)
- [AdmissionPolicyList](#admissionpolicylist)
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)
- [ClusterAdmissionPolicyGroup](#clusteradmissionpolicygroup)
- [ClusterAdmissionPolicyGroupList](#clusteradmissionpolicygrouplist)
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)
- [PolicyServer](#policyserver)
- [PolicyServerList](#policyserverlist)



#### AdmissionPolicy



AdmissionPolicy is the Schema for the admissionpolicies API



_Appears in:_
- [AdmissionPolicyList](#admissionpolicylist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`AdmissionPolicy`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[AdmissionPolicySpec](#admissionpolicyspec)_






#### AdmissionPolicyGroup



AdmissionPolicyGroup is the Schema for the AdmissionPolicyGroups API



_Appears in:_
- [AdmissionPolicyGroupList](#admissionpolicygrouplist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`AdmissionPolicyGroup`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[AdmissionPolicyGroupSpec](#admissionpolicygroupspec)_






#### AdmissionPolicyGroupList



AdmissionPolicyGroupList contains a list of AdmissionPolicyGroup.





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`AdmissionPolicyGroupList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[AdmissionPolicyGroup](#admissionpolicygroup) array_




#### AdmissionPolicyGroupSpec



AdmissionPolicyGroupSpec defines the desired state of AdmissionPolicyGroup.



_Appears in:_
- [AdmissionPolicyGroup](#admissionpolicygroup)

##### `PolicyGroupSpec`

**Type:** _[PolicyGroupSpec](#policygroupspec)_




#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy.





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`AdmissionPolicyList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[AdmissionPolicy](#admissionpolicy) array_




#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy.



_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

##### `PolicySpec`

**Type:** _[PolicySpec](#policyspec)_




#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicy`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_






#### ClusterAdmissionPolicyGroup



ClusterAdmissionPolicyGroup is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyGroupList](#clusteradmissionpolicygrouplist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicyGroup`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[ClusterAdmissionPolicyGroupSpec](#clusteradmissionpolicygroupspec)_






#### ClusterAdmissionPolicyGroupList



ClusterAdmissionPolicyGroupList contains a list of ClusterAdmissionPolicyGroup





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicyGroupList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[ClusterAdmissionPolicyGroup](#clusteradmissionpolicygroup) array_




#### ClusterAdmissionPolicyGroupSpec



ClusterAdmissionPolicyGroupSpec defines the desired state of ClusterAdmissionPolicyGroup.



_Appears in:_
- [ClusterAdmissionPolicyGroup](#clusteradmissionpolicygroup)

##### `ClusterPolicyGroupSpec`

**Type:** _[ClusterPolicyGroupSpec](#clusterpolicygroupspec)_


##### `namespaceSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

NamespaceSelector decides whether to run the webhook on an object based
on whether the namespace for that object matches the selector. If the
object itself is a namespace, the matching is performed on
object.metadata.labels. If the object is another cluster scoped resource,
it never skips the webhook.

For example, to run the webhook on objects whose namespace does not have
a runlevel of 0 or 1, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "runlevel",
        "operator": "NotIn",
        "values": ["0", "1"]
      }
    ]
  }
}
```

To run the webhook only on objects whose namespace has an environment of
prod or staging, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "environment",
        "operator": "In",
        "values": ["prod", "staging"]
      }
    ]
  }
}
```

See
https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
for more examples of label selectors.

Default to the empty LabelSelector, which matches everything.
##### `allowInsideAdmissionControllerNamespace`

**Type:** _boolean_

**Validation:**
- Optional: \{\}

AllowInsideAdmissionControllerNamespace controls whether the policy should also be
evaluated for resources in the namespace where Kubewarden is deployed.
By default (false), an exclusion rule is added to the webhook so that the
Kubewarden namespace is never targeted, protecting against an accidental
lockout. Set this to true only if you deliberately want the policy to apply
inside the Kubewarden namespace.
Warning: setting this to true may cause a deadlock if the policy prevents
Kubewarden components from starting.


#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicyList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_




#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy.



_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

##### `PolicySpec`

**Type:** _[PolicySpec](#policyspec)_


##### `namespaceSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

NamespaceSelector decides whether to run the webhook on an object based
on whether the namespace for that object matches the selector. If the
object itself is a namespace, the matching is performed on
object.metadata.labels. If the object is another cluster scoped resource,
it never skips the webhook.

For example, to run the webhook on objects whose namespace does not have
a runlevel of 0 or 1, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "runlevel",
        "operator": "NotIn",
        "values": ["0", "1"]
      }
    ]
  }
}
```

To run the webhook only on objects whose namespace has an environment of
prod or staging, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "environment",
        "operator": "In",
        "values": ["prod", "staging"]
      }
    ]
  }
}
```

See
https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
for more examples of label selectors.

Default to the empty LabelSelector, which matches everything.
##### `contextAwareResources`

**Type:** _[ContextAwareResource](#contextawareresource) array_

**Validation:**
- Optional: \{\}

List of Kubernetes resources the policy is allowed to access at evaluation time.
Access to these resources is done using the `ServiceAccount` of the PolicyServer
the policy is assigned to.
##### `allowInsideAdmissionControllerNamespace`

**Type:** _boolean_

**Validation:**
- Optional: \{\}

AllowInsideAdmissionControllerNamespace controls whether the policy should also be
evaluated for resources in the namespace where Kubewarden is deployed.
By default (false), an exclusion rule is added to the webhook so that the
Kubewarden namespace is never targeted, protecting against an accidental
lockout. Set this to true only if you deliberately want the policy to apply
inside the Kubewarden namespace.
Warning: setting this to true may cause a deadlock if the policy prevents
Kubewarden components from starting.


#### ClusterPolicyGroupSpec







_Appears in:_
- [ClusterAdmissionPolicyGroupSpec](#clusteradmissionpolicygroupspec)

##### `GroupSpec`

**Type:** _[GroupSpec](#groupspec)_


##### `policies`

**Type:** _[PolicyGroupMembersWithContext](#policygroupmemberswithcontext)_

**Validation:**
- Required: \{\}

Policies is a list of policies that are part of the group that will
be available to be called in the evaluation expression field.
Each policy in the group should be a Kubewarden policy.


#### ContextAwareResource



ContextAwareResource identifies a Kubernetes resource.



_Appears in:_
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)
- [PolicyGroupMemberWithContext](#policygroupmemberwithcontext)

##### `apiVersion`

**Type:** _string_

apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
##### `kind`

**Type:** _string_

Singular PascalCase name of the resource


#### GroupSpec







_Appears in:_
- [ClusterPolicyGroupSpec](#clusterpolicygroupspec)
- [PolicyGroupSpec](#policygroupspec)

##### `policyServer`

**Type:** _string_

**Default:** default

**Validation:**
- Optional: \{\}

PolicyServer identifies an existing PolicyServer resource.
##### `mode`

**Type:** _[PolicyMode](#policymode)_

**Default:** protect

**Validation:**
- Enum: [protect monitor]
- Optional: \{\}

Mode defines the execution mode of this policy. Can be set to
either "protect" or "monitor". If it's empty, it is defaulted to
"protect".
Transitioning this setting from "monitor" to "protect" is
allowed, but is disallowed to transition from "protect" to
"monitor". To perform this transition, the policy should be
recreated in "monitor" mode instead.
##### `rules`

**Type:** _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_

Rules describes what operations on what resources/subresources the webhook cares about.
The webhook cares about an operation if it matches _any_ Rule.
##### `failurePolicy`

**Type:** _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

FailurePolicy defines how unrecognized errors and timeout errors from the
policy are handled. Allowed values are "Ignore" or "Fail".
* "Ignore" means that an error calling the webhook is ignored and the API
  request is allowed to continue.
* "Fail" means that an error calling the webhook causes the admission to
  fail and the API request to be rejected.
The default behaviour is "Fail"
##### `backgroundAudit`

**Type:** _boolean_

**Default:** true

**Validation:**
- Optional: \{\}

BackgroundAudit indicates whether a policy should be used or skipped when
performing audit checks. If false, the policy cannot produce meaningful
evaluation results during audit checks and will be skipped.
The default is "true".
##### `matchPolicy`

**Type:** _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

matchPolicy defines how the "rules" list is used to match incoming requests.
Allowed values are "Exact" or "Equivalent".

* `Exact`: Match a request only if it exactly matches a specified rule.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
* `Equivalent`: Match a request that modifies a listed resource through an equivalent API group or version.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.

Defaults to "Equivalent"
##### `matchConditions`

**Type:** _[MatchCondition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchcondition-v1-admissionregistration) array_

**Validation:**
- Optional: \{\}

MatchConditions are a list of conditions that must be met for a request to be
validated. Match conditions filter requests that have already been matched by
the rules, namespaceSelector, and objectSelector. An empty list of
matchConditions matches all requests. There are a maximum of 64 match
conditions allowed. If a parameter object is provided, it can be accessed via
the `params` handle in the same manner as validation expressions. The exact
matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,
the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy
is evaluated. 3. If any matchCondition evaluates to an error (but none are
FALSE): - If failurePolicy=Fail, reject the request - If
failurePolicy=Ignore, the policy is skipped.
Only available if the feature gate AdmissionWebhookMatchConditions is enabled.
##### `objectSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

ObjectSelector decides whether to run the webhook based on if the
object has matching labels. objectSelector is evaluated against both
the oldObject and newObject that would be sent to the webhook, and
is considered to match if either object matches the selector. A null
object (oldObject in the case of create, or newObject in the case of
delete) or an object that cannot have labels (like a
DeploymentRollback or a PodProxyOptions object) is not considered to
match.
Use the object selector only if the webhook is opt-in, because end
users may skip the admission webhook by setting the labels.
Default to the empty LabelSelector, which matches everything.
##### `sideEffects`

**Type:** _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_

SideEffects states whether this webhook has side effects.
Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
Webhooks with side effects MUST implement a reconciliation system, since a request may be
rejected by a future step in the admission change and the side effects therefore need to be undone.
Requests with the dryRun attribute will be auto-rejected if they match a webhook with
sideEffects == Unknown or Some.
##### `timeoutSeconds`

**Type:** _integer_

**Default:** 10

**Validation:**
- Maximum: 30
- Minimum: 2
- Optional: \{\}

TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
the webhook call will be ignored or the API call will fail based on the
failure policy.
The timeout value must be between 2 and 30 seconds.
Default to 10 seconds.
##### `expression`

**Type:** _string_

**Validation:**
- Required: \{\}

Expression is the evaluation expression to accept or reject the
admission request under evaluation. This field uses CEL as the
expression language for the policy groups. Each policy in the group
will be represented as a function call in the expression with the
same name as the policy defined in the group. The expression field
should be a valid CEL expression that evaluates to a boolean value.
If the expression evaluates to true, the group policy will be
considered as accepted, otherwise, it will be considered as
rejected. This expression allows grouping policies calls and perform
logical operations on the results of the policies. See Kubewarden
documentation to learn about all the features available.
##### `message`

**Type:** _string_

**Validation:**
- Required: \{\}

Message is  used to specify the message that will be returned when
the policy group is rejected. The specific policy results will be
returned in the warning field of the response.
















#### PolicyGroupMember







_Appears in:_
- [PolicyGroupMemberWithContext](#policygroupmemberwithcontext)
- [PolicyGroupMembers](#policygroupmembers)

##### `module`

**Type:** _string_

**Validation:**
- Required: \{\}

Module is the location of the WASM module to be loaded. Can be a
local file (file://), a remote file served by an HTTP server
(http://, https://), or an artifact served by an OCI-compatible
registry (registry://).
If prefix is missing, it will default to registry:// and use that
internally.
##### `settings`

**Type:** _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_

**Validation:**
- Optional: \{\}

Settings is a free-form object that contains the policy configuration
values.
x-kubernetes-embedded-resource: false
##### `timeoutEvalSeconds`

**Type:** _integer_

**Validation:**
- Maximum: 30
- Minimum: 2
- Optional: \{\}

TimeoutEvalSeconds specifies the timeout for the policy evaluation. After
the timeout passes, the policy evaluation call will fail based on the
failure policy.
The timeout value must be between 2 and 30 seconds.


#### PolicyGroupMemberWithContext







_Appears in:_
- [PolicyGroupMembersWithContext](#policygroupmemberswithcontext)

##### `PolicyGroupMember`

**Type:** _[PolicyGroupMember](#policygroupmember)_


##### `contextAwareResources`

**Type:** _[ContextAwareResource](#contextawareresource) array_

**Validation:**
- Optional: \{\}

List of Kubernetes resources the policy is allowed to access at evaluation time.
Access to these resources is done using the `ServiceAccount` of the PolicyServer
the policy is assigned to.


#### PolicyGroupMembers

_Underlying type:_ _[map[string]PolicyGroupMember](#map[string]policygroupmember)_





_Appears in:_
- [PolicyGroupSpec](#policygroupspec)



#### PolicyGroupMembersWithContext

_Underlying type:_ _[map[string]PolicyGroupMemberWithContext](#map[string]policygroupmemberwithcontext)_





_Appears in:_
- [ClusterPolicyGroupSpec](#clusterpolicygroupspec)



#### PolicyGroupSpec







_Appears in:_
- [AdmissionPolicyGroupSpec](#admissionpolicygroupspec)

##### `GroupSpec`

**Type:** _[GroupSpec](#groupspec)_


##### `policies`

**Type:** _[PolicyGroupMembers](#policygroupmembers)_

**Validation:**
- Required: \{\}

Policies is a list of policies that are part of the group that will
be available to be called in the evaluation expression field.
Each policy in the group should be a Kubewarden policy.






#### PolicyMode

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor]

_Appears in:_
- [GroupSpec](#groupspec)
- [PolicySpec](#policyspec)



#### PolicyModeStatus

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor unknown]

_Appears in:_

| Field | Description |
| --- | --- |
| `protect` |  |
| `monitor` |  |
| `unknown` |  |




#### PolicyServer



PolicyServer is the Schema for the policyservers API.



_Appears in:_
- [PolicyServerList](#policyserverlist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`PolicyServer`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[PolicyServerSpec](#policyserverspec)_








#### PolicyServerList



PolicyServerList contains a list of PolicyServer.





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1`

##### `kind`

**Type:** _string_

`PolicyServerList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[PolicyServer](#policyserver) array_




#### PolicyServerSecurity



PolicyServerSecurity defines securityContext configuration to be used in the Policy Server workload.



_Appears in:_
- [PolicyServerSpec](#policyserverspec)

##### `container`

**Type:** _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#securitycontext-v1-core)_

**Validation:**
- Optional: \{\}

securityContext definition to be used in the policy server container
##### `pod`

**Type:** _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#podsecuritycontext-v1-core)_

**Validation:**
- Optional: \{\}

podSecurityContext definition to be used in the policy server Pod


#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer.



_Appears in:_
- [PolicyServer](#policyserver)

##### `image`

**Type:** _string_

Docker image name.
##### `replicas`

**Type:** _integer_

Replicas is the number of desired replicas.
##### `minAvailable`

**Type:** _[IntOrString](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#intorstring-intstr-util)_

Number of policy server replicas that must be still available after the
eviction. The value can be an absolute number or a percentage. Only one of
MinAvailable or Max MaxUnavailable can be set.
##### `maxUnavailable`

**Type:** _[IntOrString](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#intorstring-intstr-util)_

Number of policy server replicas that can be unavailable after the
eviction. The value can be an absolute number or a percentage. Only one of
MinAvailable or Max MaxUnavailable can be set.
##### `annotations`

**Type:** _object (keys:string, values:string)_

**Validation:**
- Optional: \{\}

Annotations is an unstructured key value map stored with a resource that may be
set by external tools to store and retrieve arbitrary metadata. They are not
queryable and should be preserved when modifying objects.
More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/
##### `labels`

**Type:** _object (keys:string, values:string)_

**Validation:**
- Optional: \{\}

Labels is a map of custom labels to be applied to the Deployment created by the
PolicyServer and to the Pods managed by that Deployment. System labels set by
the controller always take precedence over user-defined labels with the same key.
More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
##### `env`

**Type:** _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#envvar-v1-core) array_

**Validation:**
- Optional: \{\}

List of environment variables to set in the container.
##### `serviceAccountName`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of the service account associated with the policy server.
Namespace service account will be used if not specified.
##### `imagePullSecret`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of ImagePullSecret secret in the same namespace, used for pulling
policies from repositories.
##### `insecureSources`

**Type:** _string array_

**Validation:**
- Optional: \{\}

List of insecure URIs to policy repositories. The `insecureSources`
content format corresponds with the contents of the `insecure_sources`
key in `sources.yaml`. Reference for `sources.yaml` is found in the
Kubewarden documentation in the reference section.
##### `sourceAuthorities`

**Type:** _object (keys:string, values:string array)_

**Validation:**
- Optional: \{\}

Key value map of registry URIs endpoints to a list of their associated
PEM encoded certificate authorities that have to be used to verify the
certificate used by the endpoint. The `sourceAuthorities` content format
corresponds with the contents of the `source_authorities` key in
`sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden
documentation in the reference section.
##### `verificationConfig`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of VerificationConfig configmap in the kubewarden namespace (same
namespace as the controller deployment), containing Sigstore verification
configuration. The configuration must be under a key named
verification-config in the ConfigMap.
##### `sigstoreTrustConfig`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of SigstoreTrustConfig configmap in the kubewarden namespace (same
namespace as the controller deployment), containing Sigstore trust
configuration (ClientTrustConfig JSON). The configuration must be under a
key named sigstore-trust-config in the ConfigMap. This is used to configure
a custom Sigstore instance instead of the default public Sigstore infrastructure.
WARNING: This feature requires strict access control. Users with write access
to this ConfigMap can influence policy signature verification.
##### `securityContexts`

**Type:** _[PolicyServerSecurity](#policyserversecurity)_

**Validation:**
- Optional: \{\}

Security configuration to be used in the Policy Server workload.
The field allows different configurations for the pod and containers.
If set for the containers, this configuration will not be used in
containers added by other controllers (e.g. telemetry sidecars)
##### `affinity`

**Type:** _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#affinity-v1-core)_

**Validation:**
- Optional: \{\}

Affinity rules for the associated Policy Server pods.
##### `limits`

**Type:** _[ResourceList](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#resourcelist-v1-core)_

**Validation:**
- Optional: \{\}

Limits describes the maximum amount of compute resources allowed.
##### `requests`

**Type:** _[ResourceList](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#resourcelist-v1-core)_

**Validation:**
- Optional: \{\}

Requests describes the minimum amount of compute resources required.
If Request is omitted for, it defaults to Limits if that is explicitly specified,
otherwise to an implementation-defined value
##### `tolerations`

**Type:** _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#toleration-v1-core) array_

Tolerations describe the policy server pod's tolerations. It can be
used to ensure that the policy server pod is not scheduled onto a
node with a taint.
##### `priorityClassName`

**Type:** _string_

**Validation:**
- Optional: \{\}

PriorityClassName is the name of the PriorityClass to be used for the
policy server pods. Useful to schedule policy server pods with higher
priority to ensure their availability over other cluster workload
resources.
Note: If the referenced PriorityClass is deleted, existing pods
remain unchanged, but new pods that reference it cannot be created.
##### `namespacedPoliciesCapabilities`

**Type:** _string array_

**Validation:**
- Optional: \{\}

NamespacedPoliciesCapabilities lists host capability API calls allowed
for namespaced policies running on this PolicyServer. When not set,
all host capabilities are granted to namespaced policies.
Supported wildcard patterns:
- "*": allow all host capabilities
- "category/*": allow all capabilities in a category (e.g. "oci/*")
- "category/version/*": allow all capabilities of a specific version (e.g. "oci/v1/*")
- Specific capability paths (e.g. "oci/v1/verify", "net/v1/dns_lookup_host")
##### `webhookPort`

**Type:** _integer_

**Validation:**
- Maximum: 65535
- Minimum: 1
- Optional: \{\}

Port where the policy server listens for incoming webhook requests.
When unset, defaults to 8443. This is the port the Kubernetes API server
reaches when evaluating admission requests.
##### `readinessProbePort`

**Type:** _integer_

**Validation:**
- Maximum: 65535
- Minimum: 1
- Optional: \{\}

Port used by the policy server to expose the readiness probe endpoint.
When unset, defaults to 8081.
##### `metricsPort`

**Type:** _integer_

**Validation:**
- Maximum: 65535
- Minimum: 1
- Optional: \{\}

Port exposed by the metrics Service for this policy server.
When unset, defaults to the controller-wide default
(KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT env var, or 8080).
Only relevant when metrics are enabled.

Use this field to customize which port Prometheus scrapes for this
PolicyServer's metrics Service (e.g. to match naming conventions or
avoid Service-level port collisions).

NOTE: this field controls only the Service Port (the externally visible
scrape port). The Service TargetPort — the port the pod actually listens
on — is always the controller-wide default and is not affected by this
field. This is intentional: when the OpenTelemetry sidecar mode is
enabled, each pod gets its own injected sidecar, but the pod-side
Prometheus listener port is determined by controller-wide/injection
configuration, not per PolicyServer. Therefore, changing this field does
not change the pod listener port and will not resolve pod-port conflicts
such as those caused by hostNetwork.






#### PolicySpec







_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

##### `policyServer`

**Type:** _string_

**Default:** default

**Validation:**
- Optional: \{\}

PolicyServer identifies an existing PolicyServer resource.
##### `mode`

**Type:** _[PolicyMode](#policymode)_

**Default:** protect

**Validation:**
- Enum: [protect monitor]
- Optional: \{\}

Mode defines the execution mode of this policy. Can be set to
either "protect" or "monitor". If it's empty, it is defaulted to
"protect".
Transitioning this setting from "monitor" to "protect" is
allowed, but is disallowed to transition from "protect" to
"monitor". To perform this transition, the policy should be
recreated in "monitor" mode instead.
##### `module`

**Type:** _string_

**Validation:**
- Required: \{\}

Module is the location of the WASM module to be loaded. Can be a
local file (file://), a remote file served by an HTTP server
(http://, https://), or an artifact served by an OCI-compatible
registry (registry://).
If prefix is missing, it will default to registry:// and use that
internally.
##### `settings`

**Type:** _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_

**Validation:**
- Optional: \{\}

Settings is a free-form object that contains the policy configuration
values.
x-kubernetes-embedded-resource: false
##### `rules`

**Type:** _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_

Rules describes what operations on what resources/subresources the webhook cares about.
The webhook cares about an operation if it matches _any_ Rule.
##### `failurePolicy`

**Type:** _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

FailurePolicy defines how unrecognized errors and timeout errors from the
policy are handled. Allowed values are "Ignore" or "Fail".
* "Ignore" means that an error calling the webhook is ignored and the API
  request is allowed to continue.
* "Fail" means that an error calling the webhook causes the admission to
  fail and the API request to be rejected.
The default behaviour is "Fail"
##### `mutating`

**Type:** _boolean_

Mutating indicates whether a policy has the ability to mutate
incoming requests or not.
##### `backgroundAudit`

**Type:** _boolean_

**Default:** true

**Validation:**
- Optional: \{\}

BackgroundAudit indicates whether a policy should be used or skipped when
performing audit checks. If false, the policy cannot produce meaningful
evaluation results during audit checks and will be skipped.
The default is "true".
##### `matchPolicy`

**Type:** _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

matchPolicy defines how the "rules" list is used to match incoming requests.
Allowed values are "Exact" or "Equivalent".

* `Exact`: Match a request only if it exactly matches a specified rule.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
* `Equivalent`: Match a request that modifies a listed resource through an equivalent API group or version.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.

Defaults to "Equivalent"
##### `matchConditions`

**Type:** _[MatchCondition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchcondition-v1-admissionregistration) array_

**Validation:**
- Optional: \{\}

MatchConditions are a list of conditions that must be met for a request to be
validated. Match conditions filter requests that have already been matched by
the rules, namespaceSelector, and objectSelector. An empty list of
matchConditions matches all requests. There are a maximum of 64 match
conditions allowed. If a parameter object is provided, it can be accessed via
the `params` handle in the same manner as validation expressions. The exact
matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,
the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy
is evaluated. 3. If any matchCondition evaluates to an error (but none are
FALSE): - If failurePolicy=Fail, reject the request - If
failurePolicy=Ignore, the policy is skipped.
Only available if the feature gate AdmissionWebhookMatchConditions is enabled.
##### `objectSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

ObjectSelector decides whether to run the webhook based on if the
object has matching labels. objectSelector is evaluated against both
the oldObject and newObject that would be sent to the webhook, and
is considered to match if either object matches the selector. A null
object (oldObject in the case of create, or newObject in the case of
delete) or an object that cannot have labels (like a
DeploymentRollback or a PodProxyOptions object) is not considered to
match.
Use the object selector only if the webhook is opt-in, because end
users may skip the admission webhook by setting the labels.
Default to the empty LabelSelector, which matches everything.
##### `sideEffects`

**Type:** _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_

SideEffects states whether this webhook has side effects.
Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
Webhooks with side effects MUST implement a reconciliation system, since a request may be
rejected by a future step in the admission change and the side effects therefore need to be undone.
Requests with the dryRun attribute will be auto-rejected if they match a webhook with
sideEffects == Unknown or Some.
##### `timeoutSeconds`

**Type:** _integer_

**Default:** 10

**Validation:**
- Maximum: 30
- Minimum: 2
- Optional: \{\}

TimeoutSeconds specifies the timeout for the policy webhook. After the timeout passes,
the webhook call will be ignored or the API call will fail based on the
failure policy.
The timeout value must be between 2 and 30 seconds.
Default to 10 seconds.
##### `timeoutEvalSeconds`

**Type:** _integer_

**Validation:**
- Maximum: 30
- Minimum: 2
- Optional: \{\}

TimeoutEvalSeconds specifies the timeout for the policy evaluation. After
the timeout passes, the policy evaluation call will fail based on the
failure policy.
The timeout value must be between 2 and 30 seconds.
##### `message`

**Type:** _string_

**Validation:**
- Optional: \{\}

Message overrides the rejection message of the policy.
When provided, the policy's rejection message can be found
inside of the `.status.details.causes` field of the
AdmissionResponse object




#### PolicyStatusEnum

_Underlying type:_ _string_



_Validation:_
- Enum: [unscheduled scheduled pending active rejected]

_Appears in:_

| Field | Description |
| --- | --- |
| `unscheduled` | PolicyStatusUnscheduled is a transient state that will continue<br />to scheduled. This is the default state if no policy server is<br />assigned.<br /> |
| `scheduled` | PolicyStatusScheduled is a transient state that will continue to<br />pending. This is the default state if a policy server is<br />assigned.<br /> |
| `pending` | PolicyStatusPending informs that the policy server exists,<br />we are reconciling all resources.<br /> |
| `active` | PolicyStatusActive informs that the k8s API server should be<br />forwarding admission review objects to the policy.<br /> |
| `rejected` | PolicyStatusRejected means that the policy targets resources that<br />the cluster administrator does not allow for namespaced policies.<br />The controller does not deploy the policy. The PolicyActive<br />condition explains the reason.<br /> |





## policies.kubewarden.io/v1alpha2

Package v1alpha2 contains API Schema definitions for the policies v1alpha2 API group

### Resource Types
- [AdmissionPolicy](#admissionpolicy)
- [AdmissionPolicyList](#admissionpolicylist)
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)
- [PolicyServer](#policyserver)
- [PolicyServerList](#policyserverlist)



#### AdmissionPolicy



AdmissionPolicy is the Schema for the admissionpolicies API



_Appears in:_
- [AdmissionPolicyList](#admissionpolicylist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`AdmissionPolicy`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[AdmissionPolicySpec](#admissionpolicyspec)_




#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy.





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`AdmissionPolicyList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[AdmissionPolicy](#admissionpolicy) array_




#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy.



_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

##### `PolicySpec`

**Type:** _[PolicySpec](#policyspec)_




#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicy`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_




#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`ClusterAdmissionPolicyList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_




#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy.



_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

##### `PolicySpec`

**Type:** _[PolicySpec](#policyspec)_


##### `namespaceSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

NamespaceSelector decides whether to run the webhook on an object based
on whether the namespace for that object matches the selector. If the
object itself is a namespace, the matching is performed on
object.metadata.labels. If the object is another cluster scoped resource,
it never skips the webhook.

For example, to run the webhook on objects whose namespace does not have
a runlevel of 0 or 1, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "runlevel",
        "operator": "NotIn",
        "values": ["0", "1"]
      }
    ]
  }
}
```

To run the webhook only on objects whose namespace has an environment of
prod or staging, use this selector:

```json
{
  "namespaceSelector": {
    "matchExpressions": [
      {
        "key": "environment",
        "operator": "In",
        "values": ["prod", "staging"]
      }
    ]
  }
}
```

See
https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
for more examples of label selectors.

Default to the empty LabelSelector, which matches everything.






#### PolicyMode

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor]

_Appears in:_
- [PolicySpec](#policyspec)



#### PolicyModeStatus

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor unknown]

_Appears in:_

| Field | Description |
| --- | --- |
| `protect` |  |
| `monitor` |  |
| `unknown` |  |


#### PolicyServer



PolicyServer is the Schema for the policyservers API.



_Appears in:_
- [PolicyServerList](#policyserverlist)

##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`PolicyServer`
##### `metadata`

**Type:** _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `spec`

**Type:** _[PolicyServerSpec](#policyserverspec)_






#### PolicyServerList



PolicyServerList contains a list of PolicyServer.





##### `apiVersion`

**Type:** _string_

`policies.kubewarden.io/v1alpha2`

##### `kind`

**Type:** _string_

`PolicyServerList`
##### `metadata`

**Type:** _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_

Refer to Kubernetes API documentation for fields of `metadata`.
##### `items`

**Type:** _[PolicyServer](#policyserver) array_




#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer.



_Appears in:_
- [PolicyServer](#policyserver)

##### `image`

**Type:** _string_

Docker image name.
##### `replicas`

**Type:** _integer_

Replicas is the number of desired replicas.
##### `annotations`

**Type:** _object (keys:string, values:string)_

**Validation:**
- Optional: \{\}

Annotations is an unstructured key value map stored with a resource that may be
set by external tools to store and retrieve arbitrary metadata. They are not
queryable and should be preserved when modifying objects.
More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/
##### `env`

**Type:** _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#envvar-v1-core) array_

**Validation:**
- Optional: \{\}

List of environment variables to set in the container.
##### `serviceAccountName`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of the service account associated with the policy server.
Namespace service account will be used if not specified.
##### `imagePullSecret`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of ImagePullSecret secret in the same namespace, used for pulling
policies from repositories.
##### `insecureSources`

**Type:** _string array_

**Validation:**
- Optional: \{\}

List of insecure URIs to policy repositories. The `insecureSources`
content format corresponds with the contents of the `insecure_sources`
key in `sources.yaml`. Reference for `sources.yaml` is found in the
Kubewarden documentation in the reference section.
##### `sourceAuthorities`

**Type:** _object (keys:string, values:string array)_

**Validation:**
- Optional: \{\}

Key value map of registry URIs endpoints to a list of their associated
PEM encoded certificate authorities that have to be used to verify the
certificate used by the endpoint. The `sourceAuthorities` content format
corresponds with the contents of the `source_authorities` key in
`sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden
documentation in the reference section.
##### `verificationConfig`

**Type:** _string_

**Validation:**
- Optional: \{\}

Name of VerificationConfig configmap in the same namespace, containing
Sigstore verification configuration. The configuration must be under a
key named verification-config in the Configmap.




#### PolicySpec







_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

##### `policyServer`

**Type:** _string_

**Default:** default

**Validation:**
- Optional: \{\}

PolicyServer identifies an existing PolicyServer resource.
##### `module`

**Type:** _string_

**Validation:**
- Required: \{\}

Module is the location of the WASM module to be loaded. Can be a
local file (file://), a remote file served by an HTTP server
(http://, https://), or an artifact served by an OCI-compatible
registry (registry://).
##### `mode`

**Type:** _[PolicyMode](#policymode)_

**Default:** protect

**Validation:**
- Enum: [protect monitor]
- Optional: \{\}

Mode defines the execution mode of this policy. Can be set to
either "protect" or "monitor". If it's empty, it is defaulted to
"protect".
Transitioning this setting from "monitor" to "protect" is
allowed, but is disallowed to transition from "protect" to
"monitor". To perform this transition, the policy should be
recreated in "monitor" mode instead.
##### `settings`

**Type:** _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_

**Validation:**
- Optional: \{\}

Settings is a free-form object that contains the policy configuration
values.
x-kubernetes-embedded-resource: false
##### `rules`

**Type:** _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_

Rules describes what operations on what resources/subresources the webhook cares about.
The webhook cares about an operation if it matches _any_ Rule.
##### `failurePolicy`

**Type:** _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

FailurePolicy defines how unrecognized errors and timeout errors from the
policy are handled. Allowed values are "Ignore" or "Fail".
* "Ignore" means that an error calling the webhook is ignored and the API
  request is allowed to continue.
* "Fail" means that an error calling the webhook causes the admission to
  fail and the API request to be rejected.
The default behaviour is "Fail"
##### `mutating`

**Type:** _boolean_

Mutating indicates whether a policy has the ability to mutate
incoming requests or not.
##### `matchPolicy`

**Type:** _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_

**Validation:**
- Optional: \{\}

matchPolicy defines how the "rules" list is used to match incoming requests.
Allowed values are "Exact" or "Equivalent".

* `Exact`: Match a request only if it exactly matches a specified rule.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
* `Equivalent`: Match a request that modifies a listed resource through an equivalent API group or version.
For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.

Defaults to "Equivalent"
##### `objectSelector`

**Type:** _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_

**Validation:**
- Optional: \{\}

ObjectSelector decides whether to run the webhook based on if the
object has matching labels. objectSelector is evaluated against both
the oldObject and newObject that would be sent to the webhook, and
is considered to match if either object matches the selector. A null
object (oldObject in the case of create, or newObject in the case of
delete) or an object that cannot have labels (like a
DeploymentRollback or a PodProxyOptions object) is not considered to
match.
Use the object selector only if the webhook is opt-in, because end
users may skip the admission webhook by setting the labels.
Default to the empty LabelSelector, which matches everything.
##### `sideEffects`

**Type:** _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_

SideEffects states whether this webhook has side effects.
Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
Webhooks with side effects MUST implement a reconciliation system, since a request may be
rejected by a future step in the admission change and the side effects therefore need to be undone.
Requests with the dryRun attribute will be auto-rejected if they match a webhook with
sideEffects == Unknown or Some.
##### `timeoutSeconds`

**Type:** _integer_

**Default:** 10

**Validation:**
- Optional: \{\}

TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
the webhook call will be ignored or the API call will fail based on the
failure policy.
The timeout value must be between 1 and 30 seconds.
Default to 10 seconds.




#### PolicyStatusEnum

_Underlying type:_ _string_



_Validation:_
- Enum: [unscheduled scheduled pending active rejected]

_Appears in:_

| Field | Description |
| --- | --- |
| `unscheduled` | PolicyStatusUnscheduled is a transient state that will continue<br />to scheduled. This is the default state if no policy server is<br />assigned.<br /> |
| `scheduled` | PolicyStatusScheduled is a transient state that will continue to<br />pending. This is the default state if a policy server is<br />assigned.<br /> |
| `pending` | PolicyStatusPending informs that the policy server exists,<br />we are reconciling all resources.<br /> |
| `active` | PolicyStatusActive informs that the k8s API server should be<br />forwarding admission review objects to the policy.<br /> |
| `rejected` | PolicyStatusRejected means that the policy targets resources that<br />the cluster administrator does not allow for namespaced policies.<br />The controller does not deploy the policy. The PolicyActive<br />condition explains the reason.<br /> |




