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

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `AdmissionPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[AdmissionPolicySpec](#admissionpolicyspec)_ |  |  |  |




#### AdmissionPolicyGroup



AdmissionPolicyGroup is the Schema for the AdmissionPolicyGroups API



_Appears in:_
- [AdmissionPolicyGroupList](#admissionpolicygrouplist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `AdmissionPolicyGroup` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[AdmissionPolicyGroupSpec](#admissionpolicygroupspec)_ |  |  |  |




#### AdmissionPolicyGroupList



AdmissionPolicyGroupList contains a list of AdmissionPolicyGroup.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `AdmissionPolicyGroupList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[AdmissionPolicyGroup](#admissionpolicygroup) array_ |  |  |  |


#### AdmissionPolicyGroupSpec



AdmissionPolicyGroupSpec defines the desired state of AdmissionPolicyGroup.



_Appears in:_
- [AdmissionPolicyGroup](#admissionpolicygroup)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicyGroupSpec` _[PolicyGroupSpec](#policygroupspec)_ |  |  |  |


#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `AdmissionPolicyList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[AdmissionPolicy](#admissionpolicy) array_ |  |  |  |


#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy.



_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicySpec` _[PolicySpec](#policyspec)_ |  |  |  |


#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `ClusterAdmissionPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_ |  |  |  |




#### ClusterAdmissionPolicyGroup



ClusterAdmissionPolicyGroup is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyGroupList](#clusteradmissionpolicygrouplist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `ClusterAdmissionPolicyGroup` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ClusterAdmissionPolicyGroupSpec](#clusteradmissionpolicygroupspec)_ |  |  |  |




#### ClusterAdmissionPolicyGroupList



ClusterAdmissionPolicyGroupList contains a list of ClusterAdmissionPolicyGroup





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `ClusterAdmissionPolicyGroupList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ClusterAdmissionPolicyGroup](#clusteradmissionpolicygroup) array_ |  |  |  |


#### ClusterAdmissionPolicyGroupSpec



ClusterAdmissionPolicyGroupSpec defines the desired state of ClusterAdmissionPolicyGroup.



_Appears in:_
- [ClusterAdmissionPolicyGroup](#clusteradmissionpolicygroup)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ClusterPolicyGroupSpec` _[ClusterPolicyGroupSpec](#clusterpolicygroupspec)_ |  |  |  |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | NamespaceSelector decides whether to run the webhook on an object based<br />on whether the namespace for that object matches the selector. If the<br />object itself is a namespace, the matching is performed on<br />object.metadata.labels. If the object is another cluster scoped resource,<br />it never skips the webhook.<br /><br/><br/><br />For example, to run the webhook on any objects whose namespace is not<br />associated with "runlevel" of "0" or "1";  you will set the selector as<br />follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />If instead you want to only run the webhook on any objects whose<br />namespace is associated with the "environment" of "prod" or "staging";<br />you will set the selector as follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />See<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels<br />for more examples of label selectors.<br /><br/><br/><br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |
| `allowInsideAdmissionControllerNamespace` _boolean_ | AllowInsideAdmissionControllerNamespace controls whether the policy should also be<br />evaluated for resources in the namespace where Kubewarden is deployed.<br />By default (false), an exclusion rule is added to the webhook so that the<br />Kubewarden namespace is never targeted, protecting against an accidental<br />lockout. Set this to true only if you deliberately want the policy to apply<br />inside the Kubewarden namespace.<br />Warning: setting this to true may cause a deadlock if the policy prevents<br />Kubewarden components from starting. |  | Optional: \{\} <br /> |


#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `ClusterAdmissionPolicyList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_ |  |  |  |


#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy.



_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicySpec` _[PolicySpec](#policyspec)_ |  |  |  |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | NamespaceSelector decides whether to run the webhook on an object based<br />on whether the namespace for that object matches the selector. If the<br />object itself is a namespace, the matching is performed on<br />object.metadata.labels. If the object is another cluster scoped resource,<br />it never skips the webhook.<br /><br/><br/><br />For example, to run the webhook on any objects whose namespace is not<br />associated with "runlevel" of "0" or "1";  you will set the selector as<br />follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />If instead you want to only run the webhook on any objects whose<br />namespace is associated with the "environment" of "prod" or "staging";<br />you will set the selector as follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />See<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels<br />for more examples of label selectors.<br /><br/><br/><br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |
| `contextAwareResources` _[ContextAwareResource](#contextawareresource) array_ | List of Kubernetes resources the policy is allowed to access at evaluation time.<br />Access to these resources is done using the `ServiceAccount` of the PolicyServer<br />the policy is assigned to. |  | Optional: \{\} <br /> |
| `allowInsideAdmissionControllerNamespace` _boolean_ | AllowInsideAdmissionControllerNamespace controls whether the policy should also be<br />evaluated for resources in the namespace where Kubewarden is deployed.<br />By default (false), an exclusion rule is added to the webhook so that the<br />Kubewarden namespace is never targeted, protecting against an accidental<br />lockout. Set this to true only if you deliberately want the policy to apply<br />inside the Kubewarden namespace.<br />Warning: setting this to true may cause a deadlock if the policy prevents<br />Kubewarden components from starting. |  | Optional: \{\} <br /> |


#### ClusterPolicyGroupSpec







_Appears in:_
- [ClusterAdmissionPolicyGroupSpec](#clusteradmissionpolicygroupspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `GroupSpec` _[GroupSpec](#groupspec)_ |  |  |  |
| `policies` _[PolicyGroupMembersWithContext](#policygroupmemberswithcontext)_ | Policies is a list of policies that are part of the group that will<br />be available to be called in the evaluation expression field.<br />Each policy in the group should be a Kubewarden policy. |  | Required: \{\} <br /> |


#### ContextAwareResource



ContextAwareResource identifies a Kubernetes resource.



_Appears in:_
- [ClusterAdmissionPolicyFactory](#clusteradmissionpolicyfactory)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)
- [PolicyGroupMemberWithContext](#policygroupmemberwithcontext)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | apiVersion of the resource (v1 for core group, groupName/groupVersions for other). |  |  |
| `kind` _string_ | Singular PascalCase name of the resource |  |  |


#### GroupSpec







_Appears in:_
- [ClusterPolicyGroupSpec](#clusterpolicygroupspec)
- [PolicyGroupSpec](#policygroupspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. | default | Optional: \{\} <br /> |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to<br />either "protect" or "monitor". If it's empty, it is defaulted to<br />"protect".<br />Transitioning this setting from "monitor" to "protect" is<br />allowed, but is disallowed to transition from "protect" to<br />"monitor". To perform this transition, the policy should be<br />recreated in "monitor" mode instead. | protect | Enum: [protect monitor] <br />Optional: \{\} <br /> |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about.<br />The webhook cares about an operation if it matches _any_ Rule. |  |  |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the<br />policy are handled. Allowed values are "Ignore" or "Fail".<br />* "Ignore" means that an error calling the webhook is ignored and the API<br />  request is allowed to continue.<br />* "Fail" means that an error calling the webhook causes the admission to<br />  fail and the API request to be rejected.<br />The default behaviour is "Fail" |  | Optional: \{\} <br /> |
| `backgroundAudit` _boolean_ | BackgroundAudit indicates whether a policy should be used or skipped when<br />performing audit checks. If false, the policy cannot produce meaningful<br />evaluation results during audit checks and will be skipped.<br />The default is "true". | true | Optional: \{\} <br /> |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests.<br />Allowed values are "Exact" or "Equivalent".<br /><ul><br /><li><br />Exact: match a request only if it exactly matches a specified rule.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.<br /></li><br /><li><br />Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.<br /></li><br /></ul><br />Defaults to "Equivalent" |  | Optional: \{\} <br /> |
| `matchConditions` _[MatchCondition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchcondition-v1-admissionregistration) array_ | MatchConditions are a list of conditions that must be met for a request to be<br />validated. Match conditions filter requests that have already been matched by<br />the rules, namespaceSelector, and objectSelector. An empty list of<br />matchConditions matches all requests. There are a maximum of 64 match<br />conditions allowed. If a parameter object is provided, it can be accessed via<br />the `params` handle in the same manner as validation expressions. The exact<br />matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,<br />the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy<br />is evaluated. 3. If any matchCondition evaluates to an error (but none are<br />FALSE): - If failurePolicy=Fail, reject the request - If<br />failurePolicy=Ignore, the policy is skipped.<br />Only available if the feature gate AdmissionWebhookMatchConditions is enabled. |  | Optional: \{\} <br /> |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the<br />object has matching labels. objectSelector is evaluated against both<br />the oldObject and newObject that would be sent to the webhook, and<br />is considered to match if either object matches the selector. A null<br />object (oldObject in the case of create, or newObject in the case of<br />delete) or an object that cannot have labels (like a<br />DeploymentRollback or a PodProxyOptions object) is not considered to<br />match.<br />Use the object selector only if the webhook is opt-in, because end<br />users may skip the admission webhook by setting the labels.<br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects.<br />Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).<br />Webhooks with side effects MUST implement a reconciliation system, since a request may be<br />rejected by a future step in the admission change and the side effects therefore need to be undone.<br />Requests with the dryRun attribute will be auto-rejected if they match a webhook with<br />sideEffects == Unknown or Some. |  |  |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,<br />the webhook call will be ignored or the API call will fail based on the<br />failure policy.<br />The timeout value must be between 2 and 30 seconds.<br />Default to 10 seconds. | 10 | Maximum: 30 <br />Minimum: 2 <br />Optional: \{\} <br /> |
| `expression` _string_ | Expression is the evaluation expression to accept or reject the<br />admission request under evaluation. This field uses CEL as the<br />expression language for the policy groups. Each policy in the group<br />will be represented as a function call in the expression with the<br />same name as the policy defined in the group. The expression field<br />should be a valid CEL expression that evaluates to a boolean value.<br />If the expression evaluates to true, the group policy will be<br />considered as accepted, otherwise, it will be considered as<br />rejected. This expression allows grouping policies calls and perform<br />logical operations on the results of the policies. See Kubewarden<br />documentation to learn about all the features available. |  | Required: \{\} <br /> |
| `message` _string_ | Message is  used to specify the message that will be returned when<br />the policy group is rejected. The specific policy results will be<br />returned in the warning field of the response. |  | Required: \{\} <br /> |














#### PolicyGroupMember







_Appears in:_
- [PolicyGroupMemberWithContext](#policygroupmemberwithcontext)
- [PolicyGroupMembers](#policygroupmembers)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a<br />local file (file://), a remote file served by an HTTP server<br />(http://, https://), or an artifact served by an OCI-compatible<br />registry (registry://).<br />If prefix is missing, it will default to registry:// and use that<br />internally. |  | Required: \{\} <br /> |
| `settings` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_ | Settings is a free-form object that contains the policy configuration<br />values.<br />x-kubernetes-embedded-resource: false |  | Optional: \{\} <br /> |
| `timeoutEvalSeconds` _integer_ | TimeoutEvalSeconds specifies the timeout for the policy evaluation. After<br />the timeout passes, the policy evaluation call will fail based on the<br />failure policy.<br />The timeout value must be between 2 and 30 seconds. |  | Maximum: 30 <br />Minimum: 2 <br />Optional: \{\} <br /> |


#### PolicyGroupMemberWithContext







_Appears in:_
- [PolicyGroupMembersWithContext](#policygroupmemberswithcontext)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicyGroupMember` _[PolicyGroupMember](#policygroupmember)_ |  |  |  |
| `contextAwareResources` _[ContextAwareResource](#contextawareresource) array_ | List of Kubernetes resources the policy is allowed to access at evaluation time.<br />Access to these resources is done using the `ServiceAccount` of the PolicyServer<br />the policy is assigned to. |  | Optional: \{\} <br /> |


#### PolicyGroupMembers

_Underlying type:_ _[map[string]PolicyGroupMember](#map[string]policygroupmember)_





_Appears in:_
- [AdmissionPolicyGroupFactory](#admissionpolicygroupfactory)
- [PolicyGroupSpec](#policygroupspec)



#### PolicyGroupMembersWithContext

_Underlying type:_ _[map[string]PolicyGroupMemberWithContext](#map[string]policygroupmemberwithcontext)_





_Appears in:_
- [ClusterAdmissionPolicyGroupFactory](#clusteradmissionpolicygroupfactory)
- [ClusterPolicyGroupSpec](#clusterpolicygroupspec)



#### PolicyGroupSpec







_Appears in:_
- [AdmissionPolicyGroupSpec](#admissionpolicygroupspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `GroupSpec` _[GroupSpec](#groupspec)_ |  |  |  |
| `policies` _[PolicyGroupMembers](#policygroupmembers)_ | Policies is a list of policies that are part of the group that will<br />be available to be called in the evaluation expression field.<br />Each policy in the group should be a Kubewarden policy. |  | Required: \{\} <br /> |






#### PolicyMode

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor]

_Appears in:_
- [AdmissionPolicyFactory](#admissionpolicyfactory)
- [AdmissionPolicyGroupFactory](#admissionpolicygroupfactory)
- [ClusterAdmissionPolicyFactory](#clusteradmissionpolicyfactory)
- [ClusterAdmissionPolicyGroupFactory](#clusteradmissionpolicygroupfactory)
- [GroupSpec](#groupspec)
- [PolicySpec](#policyspec)



#### PolicyModeStatus

_Underlying type:_ _string_



_Validation:_
- Enum: [protect monitor unknown]

_Appears in:_
- [PolicyStatus](#policystatus)

| Field | Description |
| --- | --- |
| `protect` |  |
| `monitor` |  |
| `unknown` |  |




#### PolicyServer



PolicyServer is the Schema for the policyservers API.



_Appears in:_
- [PolicyServerList](#policyserverlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `PolicyServer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[PolicyServerSpec](#policyserverspec)_ |  |  |  |






#### PolicyServerList



PolicyServerList contains a list of PolicyServer.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1` | | |
| `kind` _string_ | `PolicyServerList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[PolicyServer](#policyserver) array_ |  |  |  |


#### PolicyServerSecurity



PolicyServerSecurity defines securityContext configuration to be used in the Policy Server workload.



_Appears in:_
- [PolicyServerSpec](#policyserverspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `container` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#securitycontext-v1-core)_ | securityContext definition to be used in the policy server container |  | Optional: \{\} <br /> |
| `pod` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#podsecuritycontext-v1-core)_ | podSecurityContext definition to be used in the policy server Pod |  | Optional: \{\} <br /> |


#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer.



_Appears in:_
- [PolicyServer](#policyserver)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `image` _string_ | Docker image name. |  |  |
| `replicas` _integer_ | Replicas is the number of desired replicas. |  |  |
| `minAvailable` _[IntOrString](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#intorstring-intstr-util)_ | Number of policy server replicas that must be still available after the<br />eviction. The value can be an absolute number or a percentage. Only one of<br />MinAvailable or Max MaxUnavailable can be set. |  |  |
| `maxUnavailable` _[IntOrString](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#intorstring-intstr-util)_ | Number of policy server replicas that can be unavailable after the<br />eviction. The value can be an absolute number or a percentage. Only one of<br />MinAvailable or Max MaxUnavailable can be set. |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations is an unstructured key value map stored with a resource that may be<br />set by external tools to store and retrieve arbitrary metadata. They are not<br />queryable and should be preserved when modifying objects.<br />More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/ |  | Optional: \{\} <br /> |
| `labels` _object (keys:string, values:string)_ | Labels is a map of custom labels to be applied to the Deployment created by the<br />PolicyServer and to the Pods managed by that Deployment. System labels set by<br />the controller always take precedence over user-defined labels with the same key.<br />More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/ |  | Optional: \{\} <br /> |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#envvar-v1-core) array_ | List of environment variables to set in the container. |  | Optional: \{\} <br /> |
| `serviceAccountName` _string_ | Name of the service account associated with the policy server.<br />Namespace service account will be used if not specified. |  | Optional: \{\} <br /> |
| `imagePullSecret` _string_ | Name of ImagePullSecret secret in the same namespace, used for pulling<br />policies from repositories. |  | Optional: \{\} <br /> |
| `insecureSources` _string array_ | List of insecure URIs to policy repositories. The `insecureSources`<br />content format corresponds with the contents of the `insecure_sources`<br />key in `sources.yaml`. Reference for `sources.yaml` is found in the<br />Kubewarden documentation in the reference section. |  | Optional: \{\} <br /> |
| `sourceAuthorities` _object (keys:string, values:string array)_ | Key value map of registry URIs endpoints to a list of their associated<br />PEM encoded certificate authorities that have to be used to verify the<br />certificate used by the endpoint. The `sourceAuthorities` content format<br />corresponds with the contents of the `source_authorities` key in<br />`sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden<br />documentation in the reference section. |  | Optional: \{\} <br /> |
| `verificationConfig` _string_ | Name of VerificationConfig configmap in the kubewarden namespace (same<br />namespace as the controller deployment), containing Sigstore verification<br />configuration. The configuration must be under a key named<br />verification-config in the ConfigMap. |  | Optional: \{\} <br /> |
| `sigstoreTrustConfig` _string_ | Name of SigstoreTrustConfig configmap in the kubewarden namespace (same<br />namespace as the controller deployment), containing Sigstore trust<br />configuration (ClientTrustConfig JSON). The configuration must be under a<br />key named sigstore-trust-config in the ConfigMap. This is used to configure<br />a custom Sigstore instance instead of the default public Sigstore infrastructure.<br />WARNING: This feature requires strict access control. Users with write access<br />to this ConfigMap can influence policy signature verification. |  | Optional: \{\} <br /> |
| `securityContexts` _[PolicyServerSecurity](#policyserversecurity)_ | Security configuration to be used in the Policy Server workload.<br />The field allows different configurations for the pod and containers.<br />If set for the containers, this configuration will not be used in<br />containers added by other controllers (e.g. telemetry sidecars) |  | Optional: \{\} <br /> |
| `affinity` _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#affinity-v1-core)_ | Affinity rules for the associated Policy Server pods. |  | Optional: \{\} <br /> |
| `limits` _[ResourceList](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#resourcelist-v1-core)_ | Limits describes the maximum amount of compute resources allowed. |  | Optional: \{\} <br /> |
| `requests` _[ResourceList](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#resourcelist-v1-core)_ | Requests describes the minimum amount of compute resources required.<br />If Request is omitted for, it defaults to Limits if that is explicitly specified,<br />otherwise to an implementation-defined value |  | Optional: \{\} <br /> |
| `tolerations` _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#toleration-v1-core) array_ | Tolerations describe the policy server pod's tolerations. It can be<br />used to ensure that the policy server pod is not scheduled onto a<br />node with a taint. |  |  |
| `priorityClassName` _string_ | PriorityClassName is the name of the PriorityClass to be used for the<br />policy server pods. Useful to schedule policy server pods with higher<br />priority to ensure their availability over other cluster workload<br />resources.<br />Note: If the referenced PriorityClass is deleted, existing pods<br />remain unchanged, but new pods that reference it cannot be created. |  | Optional: \{\} <br /> |
| `namespacedPoliciesCapabilities` _string array_ | NamespacedPoliciesCapabilities lists host capability API calls allowed<br />for namespaced policies running on this PolicyServer. When not set,<br />all host capabilities are granted to namespaced policies.<br />Supported wildcard patterns:<br />- "*": allow all host capabilities<br />- "category/*": allow all capabilities in a category (e.g. "oci/*")<br />- "category/version/*": allow all capabilities of a specific version (e.g. "oci/v1/*")<br />- Specific capability paths (e.g. "oci/v1/verify", "net/v1/dns_lookup_host") |  | Optional: \{\} <br /> |
| `webhookPort` _integer_ | Port where the policy server listens for incoming webhook requests.<br />When unset, defaults to 8443. This is the port the Kubernetes API server<br />reaches when evaluating admission requests. |  | Maximum: 65535 <br />Minimum: 1 <br />Optional: \{\} <br /> |
| `readinessProbePort` _integer_ | Port used by the policy server to expose the readiness probe endpoint.<br />When unset, defaults to 8081. |  | Maximum: 65535 <br />Minimum: 1 <br />Optional: \{\} <br /> |
| `metricsPort` _integer_ | Port exposed by the metrics Service for this policy server.<br />When unset, defaults to the controller-wide default<br />(--policy-server-metrics-port CLI flag, deprecated KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT env var, or 8080).<br />Only relevant when metrics are enabled.<br />Use this field to customize which port Prometheus scrapes for this<br />PolicyServer's metrics Service (e.g. to match naming conventions or<br />avoid Service-level port collisions).<br />NOTE: this field controls only the Service Port (the externally visible<br />scrape port). The Service TargetPort — the port the pod actually listens<br />on — is always the controller-wide default and is not affected by this<br />field. This is intentional: when the OpenTelemetry sidecar mode is<br />enabled, each pod gets its own injected sidecar, but the pod-side<br />Prometheus listener port is determined by controller-wide/injection<br />configuration, not per PolicyServer. Therefore, changing this field does<br />not change the pod listener port and will not resolve pod-port conflicts<br />such as those caused by hostNetwork. |  | Maximum: 65535 <br />Minimum: 1 <br />Optional: \{\} <br /> |






#### PolicySpec







_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. | default | Optional: \{\} <br /> |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to<br />either "protect" or "monitor". If it's empty, it is defaulted to<br />"protect".<br />Transitioning this setting from "monitor" to "protect" is<br />allowed, but is disallowed to transition from "protect" to<br />"monitor". To perform this transition, the policy should be<br />recreated in "monitor" mode instead. | protect | Enum: [protect monitor] <br />Optional: \{\} <br /> |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a<br />local file (file://), a remote file served by an HTTP server<br />(http://, https://), or an artifact served by an OCI-compatible<br />registry (registry://).<br />If prefix is missing, it will default to registry:// and use that<br />internally. |  | Required: \{\} <br /> |
| `settings` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_ | Settings is a free-form object that contains the policy configuration<br />values.<br />x-kubernetes-embedded-resource: false |  | Optional: \{\} <br /> |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about.<br />The webhook cares about an operation if it matches _any_ Rule. |  |  |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the<br />policy are handled. Allowed values are "Ignore" or "Fail".<br />* "Ignore" means that an error calling the webhook is ignored and the API<br />  request is allowed to continue.<br />* "Fail" means that an error calling the webhook causes the admission to<br />  fail and the API request to be rejected.<br />The default behaviour is "Fail" |  | Optional: \{\} <br /> |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate<br />incoming requests or not. |  |  |
| `backgroundAudit` _boolean_ | BackgroundAudit indicates whether a policy should be used or skipped when<br />performing audit checks. If false, the policy cannot produce meaningful<br />evaluation results during audit checks and will be skipped.<br />The default is "true". | true | Optional: \{\} <br /> |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests.<br />Allowed values are "Exact" or "Equivalent".<br /><ul><br /><li><br />Exact: match a request only if it exactly matches a specified rule.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.<br /></li><br /><li><br />Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.<br /></li><br /></ul><br />Defaults to "Equivalent" |  | Optional: \{\} <br /> |
| `matchConditions` _[MatchCondition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchcondition-v1-admissionregistration) array_ | MatchConditions are a list of conditions that must be met for a request to be<br />validated. Match conditions filter requests that have already been matched by<br />the rules, namespaceSelector, and objectSelector. An empty list of<br />matchConditions matches all requests. There are a maximum of 64 match<br />conditions allowed. If a parameter object is provided, it can be accessed via<br />the `params` handle in the same manner as validation expressions. The exact<br />matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,<br />the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy<br />is evaluated. 3. If any matchCondition evaluates to an error (but none are<br />FALSE): - If failurePolicy=Fail, reject the request - If<br />failurePolicy=Ignore, the policy is skipped.<br />Only available if the feature gate AdmissionWebhookMatchConditions is enabled. |  | Optional: \{\} <br /> |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the<br />object has matching labels. objectSelector is evaluated against both<br />the oldObject and newObject that would be sent to the webhook, and<br />is considered to match if either object matches the selector. A null<br />object (oldObject in the case of create, or newObject in the case of<br />delete) or an object that cannot have labels (like a<br />DeploymentRollback or a PodProxyOptions object) is not considered to<br />match.<br />Use the object selector only if the webhook is opt-in, because end<br />users may skip the admission webhook by setting the labels.<br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects.<br />Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).<br />Webhooks with side effects MUST implement a reconciliation system, since a request may be<br />rejected by a future step in the admission change and the side effects therefore need to be undone.<br />Requests with the dryRun attribute will be auto-rejected if they match a webhook with<br />sideEffects == Unknown or Some. |  |  |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for the policy webhook. After the timeout passes,<br />the webhook call will be ignored or the API call will fail based on the<br />failure policy.<br />The timeout value must be between 2 and 30 seconds.<br />Default to 10 seconds. | 10 | Maximum: 30 <br />Minimum: 2 <br />Optional: \{\} <br /> |
| `timeoutEvalSeconds` _integer_ | TimeoutEvalSeconds specifies the timeout for the policy evaluation. After<br />the timeout passes, the policy evaluation call will fail based on the<br />failure policy.<br />The timeout value must be between 2 and 30 seconds. |  | Maximum: 30 <br />Minimum: 2 <br />Optional: \{\} <br /> |
| `message` _string_ | Message overrides the rejection message of the policy.<br />When provided, the policy's rejection message can be found<br />inside of the `.status.details.causes` field of the<br />AdmissionResponse object |  | Optional: \{\} <br /> |




#### PolicyStatusEnum

_Underlying type:_ _string_



_Validation:_
- Enum: [unscheduled scheduled pending active]

_Appears in:_
- [PolicyStatus](#policystatus)

| Field | Description |
| --- | --- |
| `unscheduled` | PolicyStatusUnscheduled is a transient state that will continue<br />to scheduled. This is the default state if no policy server is<br />assigned.<br /> |
| `scheduled` | PolicyStatusScheduled is a transient state that will continue to<br />pending. This is the default state if a policy server is<br />assigned.<br /> |
| `pending` | PolicyStatusPending informs that the policy server exists,<br />we are reconciling all resources.<br /> |
| `active` | PolicyStatusActive informs that the k8s API server should be<br />forwarding admission review objects to the policy.<br /> |





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

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `AdmissionPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[AdmissionPolicySpec](#admissionpolicyspec)_ |  |  |  |


#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `AdmissionPolicyList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[AdmissionPolicy](#admissionpolicy) array_ |  |  |  |


#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy.



_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicySpec` _[PolicySpec](#policyspec)_ |  |  |  |


#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API



_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `ClusterAdmissionPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_ |  |  |  |


#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `ClusterAdmissionPolicyList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_ |  |  |  |


#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy.



_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `PolicySpec` _[PolicySpec](#policyspec)_ |  |  |  |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | NamespaceSelector decides whether to run the webhook on an object based<br />on whether the namespace for that object matches the selector. If the<br />object itself is a namespace, the matching is performed on<br />object.metadata.labels. If the object is another cluster scoped resource,<br />it never skips the webhook.<br /><br/><br/><br />For example, to run the webhook on any objects whose namespace is not<br />associated with "runlevel" of "0" or "1";  you will set the selector as<br />follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />If instead you want to only run the webhook on any objects whose<br />namespace is associated with the "environment" of "prod" or "staging";<br />you will set the selector as follows:<br /><pre><br />"namespaceSelector": \{<br/><br />&nbsp;&nbsp;"matchExpressions": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\{<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/><br />&nbsp;&nbsp;&nbsp;&nbsp;\}<br/><br />&nbsp;&nbsp;]<br/><br />\}<br /></pre><br />See<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels<br />for more examples of label selectors.<br /><br/><br/><br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |






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
- [PolicyStatus](#policystatus)

| Field | Description |
| --- | --- |
| `protect` |  |
| `monitor` |  |
| `unknown` |  |


#### PolicyServer



PolicyServer is the Schema for the policyservers API.



_Appears in:_
- [PolicyServerList](#policyserverlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `PolicyServer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[PolicyServerSpec](#policyserverspec)_ |  |  |  |




#### PolicyServerList



PolicyServerList contains a list of PolicyServer.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2` | | |
| `kind` _string_ | `PolicyServerList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[PolicyServer](#policyserver) array_ |  |  |  |


#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer.



_Appears in:_
- [PolicyServer](#policyserver)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `image` _string_ | Docker image name. |  |  |
| `replicas` _integer_ | Replicas is the number of desired replicas. |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations is an unstructured key value map stored with a resource that may be<br />set by external tools to store and retrieve arbitrary metadata. They are not<br />queryable and should be preserved when modifying objects.<br />More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/ |  | Optional: \{\} <br /> |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#envvar-v1-core) array_ | List of environment variables to set in the container. |  | Optional: \{\} <br /> |
| `serviceAccountName` _string_ | Name of the service account associated with the policy server.<br />Namespace service account will be used if not specified. |  | Optional: \{\} <br /> |
| `imagePullSecret` _string_ | Name of ImagePullSecret secret in the same namespace, used for pulling<br />policies from repositories. |  | Optional: \{\} <br /> |
| `insecureSources` _string array_ | List of insecure URIs to policy repositories. The `insecureSources`<br />content format corresponds with the contents of the `insecure_sources`<br />key in `sources.yaml`. Reference for `sources.yaml` is found in the<br />Kubewarden documentation in the reference section. |  | Optional: \{\} <br /> |
| `sourceAuthorities` _object (keys:string, values:string array)_ | Key value map of registry URIs endpoints to a list of their associated<br />PEM encoded certificate authorities that have to be used to verify the<br />certificate used by the endpoint. The `sourceAuthorities` content format<br />corresponds with the contents of the `source_authorities` key in<br />`sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden<br />documentation in the reference section. |  | Optional: \{\} <br /> |
| `verificationConfig` _string_ | Name of VerificationConfig configmap in the same namespace, containing<br />Sigstore verification configuration. The configuration must be under a<br />key named verification-config in the Configmap. |  | Optional: \{\} <br /> |




#### PolicySpec







_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. | default | Optional: \{\} <br /> |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a<br />local file (file://), a remote file served by an HTTP server<br />(http://, https://), or an artifact served by an OCI-compatible<br />registry (registry://). |  | Required: \{\} <br /> |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to<br />either "protect" or "monitor". If it's empty, it is defaulted to<br />"protect".<br />Transitioning this setting from "monitor" to "protect" is<br />allowed, but is disallowed to transition from "protect" to<br />"monitor". To perform this transition, the policy should be<br />recreated in "monitor" mode instead. | protect | Enum: [protect monitor] <br />Optional: \{\} <br /> |
| `settings` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rawextension-runtime-pkg)_ | Settings is a free-form object that contains the policy configuration<br />values.<br />x-kubernetes-embedded-resource: false |  | Optional: \{\} <br /> |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about.<br />The webhook cares about an operation if it matches _any_ Rule. |  |  |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the<br />policy are handled. Allowed values are "Ignore" or "Fail".<br />* "Ignore" means that an error calling the webhook is ignored and the API<br />  request is allowed to continue.<br />* "Fail" means that an error calling the webhook causes the admission to<br />  fail and the API request to be rejected.<br />The default behaviour is "Fail" |  | Optional: \{\} <br /> |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate<br />incoming requests or not. |  |  |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests.<br />Allowed values are "Exact" or "Equivalent".<br /><ul><br /><li><br />Exact: match a request only if it exactly matches a specified rule.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.<br /></li><br /><li><br />Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.<br />For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,<br />and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,<br />a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.<br /></li><br /></ul><br />Defaults to "Equivalent" |  | Optional: \{\} <br /> |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the<br />object has matching labels. objectSelector is evaluated against both<br />the oldObject and newObject that would be sent to the webhook, and<br />is considered to match if either object matches the selector. A null<br />object (oldObject in the case of create, or newObject in the case of<br />delete) or an object that cannot have labels (like a<br />DeploymentRollback or a PodProxyOptions object) is not considered to<br />match.<br />Use the object selector only if the webhook is opt-in, because end<br />users may skip the admission webhook by setting the labels.<br />Default to the empty LabelSelector, which matches everything. |  | Optional: \{\} <br /> |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects.<br />Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).<br />Webhooks with side effects MUST implement a reconciliation system, since a request may be<br />rejected by a future step in the admission change and the side effects therefore need to be undone.<br />Requests with the dryRun attribute will be auto-rejected if they match a webhook with<br />sideEffects == Unknown or Some. |  |  |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,<br />the webhook call will be ignored or the API call will fail based on the<br />failure policy.<br />The timeout value must be between 1 and 30 seconds.<br />Default to 10 seconds. | 10 | Optional: \{\} <br /> |




#### PolicyStatusEnum

_Underlying type:_ _string_



_Validation:_
- Enum: [unscheduled scheduled pending active]

_Appears in:_
- [PolicyStatus](#policystatus)

| Field | Description |
| --- | --- |
| `unscheduled` | PolicyStatusUnscheduled is a transient state that will continue<br />to scheduled. This is the default state if no policy server is<br />assigned.<br /> |
| `scheduled` | PolicyStatusScheduled is a transient state that will continue to<br />pending. This is the default state if a policy server is<br />assigned.<br /> |
| `pending` | PolicyStatusPending informs that the policy server exists,<br />we are reconciling all resources.<br /> |
| `active` | PolicyStatusActive informs that the k8s API server should be<br />forwarding admission review objects to the policy.<br /> |



