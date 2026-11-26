/*
copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

var _ = Describe("PolicyServer controller", func() {
	ctx := context.Background()
	var policyServerName string

	BeforeEach(func() {
		policyServerName = newName("policy-server")
	})

	When("creating a PolicyServer", func() {
		It("should use the policy server tolerations configuration in the policy server deployment", func() {
			tolerationSeconds := int64(10)
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Tolerations = []corev1.Toleration{{
				Key:               "key1",
				Operator:          corev1.TolerationOpEqual,
				Value:             "value1",
				Effect:            corev1.TaintEffectNoSchedule,
				TolerationSeconds: nil,
			}, {
				Key:               "key2",
				Operator:          corev1.TolerationOpEqual,
				Value:             "value2",
				Effect:            corev1.TaintEffectNoExecute,
				TolerationSeconds: &tolerationSeconds,
			}}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(deployment.Spec.Template.Spec.Tolerations).To(MatchAllElements(func(element interface{}) string {
				toleration, _ := element.(corev1.Toleration)
				return toleration.Key
			}, Elements{
				"key1": MatchAllFields(Fields{
					"Key":               Equal("key1"),
					"Operator":          Equal(corev1.TolerationOpEqual),
					"Value":             Equal("value1"),
					"Effect":            Equal(corev1.TaintEffectNoSchedule),
					"TolerationSeconds": BeNil(),
				}),
				"key2": MatchAllFields(Fields{
					"Key":               Equal("key2"),
					"Operator":          Equal(corev1.TolerationOpEqual),
					"Value":             Equal("value2"),
					"Effect":            Equal(corev1.TaintEffectNoExecute),
					"TolerationSeconds": PointTo(Equal(tolerationSeconds)),
				}),
			}))

			for k, v := range policyServer.CommonLabels() {
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue(k, v))
			}
		})

		It("should use the policy server affinity configuration in the policy server deployment", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Affinity = corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "label",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"nodename"},
									},
								},
							},
						},
					},
				},
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(deployment.Spec.Template.Spec.Affinity).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"NodeAffinity": PointTo(MatchFields(IgnoreExtras, Fields{
					"RequiredDuringSchedulingIgnoredDuringExecution": PointTo(MatchFields(IgnoreExtras, Fields{
						"NodeSelectorTerms": ContainElement(MatchFields(IgnoreExtras, Fields{
							"MatchExpressions": ContainElement(MatchAllFields(Fields{
								"Key":      Equal("label"),
								"Operator": Equal(corev1.NodeSelectorOpIn),
								"Values":   Equal([]string{"nodename"}),
							})),
						})),
					})),
				})),
			})))
		})

		It("should use the policy server priorityClassName configuration in the policy server deployment", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			defaultSystemClusterCriticalPriorityClass := "system-cluster-critical" // one of the default highest PriorityClass
			policyServer.Spec.PriorityClassName = defaultSystemClusterCriticalPriorityClass
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(deployment.Spec.Template.Spec.PriorityClassName).To(Equal(defaultSystemClusterCriticalPriorityClass))
		})

		It("should create policy server deployment with some default configuration", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			By("checking the deployment container security context")
			Expect(deployment.Spec.Template.Spec.Containers).Should(ContainElement(MatchFields(IgnoreExtras, Fields{
				"SecurityContext": PointTo(MatchFields(IgnoreExtras, Fields{
					"RunAsNonRoot":             PointTo(BeTrue()),
					"AllowPrivilegeEscalation": PointTo(BeFalse()),
					"Privileged":               PointTo(BeFalse()),
					"ReadOnlyRootFilesystem":   PointTo(BeTrue()),
					"Capabilities": PointTo(MatchAllFields(Fields{
						"Add":  BeNil(),
						"Drop": Equal([]corev1.Capability{"ALL"}),
					})),
					"SELinuxOptions": BeNil(),
					"WindowsOptions": BeNil(),
					"RunAsUser":      BeNil(),
					"RunAsGroup":     BeNil(),
					"ProcMount":      BeNil(),
					"SeccompProfile": BeNil(),
				})),
			})))

			By("checking the deployment spec")
			Expect(deployment.Spec.Template.Spec).To(MatchFields(IgnoreExtras, Fields{
				"Tolerations": BeEmpty(),
				"HostNetwork": BeFalse(),
				"DNSPolicy":   Not(Equal(corev1.DNSClusterFirstWithHostNet)),
				"SecurityContext": PointTo(MatchFields(IgnoreExtras, Fields{
					"SELinuxOptions":      BeNil(),
					"WindowsOptions":      BeNil(),
					"RunAsUser":           BeNil(),
					"RunAsGroup":          BeNil(),
					"RunAsNonRoot":        BeNil(),
					"SupplementalGroups":  BeNil(),
					"FSGroup":             BeNil(),
					"Sysctls":             BeNil(),
					"FSGroupChangePolicy": BeNil(),
					"SeccompProfile": PointTo(MatchAllFields(Fields{
						"Type":             Equal(corev1.SeccompProfileTypeRuntimeDefault),
						"LocalhostProfile": BeNil(),
					})),
				})),
				"Affinity": PointTo(MatchAllFields(Fields{
					"NodeAffinity":    BeNil(),
					"PodAffinity":     BeNil(),
					"PodAntiAffinity": BeNil(),
				})),
			}))
		})

		It("should create the policy server deployment and use the user defined security contexts", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			runAsUser := int64(1000)
			privileged := true
			runAsNonRoot := false
			policyServer.Spec.SecurityContexts = policiesv1.PolicyServerSecurity{
				Container: &corev1.SecurityContext{
					RunAsUser:    &runAsUser,
					Privileged:   &privileged,
					RunAsNonRoot: &runAsNonRoot,
				},
				Pod: &corev1.PodSecurityContext{
					RunAsUser:    &runAsUser,
					RunAsNonRoot: &runAsNonRoot,
				},
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(deployment.Spec.Template.Spec.Containers).Should(ContainElement(MatchFields(IgnoreExtras, Fields{
				"SecurityContext": PointTo(MatchFields(IgnoreExtras, Fields{
					"RunAsNonRoot":             PointTo(BeFalse()),
					"AllowPrivilegeEscalation": BeNil(),
					"Privileged":               PointTo(BeTrue()),
					"ReadOnlyRootFilesystem":   BeNil(),
					"Capabilities":             BeNil(),
					"SELinuxOptions":           BeNil(),
					"WindowsOptions":           BeNil(),
					"RunAsUser":                PointTo(BeNumerically("==", 1000)),
					"RunAsGroup":               BeNil(),
					"ProcMount":                BeNil(),
					"SeccompProfile":           BeNil(),
				})),
			})))

			Expect(deployment.Spec.Template.Spec.SecurityContext).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"SELinuxOptions":      BeNil(),
				"WindowsOptions":      BeNil(),
				"RunAsUser":           PointTo(BeNumerically("==", 1000)),
				"RunAsGroup":          BeNil(),
				"RunAsNonRoot":        PointTo(BeFalse()),
				"SupplementalGroups":  BeNil(),
				"FSGroup":             BeNil(),
				"Sysctls":             BeNil(),
				"FSGroupChangePolicy": BeNil(),
				"SeccompProfile":      BeNil(),
			})))
		})

		It("should create the policy server configmap empty if no policies are assigned ", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			configmap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(configmap).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: Equal("{}"),
					constants.PolicyServerConfigSourcesEntry:  Equal("{}"),
				}),
			})))
		})

		It("should create the policy server configmap with the same labels as the other policy server resources", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			configmap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Expect(configmap.Labels).To(HaveKeyWithValue(constants.PolicyServerLabelKey, policyServerName))
			for k, v := range policyServer.CommonLabels() {
				Expect(configmap.Labels).To(HaveKeyWithValue(k, v))
			}
		})

		It("should add the Kubewarden finalizer during reconciliation when it is missing", func() {
			// PolicyServers kept across a Helm uninstall/reinstall cycle have
			// their finalizers stripped by the uninstall cleanup, and the reconciler
			// must add them back.
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() (*policiesv1.PolicyServer, error) {
				return getTestPolicyServer(ctx, policyServerName)
			}, timeout, pollInterval).Should(
				HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
			)
		})

		It("should create the policy server configmap with the assigned policies", func() {
			timeoutEvalSeconds := int32(5)

			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			admissionPolicy := policiesv1.NewAdmissionPolicyFactory().
				WithMessage("This is a test message").
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())

			clusterAdmissionPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				WithTimeoutEvalSeconds(&timeoutEvalSeconds).
				WithContextAwareResources([]policiesv1.ContextAwareResource{
					{
						APIVersion: "v1",
						Kind:       "Pod",
					},
					{
						APIVersion: "v1",
						Kind:       "Deployment",
					},
				}).
				Build()
			Expect(k8sClient.Create(ctx, clusterAdmissionPolicy)).To(Succeed())

			admissionPolicyGroup := policiesv1.NewAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicyGroup)).To(Succeed())

			clusterPolicyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				WithMembers(policiesv1.PolicyGroupMembersWithContext{
					"pod_privileged": {
						PolicyGroupMember: policiesv1.PolicyGroupMember{
							Module:             "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
							TimeoutEvalSeconds: &timeoutEvalSeconds,
						},
						ContextAwareResources: []policiesv1.ContextAwareResource{
							{
								APIVersion: "v1",
								Kind:       "Pod",
							},
						},
					},
					"user_group_psp": {
						PolicyGroupMember: policiesv1.PolicyGroupMember{
							Module: "registry://ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
						},
						ContextAwareResources: []policiesv1.ContextAwareResource{
							{
								APIVersion: "v1",
								Kind:       "Deployment",
							},
						},
					},
				}).
				Build()
			Expect(k8sClient.Create(ctx, clusterPolicyGroup)).To(Succeed())

			policiesMap := policyConfigEntryMap{}
			policiesMap[admissionPolicy.GetUniqueName()] = policyServerConfigEntry{
				NamespacedName: types.NamespacedName{
					Namespace: admissionPolicy.GetNamespace(),
					Name:      admissionPolicy.GetName(),
				},
				Module:                admissionPolicy.GetModule(),
				PolicyMode:            string(admissionPolicy.GetPolicyMode()),
				AllowedToMutate:       admissionPolicy.IsMutating(),
				Settings:              admissionPolicy.GetSettings(),
				ContextAwareResources: admissionPolicy.GetContextAwareResources(),
				Message:               admissionPolicy.GetMessage(),
				TimeoutEvalSeconds:    admissionPolicy.GetTimeoutEvalSeconds(),
				HostCapabilities:      []string{"*"},
			}
			policiesMap[clusterAdmissionPolicy.GetUniqueName()] = policyServerConfigEntry{
				NamespacedName: types.NamespacedName{
					Namespace: clusterAdmissionPolicy.GetNamespace(),
					Name:      clusterAdmissionPolicy.GetName(),
				},
				Module:                clusterAdmissionPolicy.GetModule(),
				PolicyMode:            string(clusterAdmissionPolicy.GetPolicyMode()),
				AllowedToMutate:       clusterAdmissionPolicy.IsMutating(),
				Settings:              clusterAdmissionPolicy.GetSettings(),
				ContextAwareResources: clusterAdmissionPolicy.GetContextAwareResources(),
				TimeoutEvalSeconds:    clusterAdmissionPolicy.GetTimeoutEvalSeconds(),
				HostCapabilities:      []string{"*"},
			}
			policiesMap[admissionPolicyGroup.GetUniqueName()] = policyServerConfigEntry{
				NamespacedName: types.NamespacedName{
					Namespace: admissionPolicyGroup.GetNamespace(),
					Name:      admissionPolicyGroup.GetName(),
				},
				Module:                admissionPolicyGroup.GetModule(),
				PolicyMode:            string(admissionPolicyGroup.GetPolicyMode()),
				AllowedToMutate:       admissionPolicyGroup.IsMutating(),
				Settings:              admissionPolicyGroup.GetSettings(),
				ContextAwareResources: admissionPolicyGroup.GetContextAwareResources(),
				Policies:              buildPolicyGroupMembersWithContext(admissionPolicyGroup.GetPolicyGroupMembersWithContext(), []string{"*"}),
				Expression:            admissionPolicyGroup.GetExpression(),
				Message:               admissionPolicyGroup.GetMessage(),
				TimeoutEvalSeconds:    &timeoutEvalSeconds,
			}
			policiesMap[clusterPolicyGroup.GetUniqueName()] = policyServerConfigEntry{
				NamespacedName: types.NamespacedName{
					Namespace: clusterPolicyGroup.GetNamespace(),
					Name:      clusterPolicyGroup.GetName(),
				},
				Module:                clusterPolicyGroup.GetModule(),
				AllowedToMutate:       clusterPolicyGroup.IsMutating(),
				Settings:              clusterPolicyGroup.GetSettings(),
				ContextAwareResources: clusterPolicyGroup.GetContextAwareResources(),
				PolicyMode:            string(clusterPolicyGroup.GetPolicyMode()),
				Policies:              buildPolicyGroupMembersWithContext(clusterPolicyGroup.GetPolicyGroupMembersWithContext(), []string{"*"}),
				Expression:            clusterPolicyGroup.GetExpression(),
				Message:               clusterPolicyGroup.GetMessage(),
				TimeoutEvalSeconds:    &timeoutEvalSeconds,
			}

			// During the migration away from the legacy unique names, the
			// configuration also serves every policy under its legacy name.
			addLegacyPolicyEntries(policiesMap, []policiesv1.Policy{
				admissionPolicy,
				clusterAdmissionPolicy,
				admissionPolicyGroup,
				clusterPolicyGroup,
			}, logr.Discard())

			policies, err := json.Marshal(policiesMap)
			Expect(err).ToNot(HaveOccurred())

			// As we have a customization in how we serialize the policies,
			// let's check if the result json is in the expected format.
			// Otherwise, the policy server will not start.
			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						MatchJSON(policies),
						// Let's validate the custom marshalling
						WithTransform(func(data string) (map[string]interface{}, error) {
							policiesData := map[string]interface{}{}
							err = json.Unmarshal(policies, &policiesData)
							return policiesData, err
						}, MatchKeys(IgnoreExtras, Keys{
							admissionPolicy.GetUniqueName(): And(MatchKeys(IgnoreExtras, Keys{
								"namespacedName": MatchAllKeys(Keys{
									"Namespace": Equal(admissionPolicy.GetNamespace()),
									"Name":      Equal(admissionPolicy.GetName()),
								}),
								"module":           Equal(admissionPolicy.GetModule()),
								"policyMode":       Equal(string(admissionPolicy.GetPolicyMode())),
								"message":          Equal(admissionPolicy.GetMessage()),
								"hostCapabilities": ConsistOf("*"),
							}),
								Not(MatchAllKeys(Keys{
									"timeoutEvalSeconds": Ignore(),
								}))),
							clusterAdmissionPolicy.GetUniqueName(): And(MatchAllKeys(Keys{
								"namespacedName": MatchAllKeys(Keys{
									"Namespace": Equal(clusterAdmissionPolicy.GetNamespace()),
									"Name":      Equal(clusterAdmissionPolicy.GetName()),
								}),
								"module":             Equal(clusterAdmissionPolicy.GetModule()),
								"policyMode":         Equal(string(clusterAdmissionPolicy.GetPolicyMode())),
								"allowedToMutate":    Equal(clusterAdmissionPolicy.IsMutating()),
								"timeoutEvalSeconds": BeNumerically("==", *clusterAdmissionPolicy.GetTimeoutEvalSeconds()),
								"settings":           BeNil(),
								"hostCapabilities":   ConsistOf("*"),
								"contextAwareResources": And(ContainElement(MatchAllKeys(Keys{
									"apiVersion": Equal("v1"),
									"kind":       Equal("Pod"),
								})), ContainElement(MatchAllKeys(Keys{
									"apiVersion": Equal("v1"),
									"kind":       Equal("Deployment"),
								})), HaveLen(2)),
							}), Not(MatchAllKeys(Keys{
								"expression": Ignore(),
								"message":    Ignore(),
								"policies":   Ignore(),
							}))),
							admissionPolicyGroup.GetUniqueName(): And(MatchKeys(IgnoreExtras, Keys{
								"namespacedName": MatchAllKeys(Keys{
									"Namespace": Equal(admissionPolicyGroup.GetNamespace()),
									"Name":      Equal(admissionPolicyGroup.GetName()),
								}),
								"policies": MatchKeys(IgnoreExtras, Keys{
									"pod_privileged": And(MatchKeys(IgnoreExtras, Keys{
										"module":           Equal(admissionPolicyGroup.GetPolicyGroupMembersWithContext()["pod_privileged"].Module),
										"hostCapabilities": ConsistOf("*"),
									}), Not(MatchAllKeys(Keys{
										"timeoutEvalSeconds": Ignore(),
									}))),
								}),
								"policyMode": Equal(string(admissionPolicyGroup.GetPolicyMode())),
								"expression": Equal(admissionPolicyGroup.GetExpression()),
								"message":    Equal(admissionPolicyGroup.GetMessage()),
							}), Not(MatchAllKeys(Keys{
								"timeoutEvalSeconds": Ignore(),
							}))),
							clusterPolicyGroup.GetUniqueName(): And(MatchAllKeys(Keys{
								"namespacedName": MatchAllKeys(Keys{
									"Namespace": Equal(clusterPolicyGroup.GetNamespace()),
									"Name":      Equal(clusterPolicyGroup.GetName()),
								}),
								"policies": MatchKeys(IgnoreExtras, Keys{
									"pod_privileged": MatchAllKeys(Keys{
										"module":             Equal(clusterPolicyGroup.GetPolicyGroupMembersWithContext()["pod_privileged"].Module),
										"settings":           Ignore(),
										"timeoutEvalSeconds": BeNumerically("==", timeoutEvalSeconds),
										"hostCapabilities":   ConsistOf("*"),
										"contextAwareResources": And(ContainElement(MatchAllKeys(Keys{
											"apiVersion": Equal("v1"),
											"kind":       Equal("Pod"),
										})), HaveLen(1)),
									}),
									"user_group_psp": And(MatchAllKeys(Keys{
										"module":           Equal(clusterPolicyGroup.GetPolicyGroupMembersWithContext()["user_group_psp"].Module),
										"settings":         Ignore(),
										"hostCapabilities": ConsistOf("*"),
										"contextAwareResources": And(ContainElement(MatchAllKeys(Keys{
											"apiVersion": Equal("v1"),
											"kind":       Equal("Deployment"),
										})), HaveLen(1)),
									}), Not(MatchAllKeys(Keys{
										"timeoutEvalSeconds": Ignore(),
									}))),
								}),
								"policyMode": Equal(string(clusterPolicyGroup.GetPolicyMode())),
								"expression": Equal(clusterPolicyGroup.GetExpression()),
								"message":    Equal(clusterPolicyGroup.GetMessage()),
							}),
								Not(MatchKeys(IgnoreExtras, Keys{
									"settings":           Ignore(),
									"timeoutEvalSeconds": Ignore(),
								}))),
						}),
						)),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should set * on namespaced and cluster-wide policy group members when PolicyServer has no NamespacedPoliciesCapabilities", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			admissionPolicyGroup := policiesv1.NewAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicyGroup)).To(Succeed())

			clusterPolicyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, clusterPolicyGroup)).To(Succeed())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						policyGroupHostCapabilitiesMatcher(admissionPolicyGroup, clusterPolicyGroup, ConsistOf("*"), ConsistOf("*")),
					),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should set host capabilities on namespaced policy group members from PolicyServer NamespacedPoliciesCapabilities and * on cluster-wide group members", func() {
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				WithNamespacedPoliciesCapabilities([]string{"net/*"}).
				Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			admissionPolicyGroup := policiesv1.NewAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicyGroup)).To(Succeed())

			clusterPolicyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, clusterPolicyGroup)).To(Succeed())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						policyGroupHostCapabilitiesMatcher(admissionPolicyGroup, clusterPolicyGroup, ConsistOf("net/*"), ConsistOf("*")),
					),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should set * on namespaced and cluster-wide admission policies when PolicyServer has no NamespacedPoliciesCapabilities", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			admissionPolicy := policiesv1.NewAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())

			clusterAdmissionPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, clusterAdmissionPolicy)).To(Succeed())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						admissionPolicyHostCapabilitiesMatcher(admissionPolicy, clusterAdmissionPolicy, ConsistOf("*"), ConsistOf("*")),
					),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should set host capabilities on namespaced admission policies from PolicyServer NamespacedPoliciesCapabilities and * on cluster-wide admission policies", func() {
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				WithNamespacedPoliciesCapabilities([]string{"net/*"}).
				Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			admissionPolicy := policiesv1.NewAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())

			clusterAdmissionPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, clusterAdmissionPolicy)).To(Succeed())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						admissionPolicyHostCapabilitiesMatcher(admissionPolicy, clusterAdmissionPolicy, ConsistOf("net/*"), ConsistOf("*")),
					),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should deny all host capabilities to namespaced admission policies when PolicyServer has an empty NamespacedPoliciesCapabilities list", func() {
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				WithNamespacedPoliciesCapabilities([]string{}). // empty list, must stay
				Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			// The reconciler adds its finalizer with a write of the full
			// PolicyServer. That write must keep the empty list.
			Eventually(func() (*policiesv1.PolicyServer, error) {
				return getTestPolicyServer(ctx, policyServerName)
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"ObjectMeta": MatchFields(IgnoreExtras, Fields{
					"Finalizers": ContainElement(constants.KubewardenFinalizer),
				}),
				"Spec": MatchFields(IgnoreExtras, Fields{
					"NamespacedPoliciesCapabilities": And(Not(BeNil()), BeEmpty()),
				}),
			})))

			admissionPolicy := policiesv1.NewAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())

			clusterAdmissionPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, clusterAdmissionPolicy)).To(Succeed())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(ctx, policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: And(
						admissionPolicyHostCapabilitiesMatcher(admissionPolicy, clusterAdmissionPolicy, And(Not(BeNil()), BeEmpty()), ConsistOf("*")),
					),
					constants.PolicyServerConfigSourcesEntry: Equal("{}"),
				}),
			})))
		})

		It("should create the policy server configmap with the sources authorities", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.InsecureSources = []string{"localhost:5000"}
			policyServer.Spec.SourceAuthorities = map[string][]string{
				"myprivateregistry:5000": {"cert1", "cert2"},
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			sourceAuthoriries := map[string][]map[string]string{}
			for uri, certificates := range policyServer.Spec.SourceAuthorities {
				certs := []map[string]string{}
				for _, cert := range certificates {
					certs = append(certs, map[string]string{
						"type": "Data",
						"data": cert,
					})
				}
				sourceAuthoriries[uri] = certs
			}
			sources, err := json.Marshal(map[string]interface{}{
				"insecure_sources":   policyServer.Spec.InsecureSources,
				"source_authorities": sourceAuthoriries,
			})
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() error {
				_, err := getTestPolicyServerConfigMap(ctx, policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())

			configMap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Expect(configMap).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: Equal("{}"),
					constants.PolicyServerConfigSourcesEntry:  MatchJSON(sources),
				}),
			})))
		})

		It("should create PodDisruptionBudget when policy server has MinAvailable configuration set", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			minAvailable := intstr.FromInt(2)
			policyServer.Spec.MinAvailable = &minAvailable
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(ctx, policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, &minAvailable, nil))
		})

		It("should create PodDisruptionBudget when policy server has MaxUnavailable configuration set", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			maxUnavailable := intstr.FromInt(2)
			policyServer.Spec.MaxUnavailable = &maxUnavailable
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(ctx, policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
		})

		It("should not create PodDisruptionBudget when policy server has no PDB configuration", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Consistently(func() error {
				_, err := getPolicyServerPodDisruptionBudget(ctx, policyServerName)
				return err
			}, consistencyTimeout, pollInterval).ShouldNot(Succeed())
		})

		It("should create the PolicyServer deployment with the limits and the requests", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Limits = corev1.ResourceList{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("1Gi"),
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			By("creating a deployment with limits and requests set")
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(deployment.Spec.Template.Spec.Containers[0].Resources.Limits).To(Equal(policyServer.Spec.Limits))
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should use all custom ports", func() {
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				WithWebhookPort(9443).
				WithReadinessProbePort(9081).
				WithMetricsPort(9080).
				Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			By("checking all custom port env vars in the deployment")
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				container := deployment.Spec.Template.Spec.Containers[0]
				envMap := make(map[string]string)
				for _, env := range container.Env {
					envMap[env.Name] = env.Value
				}

				Expect(envMap).To(HaveKeyWithValue("KUBEWARDEN_PORT", strconv.Itoa(9443)))
				Expect(envMap).To(HaveKeyWithValue("KUBEWARDEN_READINESS_PROBE_PORT", strconv.Itoa(9081)))
				Expect(envMap).To(HaveKeyWithValue(constants.PolicyServerEnableMetricsEnvVar, "true"))

				By("checking readiness probe port")
				Expect(container.ReadinessProbe).ToNot(BeNil())
				Expect(container.ReadinessProbe.HTTPGet).ToNot(BeNil())
				Expect(container.ReadinessProbe.HTTPGet.Port).To(Equal(intstr.FromInt32(9081)))

				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("checking the service targetPort matches custom webhook port")
			Eventually(func() error {
				service, err := getTestPolicyServerService(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(service.Spec.Ports).To(ContainElement(MatchFields(IgnoreExtras, Fields{
					"Name":       Equal("policy-server"),
					"Port":       Equal(int32(constants.PolicyServerServicePort)),
					"TargetPort": Equal(intstr.FromInt32(9443)),
				})))
				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("checking the service metrics port matches custom metrics port")
			Eventually(func() error {
				service, err := getTestPolicyServerService(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(service.Spec.Ports).To(ContainElement(MatchFields(IgnoreExtras, Fields{
					"Name":       Equal("metrics"),
					"Port":       Equal(int32(9080)),
					"TargetPort": Equal(intstr.FromInt32(constants.PolicyServerMetricsPort)),
					"Protocol":   Equal(corev1.ProtocolTCP),
				})))
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should create deployment with owner reference", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(deployment.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":  Equal(policyServer.GetUID()),
						"Name": Equal(policyServer.GetName()),
						//nolint:godox //We have some tests requiring some investigation to fix some FIXME comments
						// FIXME: for some reason GroupVersionKind is not set
						// "Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						// "APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should create configmap with owner reference", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				configmap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(configmap.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":  Equal(policyServer.GetUID()),
						"Name": Equal(policyServer.GetName()),
						// FIXME: for some reason GroupVersionKind is not set
						// "Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						// "APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should create service with owner reference and correct labels", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				service, err := getTestPolicyServerService(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				Expect(service.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":  Equal(policyServer.GetUID()),
						"Name": Equal(policyServer.GetName()),
						// FIXME: for some reason GroupVersionKind is not set
						// "Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						// "APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				// This is the new port used by the policy server service
				Expect(service.Spec.Ports).To(ContainElement(MatchFields(IgnoreExtras, Fields{
					"Port":       Equal(int32(constants.PolicyServerServicePort)),
					"TargetPort": Equal(intstr.IntOrString{IntVal: int32(constants.PolicyServerListenPort)}),
				})))
				// This checks that the service has the legacy and recommended labels
				// TODO simplify this with a future release
				for k, v := range policyServer.CommonLabels() {
					Expect(service.ObjectMeta.Labels).To(HaveKeyWithValue(k, v))
				}
				return nil
			}).Should(Succeed())
		})

		It("should create the policy server secrets", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				secret, err := getTestPolicyServerSecret(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}

				By("creating a secret containing the TLS certificate and key")
				Expect(secret.Data).To(HaveKey(constants.ServerCert))
				Expect(secret.Data).To(HaveKey(constants.ServerPrivateKey))

				By("setting the secret owner reference")
				Expect(secret.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":  Equal(policyServer.GetUID()),
						"Name": Equal(policyServer.GetName()),
						// FIXME: for some reason GroupVersionKind is not set
						// "Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						// "APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should enable mTLS in the policy server deployment", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			container := deployment.Spec.Template.Spec.Containers[0]

			kubewardenCAPath := filepath.Join(kubewardenCAVolumePath, constants.CARootCert)
			clientCAPath := filepath.Join(clientCAVolumePath, constants.ClientCACert)
			By("specifying the client ca certificate")
			Expect(container.Env).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Name":  Equal("KUBEWARDEN_CLIENT_CA_FILE"),
				"Value": Equal(fmt.Sprintf("%s,%s", kubewardenCAPath, clientCAPath)),
			})))

			By("mounting the kubewarden CA Secret")
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Name": Equal(kubewardenCAVolumeName),
				"VolumeSource": MatchFields(IgnoreExtras, Fields{
					"Secret": PointTo(MatchFields(IgnoreExtras, Fields{
						"SecretName": Equal(constants.CARootSecretName),
						"Items": ConsistOf(MatchFields(IgnoreExtras, Fields{
							"Key":  Equal(constants.CARootCert),
							"Path": Equal(constants.CARootCert),
						})),
					})),
				}),
			})))
			Expect(container.VolumeMounts).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Name":      Equal(kubewardenCAVolumeName),
				"MountPath": Equal(kubewardenCAVolumePath),
			})))

			By("mounting the client CA ConfigMap")
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Name": Equal(clientCAVolumeName),
				"VolumeSource": MatchFields(IgnoreExtras, Fields{
					"ConfigMap": PointTo(MatchFields(IgnoreExtras, Fields{
						"LocalObjectReference": MatchFields(IgnoreExtras, Fields{
							"Name": Equal(clientCAConfigMapName),
						}),
						"Items": ConsistOf(MatchFields(IgnoreExtras, Fields{
							"Key":  Equal(constants.ClientCACert),
							"Path": Equal(constants.ClientCACert),
						})),
					})),
				}),
			})))
			Expect(container.VolumeMounts).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Name":      Equal(clientCAVolumeName),
				"MountPath": Equal(clientCAVolumePath),
			})))
		})

		It("should propagate custom labels from spec.labels to the Deployment and Pod template, with system labels taking precedence", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Labels = map[string]string{
				"custom-label":                 "custom-value",
				"another-label":                "another-value",
				constants.PolicyServerLabelKey: "should-be-overridden",
				"app.kubernetes.io/managed-by": "should-be-overridden",
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				// Custom labels should appear on Deployment ObjectMeta
				Expect(deployment.ObjectMeta.Labels).To(HaveKeyWithValue("custom-label", "custom-value"))
				Expect(deployment.ObjectMeta.Labels).To(HaveKeyWithValue("another-label", "another-value"))
				// Custom labels should appear on Pod template
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("custom-label", "custom-value"))
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("another-label", "another-value"))
				// System labels must not be overridden by user labels
				Expect(deployment.ObjectMeta.Labels).To(HaveKeyWithValue(constants.PolicyServerLabelKey, policyServerName))
				Expect(deployment.ObjectMeta.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "kubewarden-controller"))
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue(constants.PolicyServerLabelKey, policyServerName))
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "kubewarden-controller"))
				return nil
			}).Should(Succeed())
		})

		It("should propagate custom annotations from spec.annotations to the Deployment ObjectMeta and Pod template", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Annotations = map[string]string{
				"custom-annotation":  "custom-value",
				"another-annotation": "another-value",
			}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				// Custom annotations should appear on Deployment ObjectMeta
				Expect(deployment.ObjectMeta.Annotations).To(HaveKeyWithValue("custom-annotation", "custom-value"))
				Expect(deployment.ObjectMeta.Annotations).To(HaveKeyWithValue("another-annotation", "another-value"))
				// Custom annotations should appear on Pod template
				Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(HaveKeyWithValue("custom-annotation", "custom-value"))
				Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(HaveKeyWithValue("another-annotation", "another-value"))
				// System annotation must still be present
				Expect(deployment.ObjectMeta.Annotations).To(HaveKey(constants.PolicyServerDeploymentConfigVersionAnnotation))
				return nil
			}).Should(Succeed())
		})

		It("should remove stale labels and annotations from the Deployment when they are removed from spec", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Labels = map[string]string{"stale-label": "value"}
			policyServer.Spec.Annotations = map[string]string{"stale-annotation": "value"}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			// Confirm they appear initially on both Deployment ObjectMeta and Pod template
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if _, ok := deployment.ObjectMeta.Labels["stale-label"]; !ok {
					return errors.New("stale-label not yet present on Deployment ObjectMeta")
				}
				if _, ok := deployment.ObjectMeta.Annotations["stale-annotation"]; !ok {
					return errors.New("stale-annotation not yet present on Deployment ObjectMeta")
				}
				if _, ok := deployment.Spec.Template.ObjectMeta.Labels["stale-label"]; !ok {
					return errors.New("stale-label not yet present on Pod template")
				}
				if _, ok := deployment.Spec.Template.ObjectMeta.Annotations["stale-annotation"]; !ok {
					return errors.New("stale-annotation not yet present on Pod template")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())

			// Remove both from spec
			Eventually(func() error {
				ps, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				ps.Spec.Labels = nil
				ps.Spec.Annotations = nil
				return k8sClient.Update(ctx, ps)
			}, timeout, pollInterval).Should(Succeed())

			// Verify they are gone from both Deployment ObjectMeta and Pod template
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if _, ok := deployment.ObjectMeta.Labels["stale-label"]; ok {
					return errors.New("stale-label still present on Deployment ObjectMeta after removal from spec")
				}
				if _, ok := deployment.ObjectMeta.Annotations["stale-annotation"]; ok {
					return errors.New("stale-annotation still present on Deployment ObjectMeta after removal from spec")
				}
				if _, ok := deployment.Spec.Template.ObjectMeta.Labels["stale-label"]; ok {
					return errors.New("stale-label still present on Pod template after removal from spec")
				}
				if _, ok := deployment.Spec.Template.ObjectMeta.Annotations["stale-annotation"]; ok {
					return errors.New("stale-annotation still present on Pod template after removal from spec")
				}
				// System labels and annotations must still be present
				Expect(deployment.ObjectMeta.Labels).To(HaveKey(constants.PolicyServerLabelKey))
				Expect(deployment.ObjectMeta.Annotations).To(HaveKey(constants.PolicyServerDeploymentConfigVersionAnnotation))
				Expect(deployment.Spec.Template.ObjectMeta.Labels).To(HaveKey(constants.PolicyServerLabelKey))
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should preserve non-user-managed annotations on the Deployment when reconciling", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.Annotations = map[string]string{"user-annotation": "user-value"}
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			// Wait for the user annotation to appear on the Deployment.
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if _, ok := deployment.ObjectMeta.Annotations["user-annotation"]; !ok {
					return errors.New("user-annotation not yet present on Deployment ObjectMeta")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())

			// Simulate an external controller (e.g. Kubernetes deployment controller) adding
			// an annotation directly to the Deployment.
			const externalAnnotation = "some-external-tool/annotation"
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				deployment.ObjectMeta.Annotations[externalAnnotation] = "external-value"
				return k8sClient.Update(ctx, deployment)
			}, timeout, pollInterval).Should(Succeed())

			// Trigger a reconcile by updating the PolicyServer spec (remove the user annotation).
			Eventually(func() error {
				ps, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				ps.Spec.Annotations = nil
				return k8sClient.Update(ctx, ps)
			}, timeout, pollInterval).Should(Succeed())

			// The user annotation must be gone, but the external annotation must survive.
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if _, ok := deployment.ObjectMeta.Annotations["user-annotation"]; ok {
					return errors.New("user-annotation still present after removal from spec")
				}
				if _, ok := deployment.ObjectMeta.Annotations[externalAnnotation]; !ok {
					return errors.New("external annotation was unexpectedly removed by the controller")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should set the configMap version as a deployment annotation", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			configmap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should update the configMap version after adding a policy", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			initialConfigMap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != initialConfigMap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != initialConfigMap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())

			policyName := newName("validating-policy")
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			Eventually(func() error {
				configmap, err := getTestPolicyServerConfigMap(ctx, policyServerName)
				if err != nil {
					return err
				}
				if configmap.GetResourceVersion() == initialConfigMap.GetResourceVersion() {
					return errors.New("configmap version did not change")
				}
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should not have sigstore configuration when SigstoreTrustConfig is not set", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			policyServer.Spec.SigstoreTrustConfig = ""

			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"Volumes": Not(ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
							}))),
							"Containers": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(getPolicyServerNameWithPrefix(policyServerName)),
								"VolumeMounts": Not(ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name": Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
								}))),
								"Env": Not(ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name": Equal(constants.PolicyServerSigstoreTrustConfigEnvVar),
								}))),
							})),
						}),
					}),
				}),
			})))
		})

		It("should configure sigstore settings when SigstoreTrustConfig is provided", func() {
			configMapName := newName("sigstore-config")
			createConfigMapWithSigstoreTrustConfig(ctx, configMapName)

			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				WithSigstoreTrustConfigMap(configMapName).
				Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			expectedPath := filepath.Join(constants.PolicyServerSigstoreTrustConfigContainerPath, constants.PolicyServerSigstoreTrustConfigFilename)
			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"Volumes": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
								"VolumeSource": MatchFields(IgnoreExtras, Fields{
									"ConfigMap": PointTo(MatchFields(IgnoreExtras, Fields{
										"LocalObjectReference": MatchFields(IgnoreExtras, Fields{
											"Name": Equal(configMapName),
										}),
									})),
								}),
							})),
							"Containers": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(getPolicyServerNameWithPrefix(policyServerName)),
								"VolumeMounts": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":      Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
									"MountPath": Equal(constants.PolicyServerSigstoreTrustConfigContainerPath),
									"ReadOnly":  BeTrue(),
								})),
								"Env": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":  Equal(constants.PolicyServerSigstoreTrustConfigEnvVar),
									"Value": Equal(expectedPath),
								})),
							})),
						}),
					}),
				}),
			})))
		})
	})

	When("updating the PolicyServer", func() {
		var policyServer *policiesv1.PolicyServer

		BeforeEach(func() {
			policyServer = policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)
		})

		It("should create a PDB if the policy server definition is updated with a PodDisruptionBudget configuration", func() {
			Consistently(func() error {
				_, err := getPolicyServerPodDisruptionBudget(ctx, policyServerName)
				return err
			}, consistencyTimeout, pollInterval).ShouldNot(Succeed())

			By("updating the PolicyServer with a MaxAvailable PDB configuration")
			policyServer, err := getTestPolicyServer(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			maxUnavailable := intstr.FromInt(2)
			policyServer.Spec.MaxUnavailable = &maxUnavailable
			err = k8sClient.Update(ctx, policyServer)
			Expect(err).ToNot(HaveOccurred())

			By("creating a PodDisruptionBudget with a MaxUnavailable configuration")
			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(ctx, policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
		})

		It("should update deployment when policy server image change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldImage := deployment.Spec.Template.Spec.Containers[0].Image
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Image = "new-image"
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() string {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return ""
				}
				return deployment.Spec.Template.Spec.Containers[0].Image
			}).Should(And(Not(Equal(oldImage)), Equal("new-image")))
		})

		It("should update deployment when policy server replica size change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldReplica := deployment.Spec.Replicas
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Replicas = 2
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() int32 {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return 0
				}
				return *deployment.Spec.Replicas
			}).Should(And(Not(Equal(oldReplica)), Equal(int32(2))))
		})

		It("should update deployment when policy server service account change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldServiceAccount := deployment.Spec.Template.Spec.ServiceAccountName
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.ServiceAccountName = "new-service-account"
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() string {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return ""
				}
				return deployment.Spec.Template.Spec.ServiceAccountName
			}).Should(And(Not(Equal(oldServiceAccount)), Equal("new-service-account")))
		})

		It("should update deployment when policy server security context change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldSecurityContext := deployment.Spec.Template.Spec.SecurityContext
			newUser := int64(1000)
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.SecurityContexts.Pod = &corev1.PodSecurityContext{
					RunAsUser: &newUser,
				}
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() *corev1.PodSecurityContext {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.SecurityContext
			}).Should(And(PointTo(MatchFields(IgnoreExtras, Fields{
				"RunAsUser": PointTo(BeNumerically("==", newUser)),
			})), Not(PointTo(Equal(oldSecurityContext)))))
		})

		It("should update deployment when policy server affinity configuration change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldAffinity := deployment.Spec.Template.Spec.Affinity
			newAffinity := corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "label",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"nodename"},
									},
								},
							},
						},
					},
				},
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Affinity = newAffinity
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() *corev1.Affinity {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Affinity
			}).Should(And(Not(PointTo(Equal(oldAffinity))), PointTo(Equal(newAffinity))))
		})

		It("should update deployment when policy server annotations change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			oldAnnotations := deployment.Spec.Template.Annotations
			newAnnotations := map[string]string{
				"new-annotation": "new-value",
			}

			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Annotations = newAnnotations
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() map[string]string {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Annotations
			}).Should(And(Not(Equal(oldAnnotations)), Equal(newAnnotations)))
		})

		It("should update deployment when policy server resources limits change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			oldContainers := deployment.Spec.Template.Spec.Containers
			newResourceLimits := corev1.ResourceList{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("1Gi"),
			}

			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Limits = newResourceLimits
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() []corev1.Container {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Containers
			}).Should(And(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Resources": MatchFields(IgnoreExtras, Fields{
					"Limits": Equal(newResourceLimits),
				}),
			})), Not(Equal(oldContainers))))
		})

		It("should update deployment when policy server environment variables change", func() {
			deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
			Expect(err).ToNot(HaveOccurred())

			oldContainers := deployment.Spec.Template.Spec.Containers
			newEnvironmentVariable := corev1.EnvVar{
				Name:  "NEW_ENV",
				Value: "new-value",
			}

			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Env = []corev1.EnvVar{newEnvironmentVariable}
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() []corev1.Container {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Containers
			}).Should(And(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Env": ContainElement(Equal(newEnvironmentVariable)),
			})), Not(Equal(oldContainers))))
		})

		It("should update the PolicyServer pod with the new requests when the requests are updated", func() {
			By("updating the PolicyServer requests")
			updatedRequestsResources := corev1.ResourceList{
				"cpu":    resource.MustParse("50m"),
				"memory": resource.MustParse("500Mi"),
			}

			Eventually(func() error {
				policyServer, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Requests = updatedRequestsResources
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			By("updating the deployment with the new requests")
			Eventually(func() (*corev1.Container, error) {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil, err
				}
				return &deployment.Spec.Template.Spec.Containers[0], nil
			}, timeout, pollInterval).Should(
				And(
					HaveField("Resources.Requests", Equal(updatedRequestsResources)),
					HaveField("Resources.Limits", Equal(policyServer.Spec.Limits)),
				),
			)
		})

		It("should update deployment when SigstoreTrustConfig changes", func() {
			configMapName1 := newName("sigstore-config-1")
			createConfigMapWithSigstoreTrustConfig(ctx, configMapName1)

			Eventually(func() error {
				ps, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				ps.Spec.SigstoreTrustConfig = configMapName1
				return k8sClient.Update(ctx, ps)
			}, timeout, pollInterval).Should(Succeed())

			expectedPath := filepath.Join(constants.PolicyServerSigstoreTrustConfigContainerPath, constants.PolicyServerSigstoreTrustConfigFilename)
			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"Volumes": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
								"VolumeSource": MatchFields(IgnoreExtras, Fields{
									"ConfigMap": PointTo(MatchFields(IgnoreExtras, Fields{
										"LocalObjectReference": MatchFields(IgnoreExtras, Fields{
											"Name": Equal(configMapName1),
										}),
									})),
								}),
							})),
							"Containers": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(getPolicyServerNameWithPrefix(policyServerName)),
								"Env": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":  Equal(constants.PolicyServerSigstoreTrustConfigEnvVar),
									"Value": Equal(expectedPath),
								})),
							})),
						}),
					}),
				}),
			})))

			configMapName2 := newName("sigstore-config-2")
			createConfigMapWithSigstoreTrustConfig(ctx, configMapName2)

			Eventually(func() error {
				ps, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return err
				}
				ps.Spec.SigstoreTrustConfig = configMapName2
				return k8sClient.Update(ctx, ps)
			}, timeout, pollInterval).Should(Succeed())

			Eventually(func() string {
				ps, err := getTestPolicyServer(ctx, policyServerName)
				if err != nil {
					return ""
				}
				return ps.Spec.SigstoreTrustConfig
			}, timeout, pollInterval).Should(Equal(configMapName2))

			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"Volumes": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(constants.PolicyServerSigstoreTrustConfigVolumeName),
								"VolumeSource": MatchFields(IgnoreExtras, Fields{
									"ConfigMap": PointTo(MatchFields(IgnoreExtras, Fields{
										"LocalObjectReference": MatchFields(IgnoreExtras, Fields{
											"Name": Equal(configMapName2),
										}),
									})),
								}),
							})),
							"Containers": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(getPolicyServerNameWithPrefix(policyServerName)),
								"Env": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":  Equal(constants.PolicyServerSigstoreTrustConfigEnvVar),
									"Value": Equal(expectedPath),
								})),
							})),
						}),
					}),
				}),
			})))
		})
	})

	When("a PolicyServer has spec.imagePullSecret set", func() {
		It("should mount the Docker config volume but NOT add it to Deployment imagePullSecrets", func() {
			secretName := newName("pull-secret")
			pullSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: deploymentsNamespace,
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`),
				},
			}
			Expect(k8sClient.Create(ctx, pullSecret)).To(haveSucceededOrAlreadyExisted())

			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithImagePullSecret(secretName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"ImagePullSecrets": Not(ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(secretName),
							}))),
							"Volumes": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(imagePullSecretVolumeName),
								"VolumeSource": MatchFields(IgnoreExtras, Fields{
									"Secret": PointTo(MatchFields(IgnoreExtras, Fields{
										"SecretName": Equal(secretName),
									})),
								}),
							})),
							"Containers": ContainElement(MatchFields(IgnoreExtras, Fields{
								"VolumeMounts": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":      Equal(imagePullSecretVolumeName),
									"MountPath": Equal(dockerConfigJSONPolicyServerPath),
								})),
								"Env": ContainElement(MatchFields(IgnoreExtras, Fields{
									"Name":  Equal("KUBEWARDEN_DOCKER_CONFIG_JSON_PATH"),
									"Value": Equal(dockerConfigJSONPolicyServerPath),
								})),
							})),
						}),
					}),
				}),
			})))
		})
	})

	When("a PolicyServer has no spec.imagePullSecret but reconciler has ImagePullSecrets", func() {
		It("should set reconciler secrets in Deployment imagePullSecrets without mounting a Docker config volume", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() *appsv1.Deployment {
				deployment, err := getTestPolicyServerDeployment(ctx, policyServerName)
				if err != nil {
					return nil
				}
				return deployment
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Spec": MatchFields(IgnoreExtras, Fields{
					"Template": MatchFields(IgnoreExtras, Fields{
						"Spec": MatchFields(IgnoreExtras, Fields{
							"ImagePullSecrets": ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(reconcilerImagePullSecret),
							})),
							"Volumes": Not(ContainElement(MatchFields(IgnoreExtras, Fields{
								"Name": Equal(imagePullSecretVolumeName),
							}))),
						}),
					}),
				}),
			})))
		})
	})

	When("deleting a PolicyServer", func() {
		BeforeEach(func() {
			createPolicyServerAndWaitForItsService(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build())
		})

		Context("with no assigned policies", func() {
			It("should get its finalizer removed", func() {
				Expect(
					k8sClient.Delete(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(ctx, policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})

			It("should get its old not domain-qualified finalizer removed", func() {
				Eventually(func() error {
					policyServer, err := getTestPolicyServer(ctx, policyServerName)
					if err != nil {
						return err
					}
					controllerutil.AddFinalizer(policyServer, constants.KubewardenFinalizerPre114)
					return k8sClient.Update(ctx, policyServer)
				}, timeout, pollInterval).Should(Succeed())

				Eventually(func() error {
					policyServer, err := getTestPolicyServer(ctx, policyServerName)
					if err != nil {
						return err
					}
					if controllerutil.ContainsFinalizer(policyServer, constants.KubewardenFinalizerPre114) {
						return nil
					}
					return errors.New("finalizer not found")
				}, timeout, pollInterval).Should(Succeed())

				Expect(
					k8sClient.Delete(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(ctx, policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizerPre114)),
				)
			})
		})

		Context("with assigned policies", func() {
			var policyName string

			BeforeEach(func() {
				policyName = newName("policy")
				Expect(
					k8sClient.Create(ctx, policiesv1.NewClusterAdmissionPolicyFactory().
						WithName(policyName).
						WithPolicyServer(policyServerName).
						Build()),
				).To(Succeed())
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(ctx, policyName)
					return err
				}, timeout, pollInterval).Should(Succeed())
				Expect(
					getTestPolicyServerService(ctx, policyServerName),
				).To(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			It("should set assigned policies as scheduled and remove their webhook configuration", func() {
				policy, err := getTestClusterAdmissionPolicy(ctx, policyName)
				Expect(err).ToNot(HaveOccurred())

				// Manually create the ValidatingWebhookConfiguration to simulate
				// the policy being active. In envtest there are no running pods so
				// policies never reach the active status and the webhook is never
				// created by the controller.
				webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: policy.GetUniqueName(),
						Labels: map[string]string{
							constants.PartOfLabelKey: constants.PartOfLabelValue,
						},
					},
					Webhooks: []admissionregistrationv1.ValidatingWebhook{
						{
							Name:                    policy.GetUniqueName() + constants.WebhookNameSuffix,
							AdmissionReviewVersions: []string{"v1"},
							SideEffects: func() *admissionregistrationv1.SideEffectClass {
								s := admissionregistrationv1.SideEffectClassNone
								return &s
							}(),
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								Service: &admissionregistrationv1.ServiceReference{
									Namespace: deploymentsNamespace,
									Name:      policyServerName,
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, webhook)).To(Succeed())

				Expect(
					k8sClient.Delete(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()),
				).To(Succeed())

				// Policy should transition to scheduled.
				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(ctx, policyName)
				}, timeout, pollInterval).Should(
					HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusScheduled)),
				)

				// The ValidatingWebhookConfiguration must be removed so orphaned
				// webhooks don't block admission requests.
				Eventually(func() error {
					got := admissionregistrationv1.ValidatingWebhookConfiguration{}
					return k8sClient.Get(ctx, types.NamespacedName{Name: policy.GetUniqueName()}, &got)
				}, timeout, pollInterval).ShouldNot(Succeed())

				// Once the webhook is gone the PolicyWebhooksCleanedUp condition
				// must be True and the finalizer must be removed.
				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(ctx, policyServerName)
				}, timeout, pollInterval).Should(And(
					HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizer))),
					HaveField("Status.Conditions", ContainElement(And(
						HaveField("Type", string(policiesv1.PolicyServerPolicyWebhooksCleanedUp)),
						HaveField("Status", metav1.ConditionTrue),
					))),
				))
			})

			It("should not delete assigned policies", func() {
				Expect(
					k8sClient.Delete(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()),
				).To(Succeed())

				// No webhook exists so the finalizer should be removed once the
				// controller confirms there are no outstanding webhook configurations.
				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(ctx, policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)

				// Assigned policies should NOT be deleted by the controller
				Consistently(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(ctx, policyName)
				}, "5s", pollInterval).Should(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
				Expect(
					k8sClient.Delete(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(ctx, policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})
	})
})
