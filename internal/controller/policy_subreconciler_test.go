package controller

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
)

var _ = Describe("Reconcile requests for all the policies", func() {
	ctx := context.Background()

	It("should contain a request for each policy of each namespaced kind", func() {
		admissionPolicy := policiesv1.NewAdmissionPolicyFactory().Build()
		Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())
		admissionPolicyGroup := policiesv1.NewAdmissionPolicyGroupFactory().Build()
		Expect(k8sClient.Create(ctx, admissionPolicyGroup)).To(Succeed())

		Expect(findAllAdmissionPolicies(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(admissionPolicy),
		}))
		Expect(findAllAdmissionPolicyGroups(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(admissionPolicyGroup),
		}))
	})
})
