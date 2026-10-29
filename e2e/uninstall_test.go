package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// errUninstallCheck is the result of the uninstall check. The test environment
// ignores the errors of its Finish steps, so TestMain reads this variable
// and fails the run when it is set.
var errUninstallCheck error

// kubewardenInstalledKey is the key of a context value that the setup sets
// after a successful install of the chart.
type kubewardenInstalledKey struct{}

// uninstallAndCheck returns a Finish step that uninstalls the chart and checks
// that the uninstall leaves only the CRDs and the custom resources of the
// user, without the Kubewarden finalizers.
func uninstallAndCheck(releaseName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		// After a failed setup, there is nothing to uninstall, and the client
		// can point at a cluster that is not the test cluster.
		if installed, _ := ctx.Value(kubewardenInstalledKey{}).(bool); !installed {
			return ctx, nil
		}
		fmt.Fprintln(os.Stderr, "Uninstalling the chart, then checking what the uninstall leaves behind")
		errUninstallCheck = runUninstallCheck(ctx, cfg, releaseName)
		if errUninstallCheck == nil {
			fmt.Fprintln(os.Stderr, "The uninstall check passed")
		}
		// An error would stop the Finish steps that follow: the export of the
		// logs and the deletion of the cluster.
		return ctx, nil
	}
}

func runUninstallCheck(ctx context.Context, cfg *envconf.Config, releaseName string) error {
	r := cfg.Client().Resources()
	if err := policiesv1.AddToScheme(r.GetScheme()); err != nil {
		return fmt.Errorf("failed to add the Kubewarden types to the scheme: %w", err)
	}

	// A policy of the user, which the uninstall must keep. The controller
	// adds the Kubewarden finalizer to it, and the uninstall must remove it.
	userPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
		WithName("uninstall-user-policy").
		WithPolicyServer("default").
		WithoutFinalizers().
		Build()
	if err := r.Create(ctx, userPolicy); err != nil {
		return fmt.Errorf("failed to create the user policy: %w", err)
	}
	if err := wait.For(conditions.New(r).ResourceMatch(userPolicy, func(object k8s.Object) bool {
		return containsFinalizer(object.GetFinalizers(), constants.KubewardenFinalizer)
	}), wait.WithTimeout(2*time.Minute), wait.WithInterval(time.Second)); err != nil {
		return fmt.Errorf("the controller did not add its finalizer to the user policy: %w", err)
	}

	if err := helm.New(cfg.KubeconfigFile()).RunUninstall(
		helm.WithName(releaseName),
		helm.WithNamespace(namespace),
		helm.WithWait(),
		helm.WithTimeout("10m"),
	); err != nil {
		return fmt.Errorf("failed to uninstall the kubewarden helm chart: %w", err)
	}

	var leftovers []string
	err := wait.For(func(ctx context.Context) (bool, error) {
		// Keep the result of the last complete try, for the error message.
		found, findErr := findUninstallLeftovers(ctx, r)
		if findErr != nil {
			return false, findErr
		}
		leftovers = found
		return len(leftovers) == 0, nil
	}, wait.WithTimeout(time.Minute), wait.WithInterval(2*time.Second))
	switch {
	case len(leftovers) > 0:
		// The wait can end during a list call, with an error that only says so.
		return fmt.Errorf("one minute after the uninstall, these objects still exist: %v", leftovers)
	case err != nil:
		return fmt.Errorf("failed to look for the objects that the uninstall left behind: %w", err)
	}

	keptPolicy := &policiesv1.ClusterAdmissionPolicy{}
	if err = r.Get(ctx, userPolicy.GetName(), "", keptPolicy); err != nil {
		return fmt.Errorf("the uninstall did not keep the user policy: %w", err)
	}
	return nil
}

// findUninstallLeftovers returns the objects that the uninstall must remove
// and that still exist.
func findUninstallLeftovers(ctx context.Context, r *resources.Resources) ([]string, error) {
	var leftovers []string

	partOfKubewarden := resources.WithLabelSelector(constants.PartOfLabelKey + "=" + constants.PartOfLabelValue)
	for _, list := range []k8s.ObjectList{
		&admissionregistrationv1.ValidatingWebhookConfigurationList{},
		&admissionregistrationv1.MutatingWebhookConfigurationList{},
	} {
		names, err := listNames(ctx, r, list, partOfKubewarden)
		if err != nil {
			return nil, err
		}
		leftovers = append(leftovers, names...)
	}

	for _, name := range []string{
		constants.CARootSecretName,
		constants.WebhookServerCertSecretName,
		constants.AuditScannerClientCertSecretName,
	} {
		err := r.Get(ctx, name, namespace, &corev1.Secret{})
		switch {
		case err == nil:
			leftovers = append(leftovers, "Secret "+namespace+"/"+name)
		case !apierrors.IsNotFound(err):
			return nil, fmt.Errorf("failed to get the secret %q: %w", name, err)
		}
	}

	for _, newList := range []func() k8s.ObjectList{
		func() k8s.ObjectList { return &policiesv1.PolicyServerList{} },
		func() k8s.ObjectList { return &policiesv1.ClusterAdmissionPolicyList{} },
		func() k8s.ObjectList { return &policiesv1.AdmissionPolicyList{} },
		func() k8s.ObjectList { return &policiesv1.ClusterAdmissionPolicyGroupList{} },
		func() k8s.ObjectList { return &policiesv1.AdmissionPolicyGroupList{} },
	} {
		names, err := listNames(ctx, r, newList(),
			resources.WithLabelSelector(constants.DefaultsManagedByLabelKey+"="+constants.DefaultsManagedByLabelValue))
		if err != nil {
			return nil, err
		}
		leftovers = append(leftovers, names...)

		withFinalizer, err := listNamesWithKubewardenFinalizer(ctx, r, newList())
		if err != nil {
			return nil, err
		}
		leftovers = append(leftovers, withFinalizer...)
	}

	return leftovers, nil
}

// listNames returns the kind and the name of each object of the list.
func listNames(ctx context.Context, r *resources.Resources, list k8s.ObjectList, opts ...resources.ListOption) ([]string, error) {
	objects, err := listObjects(ctx, r, list, opts...)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(objects))
	for _, object := range objects {
		names = append(names, describe(object))
	}
	return names, nil
}

// listNamesWithKubewardenFinalizer returns the kind and the name of each
// object of the list that still has a Kubewarden finalizer.
func listNamesWithKubewardenFinalizer(ctx context.Context, r *resources.Resources, list k8s.ObjectList) ([]string, error) {
	objects, err := listObjects(ctx, r, list)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, object := range objects {
		finalizers := object.GetFinalizers()
		if containsFinalizer(finalizers, constants.KubewardenFinalizer) ||
			containsFinalizer(finalizers, constants.KubewardenFinalizerPre114) {
			names = append(names, describe(object)+" with a Kubewarden finalizer")
		}
	}
	return names, nil
}

func listObjects(ctx context.Context, r *resources.Resources, list k8s.ObjectList, opts ...resources.ListOption) ([]k8s.Object, error) {
	if err := r.List(ctx, list, opts...); err != nil {
		return nil, fmt.Errorf("failed to list %T: %w", list, err)
	}
	items, err := apimeta.ExtractList(list)
	if err != nil {
		return nil, fmt.Errorf("failed to extract the items of %T: %w", list, err)
	}
	objects := make([]k8s.Object, 0, len(items))
	for _, item := range items {
		object, ok := item.(k8s.Object)
		if !ok {
			return nil, errors.New("unexpected list item type")
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func describe(object k8s.Object) string {
	kind := fmt.Sprintf("%T", object)
	if object.GetNamespace() == "" {
		return kind + " " + object.GetName()
	}
	return kind + " " + object.GetNamespace() + "/" + object.GetName()
}
