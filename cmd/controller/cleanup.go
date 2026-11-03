/*
Copyright 2021.

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

package main

import (
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/adm-controller/internal/cleanup"
)

// runCleanup runs the uninstall cleanup performed by the Helm chart
// pre-delete hook, using a plain client instead of a manager: no leader
// election, no webhook server, no metrics.
func runCleanup(deploymentsNamespace, controllerDeploymentName string) error {
	if deploymentsNamespace == "" {
		return errors.New("--deployments-namespace must be provided in cleanup mode")
	}
	if controllerDeploymentName == "" {
		return errors.New("--controller-deployment-name must be provided in cleanup mode")
	}

	k8sClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create the client: %w", err)
	}

	err = cleanup.Run(ctrl.SetupSignalHandler(), k8sClient, ctrl.Log.WithName("cleanup"), cleanup.Options{
		DeploymentsNamespace:     deploymentsNamespace,
		ControllerDeploymentName: controllerDeploymentName,
	})
	if err != nil {
		return fmt.Errorf("failed to run the cleanup: %w", err)
	}
	return nil
}
