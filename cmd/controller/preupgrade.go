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

	"github.com/kubewarden/adm-controller/internal/upgrade"
)

// runPreUpgrade runs the work of the pre-upgrade hook of the Helm chart, with
// a plain client instead of a manager.
func runPreUpgrade(deploymentsNamespace string) error {
	if deploymentsNamespace == "" {
		return errors.New("--deployments-namespace must be provided in pre-upgrade mode")
	}

	k8sClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create the client: %w", err)
	}

	err = upgrade.KeepControllerObjects(ctrl.SetupSignalHandler(), k8sClient, ctrl.Log.WithName("pre-upgrade"), deploymentsNamespace)
	if err != nil {
		return fmt.Errorf("failed to keep the objects of the controller: %w", err)
	}
	return nil
}
