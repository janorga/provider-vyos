/*
Copyright 2020 The Crossplane Authors.

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

// Package apis contains Kubernetes API for the VyOS provider.
package apis

import (
	"k8s.io/apimachinery/pkg/runtime"

	firewallv1alpha1 "github.com/janorga/provider-vyos/apis/firewall/v1alpha1"
	routerv1alpha1 "github.com/janorga/provider-vyos/apis/router/v1alpha1"
	vyosv1alpha1 "github.com/janorga/provider-vyos/apis/v1alpha1"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes,
		vyosv1alpha1.SchemeBuilder.AddToScheme,
		firewallv1alpha1.SchemeBuilder.AddToScheme,
		routerv1alpha1.SchemeBuilder.AddToScheme,
	)
}

// AddToSchemes may be used to add all resources defined in the project to a Scheme
var AddToSchemes runtime.SchemeBuilder

// AddToScheme adds all Resources to the Scheme
func AddToScheme(s *runtime.Scheme) error {
	return AddToSchemes.AddToScheme(s)
}
