/*
Copyright 2022 The Crossplane Authors.

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

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// AddToAddressGroupParameters are the configurable fields of a AddToAddressGroup.
type AddToAddressGroupParameters struct {
	VyosUrl       string   `json:"vyosUrl"`
	IPAddress     string   `json:"ipAddress"`
	AddressGroups []string `json:"addressGroups"`
}

type AddToAddressGroupStateParameters struct {
	//+optional
	FollowedAddressGroups []string `json:"addressGroups"`

	//+optional
	FollowedIPAddress string `json:"ipAddress"`
}

// AddToAddressGroupObservation are the observable fields of a AddToAddressGroup.
type AddToAddressGroupObservation struct {
	State AddToAddressGroupStateParameters `json:"state"`
}

// A AddToAddressGroupSpec defines the desired state of a AddToAddressGroup.
type AddToAddressGroupSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       AddToAddressGroupParameters `json:"forProvider"`
}

// A AddToAddressGroupStatus represents the observed state of a AddToAddressGroup.
type AddToAddressGroupStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          AddToAddressGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A AddToAddressGroup is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vyos}
type AddToAddressGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AddToAddressGroupSpec   `json:"spec"`
	Status AddToAddressGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AddToAddressGroupList contains a list of AddToAddressGroup
type AddToAddressGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AddToAddressGroup `json:"items"`
}

// AddToAddressGroup type metadata.
var (
	AddToAddressGroupKind             = reflect.TypeOf(AddToAddressGroup{}).Name()
	AddToAddressGroupGroupKind        = schema.GroupKind{Group: Group, Kind: AddToAddressGroupKind}.String()
	AddToAddressGroupKindAPIVersion   = AddToAddressGroupKind + "." + SchemeGroupVersion.String()
	AddToAddressGroupGroupVersionKind = SchemeGroupVersion.WithKind(AddToAddressGroupKind)
)

func init() {
	SchemeBuilder.Register(&AddToAddressGroup{}, &AddToAddressGroupList{})
}
