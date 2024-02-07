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

type RouteParameters struct {
	To               string `json:"to"`
	NextHopInterface string `json:"next-hop-interface"`
}

// StaticRouteParameters are the configurable fields of a StaticRoute.
type StaticRouteParameters struct {
	VyosUrl string          `json:"vyosUrl"`
	Route   RouteParameters `json:"route"`
}

type StateParameters struct {
	FollowedRoute string `json:"followedRoute"`
}

// StaticRouteObservation are the observable fields of a StaticRoute.
type StaticRouteObservation struct {
	State StateParameters `json:"state"`
}

// A StaticRouteSpec defines the desired state of a StaticRoute.
type StaticRouteSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       StaticRouteParameters `json:"forProvider"`
}

// A StaticRouteStatus represents the observed state of a StaticRoute.
type StaticRouteStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          StaticRouteObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A StaticRoute is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vyos}
type StaticRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StaticRouteSpec   `json:"spec"`
	Status StaticRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StaticRouteList contains a list of StaticRoute
type StaticRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StaticRoute `json:"items"`
}

// StaticRoute type metadata.
var (
	StaticRouteKind             = reflect.TypeOf(StaticRoute{}).Name()
	StaticRouteGroupKind        = schema.GroupKind{Group: Group, Kind: StaticRouteKind}.String()
	StaticRouteKindAPIVersion   = StaticRouteKind + "." + SchemeGroupVersion.String()
	StaticRouteGroupVersionKind = SchemeGroupVersion.WithKind(StaticRouteKind)
)

func init() {
	SchemeBuilder.Register(&StaticRoute{}, &StaticRouteList{})
}
