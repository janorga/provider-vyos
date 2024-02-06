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

type DestinationParameters struct {
	Address string `json:"address"`
	Port    int32  `json:"port,omitempty"`
}

type RuleParameters struct {
	RuleNumber  int32                 `json:"ruleNumber"`
	Action      string                `json:"action"`
	Destination DestinationParameters `json:"destination"`
	Protocol    string                `json:"protocol,omitempty"`
}

// RulesetParameters are the configurable fields of a Ruleset.
type RulesetParameters struct {
	VyosUrl string           `json:"vyosUrl"`
	Rules   []RuleParameters `json:"rules"`
}

type StateParameters struct {
	//+optional
	FollowedRules []int32 `json:"followedRules,omitempty"`
}

// RulesetObservation are the observable fields of a Ruleset.
type RulesetObservation struct {
	State StateParameters `json:"state"`
}

// A RulesetSpec defines the desired state of a Ruleset.
type RulesetSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       RulesetParameters `json:"forProvider"`
}

// A RulesetStatus represents the observed state of a Ruleset.
type RulesetStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          RulesetObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Ruleset is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,vyos}
type Ruleset struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RulesetSpec   `json:"spec"`
	Status RulesetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RulesetList contains a list of Ruleset
type RulesetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Ruleset `json:"items"`
}

// Ruleset type metadata.
var (
	RulesetKind             = reflect.TypeOf(Ruleset{}).Name()
	RulesetGroupKind        = schema.GroupKind{Group: Group, Kind: RulesetKind}.String()
	RulesetKindAPIVersion   = RulesetKind + "." + SchemeGroupVersion.String()
	RulesetGroupVersionKind = SchemeGroupVersion.WithKind(RulesetKind)
)

func init() {
	SchemeBuilder.Register(&Ruleset{}, &RulesetList{})
}
