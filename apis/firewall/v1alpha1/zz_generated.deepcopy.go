//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroup) DeepCopyInto(out *AddToAddressGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroup.
func (in *AddToAddressGroup) DeepCopy() *AddToAddressGroup {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AddToAddressGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroupList) DeepCopyInto(out *AddToAddressGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AddToAddressGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroupList.
func (in *AddToAddressGroupList) DeepCopy() *AddToAddressGroupList {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AddToAddressGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroupObservation) DeepCopyInto(out *AddToAddressGroupObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroupObservation.
func (in *AddToAddressGroupObservation) DeepCopy() *AddToAddressGroupObservation {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroupObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroupParameters) DeepCopyInto(out *AddToAddressGroupParameters) {
	*out = *in
	if in.AddressGroups != nil {
		in, out := &in.AddressGroups, &out.AddressGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroupParameters.
func (in *AddToAddressGroupParameters) DeepCopy() *AddToAddressGroupParameters {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroupParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroupSpec) DeepCopyInto(out *AddToAddressGroupSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroupSpec.
func (in *AddToAddressGroupSpec) DeepCopy() *AddToAddressGroupSpec {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddToAddressGroupStatus) DeepCopyInto(out *AddToAddressGroupStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	out.AtProvider = in.AtProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddToAddressGroupStatus.
func (in *AddToAddressGroupStatus) DeepCopy() *AddToAddressGroupStatus {
	if in == nil {
		return nil
	}
	out := new(AddToAddressGroupStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DestinationParameters) DeepCopyInto(out *DestinationParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DestinationParameters.
func (in *DestinationParameters) DeepCopy() *DestinationParameters {
	if in == nil {
		return nil
	}
	out := new(DestinationParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Firewall) DeepCopyInto(out *Firewall) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Firewall.
func (in *Firewall) DeepCopy() *Firewall {
	if in == nil {
		return nil
	}
	out := new(Firewall)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Firewall) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallList) DeepCopyInto(out *FirewallList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Firewall, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallList.
func (in *FirewallList) DeepCopy() *FirewallList {
	if in == nil {
		return nil
	}
	out := new(FirewallList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FirewallList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallObservation) DeepCopyInto(out *FirewallObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallObservation.
func (in *FirewallObservation) DeepCopy() *FirewallObservation {
	if in == nil {
		return nil
	}
	out := new(FirewallObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallParameters) DeepCopyInto(out *FirewallParameters) {
	*out = *in
	if in.SourceAddress != nil {
		in, out := &in.SourceAddress, &out.SourceAddress
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallParameters.
func (in *FirewallParameters) DeepCopy() *FirewallParameters {
	if in == nil {
		return nil
	}
	out := new(FirewallParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallSpec) DeepCopyInto(out *FirewallSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallSpec.
func (in *FirewallSpec) DeepCopy() *FirewallSpec {
	if in == nil {
		return nil
	}
	out := new(FirewallSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FirewallStatus) DeepCopyInto(out *FirewallStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	out.AtProvider = in.AtProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FirewallStatus.
func (in *FirewallStatus) DeepCopy() *FirewallStatus {
	if in == nil {
		return nil
	}
	out := new(FirewallStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleParameters) DeepCopyInto(out *RuleParameters) {
	*out = *in
	out.Destination = in.Destination
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleParameters.
func (in *RuleParameters) DeepCopy() *RuleParameters {
	if in == nil {
		return nil
	}
	out := new(RuleParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Ruleset) DeepCopyInto(out *Ruleset) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Ruleset.
func (in *Ruleset) DeepCopy() *Ruleset {
	if in == nil {
		return nil
	}
	out := new(Ruleset)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Ruleset) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetList) DeepCopyInto(out *RulesetList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Ruleset, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetList.
func (in *RulesetList) DeepCopy() *RulesetList {
	if in == nil {
		return nil
	}
	out := new(RulesetList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RulesetList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetObservation) DeepCopyInto(out *RulesetObservation) {
	*out = *in
	in.State.DeepCopyInto(&out.State)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetObservation.
func (in *RulesetObservation) DeepCopy() *RulesetObservation {
	if in == nil {
		return nil
	}
	out := new(RulesetObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetParameters) DeepCopyInto(out *RulesetParameters) {
	*out = *in
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]RuleParameters, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetParameters.
func (in *RulesetParameters) DeepCopy() *RulesetParameters {
	if in == nil {
		return nil
	}
	out := new(RulesetParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetSpec) DeepCopyInto(out *RulesetSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetSpec.
func (in *RulesetSpec) DeepCopy() *RulesetSpec {
	if in == nil {
		return nil
	}
	out := new(RulesetSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetStateParameters) DeepCopyInto(out *RulesetStateParameters) {
	*out = *in
	if in.FollowedRules != nil {
		in, out := &in.FollowedRules, &out.FollowedRules
		*out = make([]int32, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetStateParameters.
func (in *RulesetStateParameters) DeepCopy() *RulesetStateParameters {
	if in == nil {
		return nil
	}
	out := new(RulesetStateParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesetStatus) DeepCopyInto(out *RulesetStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesetStatus.
func (in *RulesetStatus) DeepCopy() *RulesetStatus {
	if in == nil {
		return nil
	}
	out := new(RulesetStatus)
	in.DeepCopyInto(out)
	return out
}
