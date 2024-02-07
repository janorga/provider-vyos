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

package addtoaddressgroup

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/janorga/provider-vyos/apis/firewall/v1alpha1"
	apisv1alpha1 "github.com/janorga/provider-vyos/apis/v1alpha1"
	"github.com/janorga/provider-vyos/internal/features"
	vyosclient "github.com/janorga/vyos-client-go/client-insecure"
)

const (
	errNotAddToAddressGroup = "managed resource is not a AddToAddressGroup custom resource"
	errTrackPCUsage         = "cannot track ProviderConfig usage"
	errGetPC                = "cannot get ProviderConfig"
	errGetCreds             = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A VyOSService
type VyOSService struct {
	pCLI *vyosclient.Client
}

var (
	newVyOSService = func(vyosurl string, apiKey []byte) (*VyOSService, error) {
		c := vyosclient.New(vyosurl, string(apiKey[:]))
		return &VyOSService{
			pCLI: c,
		}, nil
	}
)

// Setup adds a controller that reconciles AddToAddressGroup managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.AddToAddressGroupGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.AddToAddressGroupGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newVyOSService}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.AddToAddressGroup{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(vyosurl string, apiKey []byte) (*VyOSService, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.AddToAddressGroup)
	if !ok {
		return nil, errors.New(errNotAddToAddressGroup)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	vyosurl := cr.Spec.ForProvider.VyosUrl
	svc, err := c.newServiceFn(vyosurl, data)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{service: svc}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service *VyOSService
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.AddToAddressGroup)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotAddToAddressGroup)
	}
	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)

	if len(cr.Status.AtProvider.State.FollowedIPAddress) > 0 && checkNewSpec(cr) {
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	path := "firewall group address-group"
	res, err := c.service.pCLI.Config.Show(ctx, path)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	//*** Put casting response through marshall/unmarshall JSON to deal with nested type coversions
	jsonStr, err := json.Marshal(res)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}
	var resMap map[string]map[string]any
	err = json.Unmarshal([]byte(jsonStr), &resMap)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInParsingAPIResponse")
	}
	groups := cr.Spec.ForProvider.AddressGroups

	resource_exists := false
	resource_modified := false

	for _, group := range groups {
		// make the list of addresses in the group.
		// Check if single address (string)
		// Or multiple addresses ([]string)
		current_address_list := make([]string, 0)
		if val, ok := resMap[group]["address"].(string); ok {
			current_address_list = append(current_address_list, val)
		} else {
			newres := resMap[group]["address"].([]any)
			for _, value := range newres {
				current_address_list = append(current_address_list, value.(string))
			}
		}
		// The resource exist if at least one address in group exists
		// The resource is modified if at least one address in group does not exist
		if slices.Contains(current_address_list, cr.Spec.ForProvider.IPAddress) {
			resource_exists = resource_exists || true
		} else {
			resource_modified = true
		}
	}

	if !resource_exists {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, nil
	}
	if resource_modified {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	//*** Put followed address groups on State
	if len(cr.Status.AtProvider.State.FollowedIPAddress) == 0 {
		putFollowedAddressGroupsOnState(cr)
	}

	cr.Status.SetConditions(xpv1.Available())
	return managed.ExternalObservation{
		// Return false when the external resource does not exist. This lets
		// the managed resource reconciler know that it needs to call Create to
		// (re)create the resource, or that it has successfully been deleted.
		ResourceExists: true,

		// Return false when the external resource exists, but it not up to date
		// with the desired managed resource state. This lets the managed
		// resource reconciler know that it needs to call Update.
		ResourceUpToDate: true,

		// Return any details that may be required to connect to the external
		// resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.AddToAddressGroup)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotAddToAddressGroup)
	}
	fmt.Printf("Creating/Updating: %+v", cr)

	path := "firewall group address-group"

	valueMap := make(map[string]string)
	for _, group := range cr.Spec.ForProvider.AddressGroups {
		valueMap[group+" address"] = cr.Spec.ForProvider.IPAddress
	}

	err := c.service.pCLI.Config.Set(ctx, path, valueMap)

	if err != nil {
		fmt.Printf("Cannot create: %+v", cr)
		fmt.Printf("Error💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥: %+v", err)
	} else {
		fmt.Printf("Creating: %+v", cr)
	}

	//*** Put followed address groups on State
	putFollowedAddressGroupsOnState(cr)

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.AddToAddressGroup)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotAddToAddressGroup)
	}
	spec_address_groups := make([]string, len(cr.Spec.ForProvider.AddressGroups))
	copy(spec_address_groups, cr.Spec.ForProvider.AddressGroups)

	//*** If IP is updated, mark spec address groups as empty to delete all
	if cr.Status.AtProvider.State.FollowedIPAddress != cr.Spec.ForProvider.IPAddress {
		spec_address_groups = []string{""}
	}
	//*** Find groups in followed address groups that are not in spec address groups
	address_group_todelete := make([]string, 0)
	for _, followed_address_group := range cr.Status.AtProvider.State.FollowedAddressGroups {
		found := false
		for _, address_group := range spec_address_groups {
			if followed_address_group == address_group {
				found = true
				break
			}
		}
		if !found {
			address_group_todelete = append(address_group_todelete, followed_address_group)
		}
	}
	//*** Delete not found rules on last applied configuration
	path := "firewall group address-group"

	valueMap := make(map[string]string)
	for _, group := range address_group_todelete {
		valueMap[group+" address"] = cr.Status.AtProvider.State.FollowedIPAddress
	}
	err := c.service.pCLI.Config.Delete(ctx, path, valueMap)
	if err != nil {
		fmt.Printf("Cannot Delete: %+v", cr)
		fmt.Printf("Error: %+v", err)
	} else {
		fmt.Printf("Deleted: %+v", cr)
	}

	//*** Create/Update rules
	fmt.Printf("Creating/Updating: %+v", cr)
	mg_eu, err := c.Create(ctx, mg)

	//*** Put followed address groups on State
	putFollowedAddressGroupsOnState(cr)

	return managed.ExternalUpdate{ConnectionDetails: managed.ExternalUpdate(mg_eu).ConnectionDetails}, err
}
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.AddToAddressGroup)
	if !ok {
		return errors.New(errNotAddToAddressGroup)
	}

	fmt.Printf("Deleting: %+v", cr)
	path := "firewall group address-group"

	valueMap := make(map[string]string)
	for _, group := range cr.Spec.ForProvider.AddressGroups {
		valueMap[group+" address"] = cr.Spec.ForProvider.IPAddress
	}
	err := c.service.pCLI.Config.Delete(ctx, path, valueMap)

	if err != nil {
		fmt.Printf("Cannot Delete: %+v", cr)
		fmt.Printf("Error: %+v", err)
	} else {
		fmt.Printf("Deleted: %+v", cr)
	}

	return nil
}

func putFollowedAddressGroupsOnState(cr *v1alpha1.AddToAddressGroup) {
	//*** Put applied rules on State
	cr.Status.AtProvider.State.FollowedAddressGroups = cr.Spec.ForProvider.AddressGroups
	cr.Status.AtProvider.State.FollowedIPAddress = cr.Spec.ForProvider.IPAddress
}

func checkNewSpec(cr *v1alpha1.AddToAddressGroup) bool {
	if cr.Status.AtProvider.State.FollowedIPAddress != cr.Spec.ForProvider.IPAddress {
		return true
	}
	for _, address_group := range cr.Spec.ForProvider.AddressGroups {
		for _, address_group_followed := range cr.Status.AtProvider.State.FollowedAddressGroups {
			if address_group == address_group_followed {
				return false
			}
		}
	}
	return true
}
