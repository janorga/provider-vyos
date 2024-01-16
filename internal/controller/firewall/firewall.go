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

package firewall

import (
	"context"
	"fmt"

	"github.com/jeremywohl/flatten"

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
	errNotFirewall  = "managed resource is not a Firewall custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A VyOSService does nothing.
type VyOSService struct {
	pCLI *vyosclient.Client
}

var (
	newVyOSService = func(apiKey []byte) (*VyOSService, error) {
		url := "https://10.7.191.156"
		c := vyosclient.New(url, string(apiKey[:]))

		return &VyOSService{
			pCLI: c,
		}, nil
	}
)

// Setup adds a controller that reconciles Firewall managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.FirewallGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.FirewallGroupVersionKind),
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
		For(&v1alpha1.Firewall{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(apiKey []byte) (*VyOSService, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Firewall)
	if !ok {
		return nil, errors.New(errNotFirewall)
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

	svc, err := c.newServiceFn(data)
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
	cr, ok := mg.(*v1alpha1.Firewall)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotFirewall)
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)

	ruleNumber := cr.Spec.ForProvider.RuleNumber
	valueMap := make(map[string]string)
	valueMap["action"] = cr.Spec.ForProvider.Action
	valueMap["destination address"] = cr.Spec.ForProvider.DestinationAddress
	if cr.Spec.ForProvider.SourceAddress != nil && *cr.Spec.ForProvider.SourceAddress != "" {
		valueMap["source address"] = *cr.Spec.ForProvider.SourceAddress
	}

	path := "firewall name LAN-INBOUND rule " + fmt.Sprint(ruleNumber)

	res, err := c.service.pCLI.Config.Show(ctx, path)

	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	if res == nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, nil
	}

	isSynced := func(res any) bool {
		if rule, ok := res.(map[string]any); ok {
			flat, _ := flatten.Flatten(rule, "", flatten.DotStyle)

			if flat["action"] != cr.Spec.ForProvider.Action {
				return false
			}
			if flat["destination.address"] != cr.Spec.ForProvider.DestinationAddress {
				return false
			}
			if sa, ok := flat["source.address"]; ok {
				if sa != cr.Spec.ForProvider.SourceAddress {
					return false
				}
			}
			return true
		}
		return false
	}

	if isSynced(res) {
		fmt.Println("**************** IS UP TO DATE 🔥")
		cr.Status.SetConditions(xpv1.Available())
	} else {
		fmt.Println("**************** IS NOT UP TO DATE 💔")
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

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
	cr, ok := mg.(*v1alpha1.Firewall)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotFirewall)
	}

	fmt.Printf("Tying to Create: %+v", cr)

	ruleNumber := cr.Spec.ForProvider.RuleNumber
	valueMap := make(map[string]string)
	valueMap["action"] = cr.Spec.ForProvider.Action
	valueMap["destination address"] = cr.Spec.ForProvider.DestinationAddress
	if cr.Spec.ForProvider.SourceAddress != nil && *cr.Spec.ForProvider.SourceAddress != "" {
		valueMap["source address"] = *cr.Spec.ForProvider.SourceAddress
	}

	path := "firewall name LAN-INBOUND rule " + fmt.Sprint(ruleNumber)

	cr.Status.SetConditions(xpv1.Creating())

	err := c.service.pCLI.Config.Set(ctx, path, valueMap)

	if err != nil {
		fmt.Printf("Cannot create: %+v", cr)
		fmt.Printf("Error: %+v", err)
	} else {
		fmt.Printf("Creating: %+v", cr)
	}

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Firewall)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotFirewall)
	}

	fmt.Printf("Updating: %+v", cr)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Firewall)
	if !ok {
		return errors.New(errNotFirewall)
	}

	fmt.Printf("Deleting: %+v", cr)

	return nil
}
