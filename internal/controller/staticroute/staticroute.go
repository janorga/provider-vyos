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

package staticroute

import (
	"context"
	"fmt"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/janorga/provider-vyos/apis/router/v1alpha1"
	apisv1alpha1 "github.com/janorga/provider-vyos/apis/v1alpha1"
	"github.com/janorga/provider-vyos/internal/features"
	vyosclient "github.com/janorga/vyos-client-go/client-insecure"
)

const (
	errNotStaticRoute = "managed resource is not a StaticRoute custom resource"
	errTrackPCUsage   = "cannot track ProviderConfig usage"
	errGetPC          = "cannot get ProviderConfig"
	errGetCreds       = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A VyOSService
type VyOSService struct {
	apiKey  string
	url     string
	timeout int32
}

func (vs *VyOSService) New() *vyosclient.Client {
	return vyosclient.New(vs.url, vs.apiKey, vs.timeout)
}

var (
	newVyOSService = func(vyosurl string, apiKey []byte) (*VyOSService, error) {
		return &VyOSService{
			apiKey:  string(apiKey[:]),
			url:     vyosurl,
			timeout: 60,
		}, nil
	}
)

// Setup adds a controller that reconciles StaticRoute managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.StaticRouteGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.StaticRouteGroupVersionKind),
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
		For(&v1alpha1.StaticRoute{}).
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
	cr, ok := mg.(*v1alpha1.StaticRoute)
	if !ok {
		return nil, errors.New(errNotStaticRoute)
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
	cr, ok := mg.(*v1alpha1.StaticRoute)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotStaticRoute)
	}

	if len(cr.Status.AtProvider.State.FollowedRoute) > 0 &&
		(cr.Status.AtProvider.State.FollowedRoute != cr.Spec.ForProvider.Route.To) {
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)
	path := "protocols static interface-route " + cr.Spec.ForProvider.Route.To + " next-hop-interface"

	vyosclient := c.service.New()
	res, err := vyosclient.Config.Show(ctx, path)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	//Does not exist
	if res == nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, nil
	}

	_, not_modified := res.(map[string]any)[cr.Spec.ForProvider.Route.NextHopInterface]

	//Is modified
	if !not_modified {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	if len(cr.Status.AtProvider.State.FollowedRoute) == 0 {
		putFollowedRouteOnState(cr)
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
	cr, ok := mg.(*v1alpha1.StaticRoute)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotStaticRoute)
	}

	fmt.Printf("Creating/Updating: %+v", cr)

	path := "protocols static interface-route " + cr.Spec.ForProvider.Route.To + " next-hop-interface"

	valueMap := make(map[string]string)

	valueMap[cr.Spec.ForProvider.Route.NextHopInterface] = ""

	vyosclient := c.service.New()
	err := vyosclient.Config.Set(ctx, path, valueMap)

	if err != nil {
		fmt.Printf("Cannot create: %+v", cr)
		fmt.Printf("Error💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥: %+v", err)
		return managed.ExternalCreation{
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	} else {
		fmt.Printf("Creating: %+v", cr)
	}

	putFollowedRouteOnState(cr)

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.StaticRoute)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotStaticRoute)
	}

	// Delete route first if spec "To" is different than followed route
	if cr.Spec.ForProvider.Route.To != cr.Status.AtProvider.State.FollowedRoute {
		path := "protocols static interface-route " + cr.Status.AtProvider.State.FollowedRoute

		vyosclient := c.service.New()
		err := vyosclient.Config.Delete(ctx, path, "")
		if err != nil {
			fmt.Printf("Cannot Delete: %+v", cr)
			fmt.Printf("Error: %+v", err)
			return managed.ExternalUpdate{
				ConnectionDetails: managed.ConnectionDetails{},
			}, err
		} else {
			fmt.Printf("Deleted: %+v", cr)
		}
	}

	fmt.Printf("Creating/Updating: %+v", cr)
	mg_eu, err := c.Create(ctx, mg)

	// FollowedRoute updated at Create function

	return managed.ExternalUpdate{ConnectionDetails: managed.ExternalUpdate(mg_eu).ConnectionDetails}, err
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.StaticRoute)
	if !ok {
		return errors.New(errNotStaticRoute)
	}

	fmt.Printf("Deleting: %+v", cr)

	path := "protocols static interface-route " + cr.Spec.ForProvider.Route.To

	vyosclient := c.service.New()
	err := vyosclient.Config.Delete(ctx, path, "")

	if err != nil {
		fmt.Printf("Cannot Delete: %+v", cr)
		fmt.Printf("Error: %+v", err)
		return err
	} else {
		fmt.Printf("Deleted: %+v", cr)
	}

	return nil
}

func putFollowedRouteOnState(cr *v1alpha1.StaticRoute) {
	cr.Status.AtProvider.State.FollowedRoute = cr.Spec.ForProvider.Route.To
}
