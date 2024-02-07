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

package ruleset

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jeremywohl/flatten"

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
	errNotRuleset   = "managed resource is not a Ruleset custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

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

// Setup adds a controller that reconciles Ruleset managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.RulesetGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.RulesetGroupVersionKind),
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
		For(&v1alpha1.Ruleset{}).
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
	cr, ok := mg.(*v1alpha1.Ruleset)
	if !ok {
		return nil, errors.New(errNotRuleset)
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

	return &external{service: svc, kube: c.kube}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service *VyOSService
	kube    client.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Ruleset)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRuleset)
	}
	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)

	if len(cr.Status.AtProvider.State.FollowedRules) > 0 && checkNewSpec(cr) {
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	path := "firewall name LAN-INBOUND rule"

	res, err := c.service.pCLI.Config.Show(ctx, path)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	resMap, ok := res.(map[string]any)
	if !ok {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInExternalAPICall")
	}

	resflat, err := flatten.Flatten(resMap, "", flatten.DotStyle)
	if err != nil {
		cr.Status.SetConditions(xpv1.Unavailable())
		return managed.ExternalObservation{
			ResourceExists:   false,
			ResourceUpToDate: false,
		}, errors.New("errInParsingAPIResponse")
	}
	rules := cr.Spec.ForProvider.Rules

	resource_exists := false
	resource_modified := false

	for _, rule := range rules {
		ruleNumber := fmt.Sprint(rule.RuleNumber)

		// The resource exist if at least one rule exists
		// The resource is modified if at least one rule is modified

		// Check if al rules as a resource exist
		if _, ok := resflat[ruleNumber+".action"]; ok {

			resource_exists = resource_exists || ok
			//Check if up to date
			if resource_exists && !resource_modified {

				if rule.Action != resflat[ruleNumber+".action"] {
					resource_modified = true
				}
				if rule.Protocol != resflat[ruleNumber+".protocol"] {
					resource_modified = true
				}
				if rule.Destination.Address != resflat[ruleNumber+".destination.address"] {
					resource_modified = true
				}
				if fmt.Sprint(rule.Destination.Port) != resflat[ruleNumber+".destination.port"] {
					resource_modified = true
				}
			}
		} else {
			//mark also modified if one rule is missing
			resource_modified = true
			continue
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

	//*** Put applied rules on State
	if len(cr.Status.AtProvider.State.FollowedRules) == 0 {
		putFollowedRulesOnState(cr)
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

func createUpdate(ctx context.Context, cr *v1alpha1.Ruleset, vyosclient *vyosclient.Client) {
	rules := cr.Spec.ForProvider.Rules

	var path string
	valueMap := make(map[string]string)

	for _, rule := range rules {
		path = "firewall name LAN-INBOUND"

		ruleNumber_string := fmt.Sprint(rule.RuleNumber)

		valueMap["rule"] = fmt.Sprint(rule.RuleNumber)
		valueMap["rule "+ruleNumber_string+" action"] = rule.Action
		valueMap["rule "+ruleNumber_string+" protocol"] = rule.Protocol
		valueMap["rule "+ruleNumber_string+" destination address"] = rule.Destination.Address
		valueMap["rule "+ruleNumber_string+" destination port"] = fmt.Sprint(rule.Destination.Port)
	}

	err := vyosclient.Config.Set(ctx, path, valueMap)

	if err != nil {
		fmt.Printf("Cannot create: %+v", cr)
		fmt.Printf("Error💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥: %+v", err)
	} else {
		fmt.Printf("Creating: %+v", cr)
	}

	//*** Put applied rules on State
	putFollowedRulesOnState(cr)
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Ruleset)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRuleset)
	}

	fmt.Printf("Creating: %+v", cr)
	cr.Status.SetConditions(xpv1.Creating())

	createUpdate(ctx, cr, c.service.pCLI)

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Ruleset)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRuleset)
	}

	fmt.Printf("Updating: %+v", cr)

	//**************** Check if rule in Followed Rules is not in in Spec
	followed_rules := cr.Status.AtProvider.State.FollowedRules
	rules_not_found := make([]int32, 0)
	// Check if rule in last applied is not in Spec
	for _, f_rule := range followed_rules {
		found := false
		for _, rule_spec := range cr.Spec.ForProvider.Rules {
			if f_rule == rule_spec.RuleNumber {
				found = true
				break
			}
		}
		if !found {
			rules_not_found = append(rules_not_found, f_rule)
		}
	}
	//*** Delete not found rules on last applied configuration
	path := "firewall name LAN-INBOUND"
	delete_rules := make(map[string]string)
	for _, rule_number := range rules_not_found {
		delete_rules["rule "+fmt.Sprint(rule_number)] = ""
	}
	err := c.service.pCLI.Config.Delete(ctx, path, delete_rules)
	if err != nil {
		fmt.Printf("Cannot Delete: %+v", cr)
		fmt.Printf("Error: %+v", err)
	} else {
		fmt.Printf("Deleted: %+v", cr)
	}
	//*** Re-Create rules
	//TODO: Re-Create only modified rules
	createUpdate(ctx, cr, c.service.pCLI)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Ruleset)
	if !ok {
		return errors.New(errNotRuleset)
	}

	fmt.Printf("Deleting: %+v", cr)

	cr.Status.SetConditions(xpv1.Deleting())
	rules := cr.Spec.ForProvider.Rules
	path := "firewall name LAN-INBOUND"
	delete_rules := make(map[string]string)

	for _, rule := range rules {
		delete_rules["rule "+fmt.Sprint(rule.RuleNumber)] = ""
	}

	err := c.service.pCLI.Config.Delete(ctx, path, delete_rules)

	if err != nil {
		fmt.Printf("Cannot Delete: %+v", cr)
		fmt.Printf("Error: %+v", err)
	} else {
		fmt.Printf("Deleted: %+v", cr)
	}

	return nil
}

func putFollowedRulesOnState(cr *v1alpha1.Ruleset) {
	//*** Put applied rules on State
	applied_rules := make([]int32, 0)
	for _, rule := range cr.Spec.ForProvider.Rules {
		applied_rules = append(applied_rules, rule.RuleNumber)
	}
	cr.Status.AtProvider.State.FollowedRules = applied_rules
}

func checkNewSpec(cr *v1alpha1.Ruleset) bool {
	for _, rule_spec := range cr.Spec.ForProvider.Rules {
		rule_spec_rulenumber := rule_spec.RuleNumber
		for _, rule_followed := range cr.Status.AtProvider.State.FollowedRules {
			if rule_spec_rulenumber == rule_followed {
				return false
			}
		}
	}
	return true
}
