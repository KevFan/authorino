/*
Copyright 2020 Red Hat, Inc.

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

package controllers

import (
	"context"
	"fmt"
	"sort"
	"sync"

	old "github.com/kuadrant/authorino/api/v1beta1"
	api "github.com/kuadrant/authorino/api/v1beta2"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	authorization_evaluators "github.com/kuadrant/authorino/pkg/evaluators/authorization"
	identity_evaluators "github.com/kuadrant/authorino/pkg/evaluators/identity"
	metadata_evaluators "github.com/kuadrant/authorino/pkg/evaluators/metadata"
	response_evaluators "github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/oauth2"
	"github.com/kuadrant/authorino/pkg/utils"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	failedToCleanConfig = "failed to clean up all asynchronous workers"

	AuthConfigsReadyzSubpath = "authconfigs"
)

// AuthConfigReconciler reconciles an AuthConfig object
type AuthConfigReconciler struct {
	client.Client
	Logger                      logr.Logger
	Scheme                      *runtime.Scheme
	Index                       index.Index
	AllowSupersedingHostSubsets bool
	StatusReport                *StatusReportMap
	LabelSelector               labels.Selector
	Namespace                   string

	indexBootstrap sync.Mutex
}

// +kubebuilder:rbac:groups=authorino.kuadrant.io,resources=authconfigs,verbs=get;list;watch;create;update;patch;delete

func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := r.bootstrapIndex(ctx); err != nil {
		r.Logger.Error(err, "failed to bootstrap the index")
	}

	resourceId := req.String()
	logger := r.Logger.WithValues("authconfig", resourceId)
	reportReconciled := true

	r.StatusReport.Set(resourceId, api.StatusReasonReconciling, "", []string{})

	var linkedHosts, looseHosts []string

	authConfig := api.AuthConfig{}
	if err := r.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, r.LabelSelector) {
		// could not find the resource: 404 Not found (resource must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(resourceId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		// delete related authconfigs from the index.
		r.Index.Delete(resourceId)
		r.StatusReport.Clear(resourceId)
		reportReconciled = false
		logger.Info("resource de-indexed")
	} else {
		// resource found and it is to be watched by this controller
		// we need to either create it or update it in the index

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(resourceId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		translatedAuthConfig, err := r.translateAuthConfig(log.IntoContext(ctx, logger), &authConfig)
		if err != nil {
			r.StatusReport.Set(resourceId, api.StatusReasonInvalidResource, err.Error(), []string{})
			return ctrl.Result{}, err
		}

		// delete unused hosts from the index
		for _, host := range utils.SubtractSlice(r.Index.FindKeys(resourceId), authConfig.Spec.Hosts) {
			r.Index.DeleteKey(resourceId, host)
		}

		linkedHosts, looseHosts, err = r.addToIndex(log.IntoContext(ctx, logger), req.Namespace, resourceId, translatedAuthConfig, authConfig.Spec.Hosts)

		if len(looseHosts) > 0 {
			r.StatusReport.Set(resourceId, api.StatusReasonHostsNotLinked, "one or more hosts are not linked to the resource", linkedHosts)
			reportReconciled = false
		}

		if err != nil {
			r.StatusReport.Set(resourceId, api.StatusReasonCachingError, err.Error(), linkedHosts)
			return ctrl.Result{}, err
		}
	}

	if len(linkedHosts) > 0 {
		logger.Info("resource reconciled")
	}

	if reportReconciled {
		r.StatusReport.Set(resourceId, api.StatusReasonReconciled, "", linkedHosts)
	}

	return ctrl.Result{}, nil
}

func (r *AuthConfigReconciler) cleanConfigs(resourceId string, ctx context.Context) error {
	if hosts := r.Index.FindKeys(resourceId); len(hosts) > 0 {
		// no need to clean for all the hosts as the config should be the same
		if authConfig := r.Index.Get(hosts[0]); authConfig != nil {
			return authConfig.Clean(ctx)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) translateAuthConfig(ctx context.Context, authConfig *api.AuthConfig) (*evaluators.AuthConfig, error) {
	var ctxWithLogger context.Context

	identityConfigs := make([]evaluators.IdentityConfig, 0)
	interfacedIdentityConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("identity"))

	authConfigIdentityConfigs := authConfig.Spec.Authentication

	if len(authConfigIdentityConfigs) == 0 {
		authConfigIdentityConfigs["anonymous"] = api.AuthenticationSpec{
			CommonEvaluatorSpec: api.CommonEvaluatorSpec{},
			Credentials:         api.Credentials{},
			AuthenticationMethodSpec: api.AuthenticationMethodSpec{
				AnonymousAccess: &api.AnonymousAccessSpec{},
			},
		}
	}

	for identityCfgName, identity := range authConfigIdentityConfigs {
		extendedProperties := make([]evaluators.IdentityExtension, len(identity.Defaults)+len(identity.Overrides))
		for propertyName, property := range identity.Defaults {
			extendedProperties = append(extendedProperties, evaluators.NewIdentityExtension(propertyName, json.JSONValue{
				Static:  property.Value,
				Pattern: property.Selector,
			}, false))
		}
		for propertyName, property := range identity.Overrides {
			extendedProperties = append(extendedProperties, evaluators.NewIdentityExtension(propertyName, json.JSONValue{
				Static:  property.Value,
				Pattern: property.Selector,
			}, true))
		}

		translatedIdentity := &evaluators.IdentityConfig{
			Name:               identityCfgName,
			Priority:           identity.Priority,
			Conditions:         buildJSONExpression(authConfig, identity.Conditions, jsonexp.All),
			ExtendedProperties: extendedProperties,
			Metrics:            identity.Metrics,
		}

		if identity.Cache != nil {
			ttl := identity.Cache.TTL
			if ttl == 0 {
				ttl = old.EvaluatorDefaultCacheTTL
			}
			translatedIdentity.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&identity.Cache.Key),
				ttl,
			)
		}

		authCred := auth.NewAuthCredential(identity.Credentials.KeySelector, string(identity.Credentials.In))

		switch identity.GetType() {
		// oauth2
		case old.IdentityOAuth2:
			oauth2Identity := identity.OAuth2

			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      oauth2Identity.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			translatedIdentity.OAuth2 = identity_evaluators.NewOAuth2Identity(
				oauth2Identity.TokenIntrospectionUrl,
				oauth2Identity.TokenTypeHint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
				authCred,
			)

		// oidc
		case old.IdentityOidc:
			translatedIdentity.OIDC = identity_evaluators.NewOIDC(identity.Oidc.Endpoint, authCred, identity.Oidc.TTL, ctxWithLogger)

		// apiKey
		case old.IdentityApiKey:
			namespace := authConfig.Namespace
			if identity.APIKey.AllNamespaces && r.ClusterWide() {
				namespace = ""
			}
			selector, err := metav1.LabelSelectorAsSelector(identity.APIKey.Selector)
			if err != nil {
				return nil, err
			}
			translatedIdentity.APIKey = identity_evaluators.NewApiKeyIdentity(identity.Name, selector, namespace, authCred, r.Client, ctxWithLogger)

		// MTLS
		case old.IdentityMTLS:
			namespace := authConfig.Namespace
			if identity.MTLS.AllNamespaces && r.ClusterWide() {
				namespace = ""
			}
			selector, err := metav1.LabelSelectorAsSelector(identity.MTLS.Selector)
			if err != nil {
				return nil, err
			}
			translatedIdentity.MTLS = identity_evaluators.NewMTLSIdentity(identity.Name, selector, namespace, r.Client, ctxWithLogger)

		// kubernetes auth
		case old.IdentityKubernetesAuth:
			if k8sAuthConfig, err := identity_evaluators.NewKubernetesAuthIdentity(authCred, identity.KubernetesAuth.Audiences); err != nil {
				return nil, err
			} else {
				translatedIdentity.KubernetesAuth = k8sAuthConfig
			}

		case old.IdentityPlain:
			translatedIdentity.Plain = &identity_evaluators.Plain{Pattern: identity.Plain.AuthJSON}

		case old.IdentityAnonymous:
			translatedIdentity.Noop = &identity_evaluators.Noop{AuthCredentials: authCred}

		case old.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", identity)
		}

		identityConfigs = append(identityConfigs, *translatedIdentity)
		interfacedIdentityConfigs = append(interfacedIdentityConfigs, translatedIdentity)
	}

	interfacedMetadataConfigs := make([]auth.AuthConfigEvaluator, 0)

	for _, metadata := range authConfig.Spec.Metadata {
		translatedMetadata := &evaluators.MetadataConfig{
			Name:       metadata.Name,
			Priority:   metadata.Priority,
			Conditions: buildJSONExpression(authConfig, metadata.Conditions, jsonexp.All),
			Metrics:    metadata.Metrics,
		}

		if metadata.Cache != nil {
			ttl := metadata.Cache.TTL
			if ttl == 0 {
				ttl = old.EvaluatorDefaultCacheTTL
			}
			translatedMetadata.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&metadata.Cache.Key),
				ttl,
			)
		}

		switch metadata.GetType() {
		// uma
		case old.MetadataUma:
			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      metadata.UMA.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			if uma, err := metadata_evaluators.NewUMAMetadata(
				metadata.UMA.Endpoint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
			); err != nil {
				return nil, err
			} else {
				translatedMetadata.UMA = uma
			}

		// user_info
		case old.MetadataUserinfo:
			translatedMetadata.UserInfo = &metadata_evaluators.UserInfo{}

			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UserInfo.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UserInfo.OIDC = idConfig.OIDC
			}

		// generic http
		case old.MetadataGenericHTTP:
			ev, err := r.buildGenericHttpEvaluator(ctx, metadata.GenericHTTP, authConfig.Namespace)
			if err != nil {
				return nil, err
			}
			translatedMetadata.GenericHTTP = ev

		case old.TypeUnknown:
			return nil, fmt.Errorf("unknown metadata type %v", metadata)
		}

		interfacedMetadataConfigs = append(interfacedMetadataConfigs, translatedMetadata)
	}

	interfacedAuthorizationConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("authorization"))

	for index, authorization := range authConfig.Spec.Authorization {
		translatedAuthorization := &evaluators.AuthorizationConfig{
			Name:       authorization.Name,
			Priority:   authorization.Priority,
			Conditions: buildJSONExpression(authConfig, authorization.Conditions, jsonexp.All),
			Metrics:    authorization.Metrics,
		}

		if authorization.Cache != nil {
			ttl := authorization.Cache.TTL
			if ttl == 0 {
				ttl = old.EvaluatorDefaultCacheTTL
			}
			translatedAuthorization.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&authorization.Cache.Key),
				ttl,
			)
		}

		switch authorization.GetType() {
		// opa
		case old.AuthorizationOPA:
			policyName := authConfig.GetNamespace() + "/" + authConfig.GetName() + "/" + authorization.Name
			opa := authorization.OPA
			externalRegistry := opa.ExternalRegistry
			secret := &v1.Secret{}
			var sharedSecret string

			if externalRegistry.SharedSecret != nil {
				if err := r.Client.Get(ctx, types.NamespacedName{
					Namespace: authConfig.Namespace,
					Name:      externalRegistry.SharedSecret.Name},
					secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}
				sharedSecret = string(secret.Data[externalRegistry.SharedSecret.Key])
			}

			externalSource := &authorization_evaluators.OPAExternalSource{
				Endpoint:        externalRegistry.Endpoint,
				SharedSecret:    sharedSecret,
				AuthCredentials: auth.NewAuthCredential(externalRegistry.Credentials.KeySelector, string(externalRegistry.Credentials.In)),
				TTL:             externalRegistry.TTL,
			}

			var err error
			translatedAuthorization.OPA, err = authorization_evaluators.NewOPAAuthorization(policyName, opa.InlineRego, externalSource, opa.AllValues, index, ctxWithLogger)
			if err != nil {
				return nil, err
			}

		// json
		case old.AuthorizationJSONPatternMatching:
			translatedAuthorization.JSON = &authorization_evaluators.JSONPatternMatching{
				Rules: buildJSONExpression(authConfig, authorization.JSON.Rules, jsonexp.All),
			}

		case old.AuthorizationKubernetesAuthz:
			user := authorization.KubernetesAuthz.User
			authorinoUser := json.JSONValue{Static: user.Value, Pattern: user.ValueFrom.AuthJSON}

			var authorinoResourceAttributes *authorization_evaluators.KubernetesAuthzResourceAttributes
			resourceAttributes := authorization.KubernetesAuthz.ResourceAttributes
			if resourceAttributes != nil {
				authorinoResourceAttributes = &authorization_evaluators.KubernetesAuthzResourceAttributes{
					Namespace:   json.JSONValue{Static: resourceAttributes.Namespace.Value, Pattern: resourceAttributes.Namespace.ValueFrom.AuthJSON},
					Group:       json.JSONValue{Static: resourceAttributes.Group.Value, Pattern: resourceAttributes.Group.ValueFrom.AuthJSON},
					Resource:    json.JSONValue{Static: resourceAttributes.Resource.Value, Pattern: resourceAttributes.Resource.ValueFrom.AuthJSON},
					Name:        json.JSONValue{Static: resourceAttributes.Name.Value, Pattern: resourceAttributes.Name.ValueFrom.AuthJSON},
					SubResource: json.JSONValue{Static: resourceAttributes.SubResource.Value, Pattern: resourceAttributes.SubResource.ValueFrom.AuthJSON},
					Verb:        json.JSONValue{Static: resourceAttributes.Verb.Value, Pattern: resourceAttributes.Verb.ValueFrom.AuthJSON},
				}
			}

			var err error
			translatedAuthorization.KubernetesAuthz, err = authorization_evaluators.NewKubernetesAuthz(authorinoUser, authorization.KubernetesAuthz.Groups, authorinoResourceAttributes)
			if err != nil {
				return nil, err
			}

		case old.AuthorizationAuthzed:
			authzed := authorization.Authzed

			secret := &v1.Secret{}
			var sharedSecret string
			if secretRef := authzed.SharedSecret; secretRef != nil {
				if err := r.Client.Get(ctx, types.NamespacedName{Namespace: authConfig.Namespace, Name: secretRef.Name}, secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}
				sharedSecret = string(secret.Data[secretRef.Key])
			}

			translatedAuthzed := &authorization_evaluators.Authzed{
				Endpoint:     authzed.Endpoint,
				Insecure:     authzed.Insecure,
				SharedSecret: sharedSecret,
				Permission:   *getJsonFromStaticDynamic(&authzed.Permission),
			}
			translatedAuthzed.Subject, translatedAuthzed.SubjectKind = authzedObjectToJsonValues(authzed.Subject)
			translatedAuthzed.Resource, translatedAuthzed.ResourceKind = authzedObjectToJsonValues(authzed.Resource)

			translatedAuthorization.Authzed = translatedAuthzed

		case old.TypeUnknown:
			return nil, fmt.Errorf("unknown authorization type %v", authorization)
		}

		interfacedAuthorizationConfigs = append(interfacedAuthorizationConfigs, translatedAuthorization)
	}

	interfacedResponseConfigs := make([]auth.AuthConfigEvaluator, 0)

	for _, response := range authConfig.Spec.Response {
		translatedResponse := evaluators.NewResponseConfig(
			response.Name,
			response.Priority,
			buildJSONExpression(authConfig, response.Conditions, jsonexp.All),
			string(response.Wrapper),
			response.WrapperKey,
			response.Metrics,
		)

		if response.Cache != nil {
			ttl := response.Cache.TTL
			if ttl == 0 {
				ttl = old.EvaluatorDefaultCacheTTL
			}
			translatedResponse.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&response.Cache.Key),
				ttl,
			)
		}

		switch response.GetType() {
		// wristband
		case old.ResponseWristband:
			wristband := response.Wristband
			signingKeys := make([]jose.JSONWebKey, 0)

			for _, signingKeyRef := range wristband.SigningKeyRefs {
				secret := &v1.Secret{}
				secretName := types.NamespacedName{
					Namespace: authConfig.Namespace,
					Name:      signingKeyRef.Name,
				}
				if err := r.Client.Get(ctx, secretName, secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				} else {
					if signingKey, err := response_evaluators.NewSigningKey(
						signingKeyRef.Name,
						string(signingKeyRef.Algorithm),
						secret.Data["key.pem"],
					); err != nil {
						return nil, err
					} else {
						signingKeys = append(signingKeys, *signingKey)
					}
				}
			}

			customClaims := make([]json.JSONProperty, 0)
			for _, claim := range wristband.CustomClaims {
				customClaims = append(customClaims, json.JSONProperty{
					Name: claim.Name,
					Value: json.JSONValue{
						Static:  claim.Value,
						Pattern: claim.ValueFrom.AuthJSON,
					},
				})
			}

			if authorinoWristband, err := response_evaluators.NewWristbandConfig(
				wristband.Issuer,
				customClaims,
				wristband.TokenDuration,
				signingKeys,
			); err != nil {
				return nil, err
			} else {
				translatedResponse.Wristband = authorinoWristband
			}

		// dynamic json
		case old.ResponseDynamicJSON:
			jsonProperties := make([]json.JSONProperty, 0)

			for _, property := range response.JSON.Properties {
				jsonProperties = append(jsonProperties, json.JSONProperty{
					Name: property.Name,
					Value: json.JSONValue{
						Static:  property.Value,
						Pattern: property.ValueFrom.AuthJSON,
					},
				})
			}

			translatedResponse.DynamicJSON = response_evaluators.NewDynamicJSONResponse(jsonProperties)

		// plain
		case old.ResponsePlain:
			translatedResponse.Plain = &response_evaluators.Plain{
				JSONValue: json.JSONValue{
					Static:  response.Plain.Value,
					Pattern: response.Plain.ValueFrom.AuthJSON,
				},
			}

		case old.TypeUnknown:
			return nil, fmt.Errorf("unknown response type %v", response)
		}

		interfacedResponseConfigs = append(interfacedResponseConfigs, translatedResponse)
	}

	interfacedCallbackConfigs := make([]auth.AuthConfigEvaluator, 0)

	for _, callback := range authConfig.Spec.Callbacks {
		translatedCallback := &evaluators.CallbackConfig{
			Name:       callback.Name,
			Priority:   callback.Priority,
			Conditions: buildJSONExpression(authConfig, callback.Conditions, jsonexp.All),
			Metrics:    callback.Metrics,
		}

		switch callback.GetType() {
		// http
		case old.CallbackHTTP:
			ev, err := r.buildGenericHttpEvaluator(ctx, callback.HTTP, authConfig.Namespace)
			if err != nil {
				return nil, err
			}
			translatedCallback.HTTP = ev

		case old.TypeUnknown:
			return nil, fmt.Errorf("unknown callback type %v", callback)
		}

		interfacedCallbackConfigs = append(interfacedCallbackConfigs, translatedCallback)
	}

	translatedAuthConfig := &evaluators.AuthConfig{
		Conditions:           buildJSONExpression(authConfig, authConfig.Spec.Conditions, jsonexp.All),
		IdentityConfigs:      interfacedIdentityConfigs,
		MetadataConfigs:      interfacedMetadataConfigs,
		AuthorizationConfigs: interfacedAuthorizationConfigs,
		ResponseConfigs:      interfacedResponseConfigs,
		CallbackConfigs:      interfacedCallbackConfigs,
		Labels:               map[string]string{"namespace": authConfig.Namespace, "name": authConfig.Name},
	}

	// denyWith
	if denyWith := authConfig.Spec.DenyWith; denyWith != nil {
		translatedAuthConfig.Unauthenticated = buildAuthorinoDenyWithValues(denyWith.Unauthenticated)
		translatedAuthConfig.Unauthorized = buildAuthorinoDenyWithValues(denyWith.Unauthorized)
	}

	return translatedAuthConfig, nil
}

func (r *AuthConfigReconciler) addToIndex(ctx context.Context, resourceNamespace, resourceId string, authConfig *evaluators.AuthConfig, hosts []string) (linkedHosts, looseHosts []string, err error) {
	logger := log.FromContext(ctx)
	linkedHosts = []string{}
	looseHosts = []string{}

	for _, host := range hosts {
		// check for host name collision between resources
		if r.hostTaken(host, resourceId) {
			looseHosts = append(looseHosts, host)
			logger.Info("host already taken", "host", host)
			continue
		}

		// add to the index
		if err = r.Index.Set(resourceId, host, *authConfig, true); err != nil {
			return
		}

		linkedHosts = append(linkedHosts, host)
	}

	return
}

func (r *AuthConfigReconciler) hostTaken(host, resourceId string) bool {
	indexedResourceId, found := r.Index.FindId(host)
	return found && indexedResourceId != resourceId && !r.supersedeHostSubset(host, indexedResourceId)
}

func (r *AuthConfigReconciler) supersedeHostSubset(host, supersetResourceId string) bool {
	return r.AllowSupersedingHostSubsets && !utils.SliceContains(r.Index.FindKeys(supersetResourceId), host)
}

func (r *AuthConfigReconciler) bootstrapIndex(ctx context.Context) error {
	r.indexBootstrap.Lock()
	defer r.indexBootstrap.Unlock()

	if !r.Index.Empty() {
		return nil
	}

	authConfigList := old.AuthConfigList{}
	listOptions := []client.ListOption{}
	if r.LabelSelector != nil {
		listOptions = append(listOptions, client.MatchingLabelsSelector{Selector: r.LabelSelector})
	}
	if err := r.List(ctx, &authConfigList, listOptions...); err != nil {
		return err
	}

	count := len(authConfigList.Items)
	if count == 0 {
		return nil
	}

	logger := r.Logger.WithName("bootstrap")
	logger.Info("building the index", "count", count)

	sort.Sort(authConfigList.Items)

	ctx = log.IntoContext(ctx, logger)
	denyAll := &evaluators.AuthConfig{
		AuthorizationConfigs: []auth.AuthConfigEvaluator{evaluators.NewDenyAllAuthorization(ctx, "deny-all", "")},
		DenyWith:             evaluators.DenyWith{Unauthorized: &evaluators.DenyWithValues{Code: 503, Message: &json.JSONValue{Static: "Busy"}}},
	}

	for _, authConfig := range authConfigList.Items {
		if len(authConfig.Status.Summary.HostsReady) == 0 { // unfortunately we cannot use arbitrary field selectors for custom resources yet - https://github.com/kubernetes/kubernetes/issues/51046
			continue
		}

		authConfigName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
		logger.V(1).Info("building index", "authconfig", authConfigName.String())

		_, _, err := r.addToIndex(
			log.IntoContext(ctx, logger.WithValues("authconfig", authConfigName)),
			authConfig.Namespace,
			authConfigName.String(),
			denyAll,
			authConfig.Spec.Hosts,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (r *AuthConfigReconciler) ClusterWide() bool {
	return r.Namespace == ""
}

func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&old.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(r.LabelSelector))).
		Complete(r)
}

func (r *AuthConfigReconciler) Ready(includes, _ []string, _ bool) error {
	if !utils.SliceContains(includes, AuthConfigsReadyzSubpath) {
		return nil
	}

	for id, status := range r.StatusReport.ReadAll() {
		switch status.Reason {
		case old.StatusReasonReconciled:
			continue
		default:
			return fmt.Errorf("authconfig is not ready: %s (reason: %s)", id, status.Reason)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) buildGenericHttpEvaluator(ctx context.Context, http *old.Metadata_GenericHTTP, namespace string) (*metadata_evaluators.GenericHttp, error) {
	var sharedSecret string
	if sharedSecretRef := http.SharedSecret; sharedSecretRef != nil {
		secret := &v1.Secret{}
		if sharedSecretRef != nil {
			if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sharedSecretRef.Name}, secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}
			sharedSecret = string(secret.Data[sharedSecretRef.Key])
		}
	}

	var oauth2ClientCredentialsConfig *oauth2.ClientCredentials
	oauth2TokenForceFetch := false
	if oauth2Config := http.OAuth2; oauth2Config != nil {
		secret := &v1.Secret{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: oauth2Config.ClientSecret.Name}, secret); err != nil {
			return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
		}
		clientSecret := string(secret.Data[oauth2Config.ClientSecret.Key])
		oauth2ClientCredentialsConfig = oauth2.NewClientCredentialsConfig(oauth2Config.TokenUrl, oauth2Config.ClientId, clientSecret, oauth2Config.Scopes, oauth2Config.ExtraParams)
		oauth2TokenForceFetch = oauth2Config.Cache != nil && !*oauth2Config.Cache
	}

	var body *json.JSONValue
	if b := http.Body; b != nil {
		body = &json.JSONValue{Static: b.Value, Pattern: b.ValueFrom.AuthJSON}
	}

	params := make([]json.JSONProperty, 0, len(http.Parameters))
	for _, param := range http.Parameters {
		params = append(params, json.JSONProperty{
			Name: param.Name,
			Value: json.JSONValue{
				Static:  param.Value,
				Pattern: param.ValueFrom.AuthJSON,
			},
		})
	}

	headers := make([]json.JSONProperty, 0, len(http.Headers))
	for _, header := range http.Headers {
		headers = append(headers, json.JSONProperty{
			Name: header.Name,
			Value: json.JSONValue{
				Static:  header.Value,
				Pattern: header.ValueFrom.AuthJSON,
			},
		})
	}

	method := "GET"
	if m := http.Method; m != nil {
		method = string(*m)
	}

	ev := &metadata_evaluators.GenericHttp{
		Endpoint:              http.Endpoint,
		Method:                method,
		Body:                  body,
		Parameters:            params,
		Headers:               headers,
		ContentType:           string(http.ContentType),
		SharedSecret:          sharedSecret,
		OAuth2:                oauth2ClientCredentialsConfig,
		OAuth2TokenForceFetch: oauth2TokenForceFetch,
	}

	if sharedSecret != "" || oauth2ClientCredentialsConfig != nil {
		ev.AuthCredentials = auth.NewAuthCredential(http.Credentials.KeySelector, string(http.Credentials.In))
	}

	return ev, nil
}

func findIdentityConfigByName(identityConfigs []evaluators.IdentityConfig, name string) (*evaluators.IdentityConfig, error) {
	for _, id := range identityConfigs {
		if id.Name == name {
			return &id, nil
		}
	}
	return nil, fmt.Errorf("missing identity config %v", name)
}

func buildJSONExpression(authConfig *api.AuthConfig, patterns []api.PatternExpressionOrRef, op func(...jsonexp.Expression) jsonexp.Expression) jsonexp.Expression {
	var expression []jsonexp.Expression
	for _, pattern := range patterns {
		// patterns or refs
		expression = append(expression, buildJSONExpressionPatterns(authConfig, pattern)...)
		// all
		if len(pattern.All) > 0 {
			p := make([]api.PatternExpressionOrRef, len(pattern.All))
			for i, ptn := range pattern.All {
				p[i] = ptn.PatternExpressionOrRef
			}
			expression = append(expression, buildJSONExpression(authConfig, p, jsonexp.All))
		}
		// any
		if len(pattern.Any) > 0 {
			p := make([]api.PatternExpressionOrRef, len(pattern.Any))
			for i, ptn := range pattern.Any {
				p[i] = ptn.PatternExpressionOrRef
			}
			expression = append(expression, buildJSONExpression(authConfig, p, jsonexp.Any))
		}
	}
	return op(expression...)
}

func buildJSONExpressionPatterns(authConfig *api.AuthConfig, pattern api.PatternExpressionOrRef) []jsonexp.Expression {
	expressionsToAdd := api.PatternExpressions{}
	if expressionsByRef, found := authConfig.Spec.NamedPatterns[pattern.PatternRef.Name]; found {
		expressionsToAdd = append(expressionsToAdd, expressionsByRef...)
	} else if pattern.PatternExpression.Operator != "" {
		expressionsToAdd = append(expressionsToAdd, pattern.PatternExpression)
	}

	expressions := make([]jsonexp.Expression, len(expressionsToAdd))
	for i, expression := range expressionsToAdd {
		expressions[i] = buildJSONExpressionPattern(expression)
	}
	return expressions
}

func buildJSONExpressionPattern(expression api.PatternExpression) jsonexp.Expression {
	return jsonexp.Pattern{
		Selector: expression.Selector,
		Operator: jsonexp.OperatorFromString(string(expression.Operator)),
		Value:    expression.Value,
	}
}

func buildAuthorinoDenyWithValues(denyWithSpec *old.DenyWithSpec) *evaluators.DenyWithValues {
	if denyWithSpec == nil {
		return nil
	}

	headers := make([]json.JSONProperty, 0, len(denyWithSpec.Headers))
	for _, header := range denyWithSpec.Headers {
		headers = append(headers, json.JSONProperty{Name: header.Name, Value: json.JSONValue{Static: header.Value, Pattern: header.ValueFrom.AuthJSON}})
	}

	return &evaluators.DenyWithValues{
		Code:    int32(denyWithSpec.Code),
		Message: getJsonFromStaticDynamic(denyWithSpec.Message),
		Headers: headers,
		Body:    getJsonFromStaticDynamic(denyWithSpec.Body),
	}
}

func getJsonFromStaticDynamic(value *api.ValueOrSelector) *json.JSONValue {
	if value == nil {
		return nil
	}

	return &json.JSONValue{
		Static:  value.Value,
		Pattern: value.Selector,
	}
}

func authzedObjectToJsonValues(obj *old.AuthzedObject) (name json.JSONValue, kind json.JSONValue) {
	if obj == nil {
		return
	}

	name = *getJsonFromStaticDynamic(&obj.Name)
	kind = *getJsonFromStaticDynamic(&obj.Kind)

	return name, kind
}
