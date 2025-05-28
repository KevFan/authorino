package identity

import (
	gocontext "context"
	"fmt"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/workers"

	goidc "github.com/coreos/go-oidc/v3/oidc"
)

const (
	msg_oidcProviderConfigMissingError    = "missing openid connect configuration"
	msg_oidcProviderConfigRefreshSuccess  = "openid connect configuration updated"
	msg_oidcProviderConfigRefreshError    = "failed to discovery openid connect configuration"
	msg_oidcProviderConfigRefreshDisabled = "auto-refresh of openid connect configuration disabled"
)

type OIDC struct {
	auth.AuthCredentials
	Endpoint  string `yaml:"endpoint"`
	JwksUrl   string `yaml:"jwksUrl"`
	provider  *goidc.Provider
	keySet    goidc.KeySet
	refresher workers.Worker
}

func NewOIDC(endpoint, jwksUrl string, creds auth.AuthCredentials, ttl int, ctx gocontext.Context) *OIDC {
	oidc := &OIDC{
		AuthCredentials: creds,
		Endpoint:        endpoint,
	}
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc"))
	if jwksUrl != "" {
		oidc.keySet = goidc.NewRemoteKeySet(ctxWithLogger, oidc.JwksUrl)
		oidc.configureKeySetRefresh(ttl, ctxWithLogger)
	} else {
		_ = oidc.getProvider(ctxWithLogger, false)
		oidc.configureProviderRefresh(ttl, ctxWithLogger)
	}
	return oidc
}

func (oidc *OIDC) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	// retrieve access token
	accessToken, err := oidc.GetCredentialsFromReq(pipeline.GetRequest().GetAttributes().GetRequest().GetHttp())
	if err != nil {
		return nil, err
	}

	// verify jwt and extract claims
	var claims interface{}
	if _, err := oidc.decodeAndVerifyToken(accessToken, log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc")), &claims); err != nil {
		return nil, err
	} else {
		return claims, nil
	}
}

func (oidc *OIDC) getProvider(ctx gocontext.Context, force bool) *goidc.Provider {
	if oidc.provider == nil || force {
		endpoint := oidc.Endpoint
		if provider, err := goidc.NewProvider(gocontext.TODO(), endpoint); err != nil {
			log.FromContext(ctx).Error(err, msg_oidcProviderConfigRefreshError, "endpoint", endpoint)
		} else {
			log.FromContext(ctx).V(1).Info(msg_oidcProviderConfigRefreshSuccess, "endpoint", endpoint)
			oidc.provider = provider
		}
	}

	return oidc.provider
}

func (oidc *OIDC) decodeAndVerifyToken(accessToken string, ctx gocontext.Context, claims *interface{}) (*goidc.IDToken, error) {
	if err := context.CheckContext(ctx); err != nil {
		return nil, err
	}

	// verify jwt
	idToken, err := oidc.verifyToken(accessToken, ctx)
	if err != nil {
		return nil, err
	}

	// extract claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return idToken, nil
}

func (oidc *OIDC) verifyToken(accessToken string, ctx gocontext.Context) (*goidc.IDToken, error) {
	tokenVerifierConfig := &goidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}

	// Manual JWKS
	if oidc.keySet != nil {
		verifier := goidc.NewVerifier(oidc.Endpoint, oidc.keySet, tokenVerifierConfig)
		return verifier.Verify(ctx, accessToken)
	}

	// Otherwise, use the OIDC provider's Verifier (discovery mode)
	provider := oidc.getProvider(ctx, false)
	if provider == nil {
		return nil, fmt.Errorf(msg_oidcProviderConfigMissingError)
	}

	return provider.Verifier(tokenVerifierConfig).Verify(ctx, accessToken)
}

func (oidc *OIDC) GetURL(name string, ctx gocontext.Context) (*url.URL, error) {
	var providerClaims map[string]interface{}
	_ = oidc.getProvider(ctx, false).Claims(&providerClaims)

	if endpoint, err := url.Parse(providerClaims[name].(string)); err != nil {
		return nil, err
	} else {
		return endpoint, nil
	}
}

func (oidc *OIDC) configureProviderRefresh(ttl int, ctx gocontext.Context) {
	var err error

	oidc.refresher, err = workers.StartWorker(ctx, ttl, func() {
		oidc.getProvider(ctx, true)
	})

	if err != nil {
		log.FromContext(ctx).V(1).Info(msg_oidcProviderConfigRefreshDisabled, "reason", err)
	}
}

func (oidc *OIDC) configureKeySetRefresh(ttl int, ctx gocontext.Context) {
	if oidc.keySet == nil {
		// No manual JWKS configured, nothing to refresh here
		return
	}

	var err error

	oidc.refresher, err = workers.StartWorker(ctx, ttl, func() {
		// Recreate keySet to refresh JWKS keys
		oidc.keySet = goidc.NewRemoteKeySet(ctx, oidc.JwksUrl)
		log.FromContext(ctx).V(1).Info("manual JWKS refreshed", "jwks_url", oidc.JwksUrl)
	})

	if err != nil {
		log.FromContext(ctx).V(1).Info("manual JWKS refresh disabled", "reason", err)
	}
}

// Clean ensures the goroutine started by configureProviderRefresh is cleaned up
func (oidc *OIDC) Clean(ctx gocontext.Context) error {
	if oidc.refresher == nil {
		return nil
	}
	return oidc.refresher.Stop()
}
