package kerberos

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-hclog"
	kerberos "github.com/hashicorp/vault-plugin-auth-kerberos"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/tyrannosaurus-becks/gokrb5/spnego"
)

type kerberosMethod struct {
	logger    hclog.Logger
	mountPath string
	loginCfg  *kerberos.LoginCfg
}

func NewKerberosAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}
	username, err := toString(conf.Config, "username")
	if err != nil {
		return nil, err
	}
	service, err := toString(conf.Config, "service")
	if err != nil {
		return nil, err
	}
	realm, err := toString(conf.Config, "realm")
	if err != nil {
		return nil, err
	}
	keytabPath, err := toString(conf.Config, "keytab_path")
	if err != nil {
		return nil, err
	}
	krb5ConfPath, err := toString(conf.Config, "krb5conf_path")
	if err != nil {
		return nil, err
	}
	return &kerberosMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,
		loginCfg: &kerberos.LoginCfg{
			Username:     username,
			Service:      service,
			Realm:        realm,
			KeytabPath:   keytabPath,
			Krb5ConfPath: krb5ConfPath,
		},
	}, nil
}

func (k *kerberosMethod) Authenticate(context.Context, *api.Client) (string, http.Header, map[string]interface{}, error) {
	k.logger.Trace("beginning authentication")
	authHeaderVal, err := kerberos.GetAuthHeaderVal(k.loginCfg)
	if err != nil {
		return "", nil, nil, err
	}
	header := new(http.Header)
	header.Set(spnego.HTTPHeaderAuthRequest, authHeaderVal)
	return k.mountPath, *header, nil, nil
}

// These functions are implemented to meed the AuthHandler interface,
// but we don't need to take advantage of them.
func (k *kerberosMethod) NewCreds() chan struct{} { return nil }
func (k *kerberosMethod) CredSuccess()            {}
func (k *kerberosMethod) Shutdown()               {}

func toString(m map[string]interface{}, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%q is required", key)
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string", key)
	}
	return v, nil
}
