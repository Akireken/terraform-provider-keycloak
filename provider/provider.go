package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/meta"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak"
)

func KeycloakProvider(client *keycloak.KeycloakClient) *schema.Provider {
	provider := &schema.Provider{
		DataSourcesMap: map[string]*schema.Resource{
			"keycloak_openid_client": dataSourceKeycloakOpenidClient()},
		ResourcesMap: map[string]*schema.Resource{
			"keycloak_openid_client": resourceKeycloakOpenidClient(),
		},
		Schema: map[string]*schema.Schema{
			"client_id": {
				Required:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_ID", nil),
			},
			"client_secret": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_SECRET", nil),
			},
			"username": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_USER", nil),
			},
			"password": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_PASSWORD", nil),
			},
			"realm": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_REALM", "master"),
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The base URL of the Keycloak instance, before `/auth`",
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_URL", nil),
			},
			"initial_login": {
				Optional:    true,
				Type:        schema.TypeBool,
				Description: "Whether or not to login to Keycloak instance on provider initialization",
				Default:     true,
			},
			"client_timeout": {
				Optional:    true,
				Type:        schema.TypeInt,
				Description: "Timeout (in seconds) of the Keycloak client",
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_TIMEOUT", 15),
			},
			"root_ca_certificate": {
				Optional:    true,
				Type:        schema.TypeString,
				Description: "Allows x509 calls using an unknown CA certificate (for development purposes)",
				Default:     "",
			},
			"tls_insecure_skip_verify": {
				Optional:    true,
				Type:        schema.TypeBool,
				Description: "Allows ignoring insecure certificates when set to true. Defaults to false. Disabling security check is dangerous and should be avoided.",
				Default:     false,
			},
			"red_hat_sso": {
				Optional:    true,
				Type:        schema.TypeBool,
				Description: "When true, the provider will treat the Keycloak instance as a Red Hat SSO server, specifically when parsing the version returned from the /serverinfo API endpoint.",
				Default:     false,
			},
			"base_path": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_BASE_PATH", ""),
			},
			"additional_headers": {
				Optional: true,
				Type:     schema.TypeMap,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		if client != nil {
			return client, nil
		}

		url := data.Get("url").(string)
		basePath := data.Get("base_path").(string)
		clientId := data.Get("client_id").(string)
		clientSecret := data.Get("client_secret").(string)
		username := data.Get("username").(string)
		password := data.Get("password").(string)
		realm := data.Get("realm").(string)
		initialLogin := data.Get("initial_login").(bool)
		clientTimeout := data.Get("client_timeout").(int)
		tlsInsecureSkipVerify := data.Get("tls_insecure_skip_verify").(bool)
		rootCaCertificate := data.Get("root_ca_certificate").(string)
		redHatSSO := data.Get("red_hat_sso").(bool)
		additionalHeaders := make(map[string]string)
		for k, v := range data.Get("additional_headers").(map[string]interface{}) {
			additionalHeaders[k] = v.(string)
		}

		var diags diag.Diagnostics

		userAgent := fmt.Sprintf("HashiCorp Terraform/%s (+https://www.terraform.io) Terraform Plugin SDK/%s", provider.TerraformVersion, meta.SDKVersionString())

		keycloakClient, err := keycloak.NewKeycloakClient(ctx, url, basePath, clientId, clientSecret, realm, username, password, initialLogin, clientTimeout, rootCaCertificate, tlsInsecureSkipVerify, userAgent, redHatSSO, additionalHeaders)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "error initializing keycloak provider",
				Detail:   err.Error(),
			})
		}

		return keycloakClient, diags
	}

	return provider
}
