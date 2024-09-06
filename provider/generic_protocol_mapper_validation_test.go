package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

/*
 * Keycloak does not allow two protocol mappers to exist with the same name, but if you create two of them with the same
 * name quickly enough (which Terraform is pretty good at), the API allows it.
 *
 * The following tests check to see if that error is caught by creating a single protocol mapper first (each test uses a
 * different one), then creating another mapper with the same name in the next test step.
 */

/*
 * Protocol mappers must be attached to either a client or client scope.  The following tests assert that errors are raised
 * if neither are specified.
 */

func TestAccKeycloakOpenIdFullNameProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdFullNameProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdGroupMembershipProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdGroupMembershipProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdUserAttributeProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdUserAttributeProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdUserPropertyProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdUserPropertyProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdHardcodedClaimProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdHardcodedClaimProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdUserRealmRoleProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdUserRealmRoleProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdUserClientRoleProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdUserClientRoleProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func TestAccKeycloakOpenIdUserSessionNoteProtocolMapper_validateClientOrClientScopeSet(t *testing.T) {
	t.Parallel()
	mapperName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOpenIdUserSessionNoteProtocolMapper_parentResourceValidation(mapperName),
				ExpectError: regexp.MustCompile("validation error: one of ClientId or ClientScopeId must be set"),
			},
		},
	})
}

func testGenericProtocolMapperValidation_clientGroupMembershipMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client" {
  	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
  	client_id       = keycloak_openid_client.openid_client.id

  	claim_name      = "foo"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientFullNameMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_full_name_protocol_mapper" "full_name_mapper_client" {
  	name       = "%s"
	realm_id   = data.keycloak_realm.realm.id
  	client_id  = keycloak_openid_client.openid_client.id
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientUserAttributeMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client" {
  	name           = "%s"
	realm_id       = data.keycloak_realm.realm.id
  	client_id      = keycloak_openid_client.openid_client.id
  	user_attribute = "foo-attribute"
  	claim_name     = "bar-attribute"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientUserPropertyMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client" {
  	name          = "%s"
	realm_id      = data.keycloak_realm.realm.id
  	client_id     = keycloak_openid_client.openid_client.id
  	user_property = "foo-property"
  	claim_name    = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientFullNameAndGroupMembershipMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client" {
  	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
  	client_id       = keycloak_openid_client.openid_client.id

  	claim_name      = "foo"
}

resource "keycloak_openid_full_name_protocol_mapper" "full_name_mapper_client" {
  	name       = "%s"
	realm_id   = data.keycloak_realm.realm.id
  	client_id  = keycloak_openid_client.openid_client.id
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientGroupMembershipAndUserAttributeMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client" {
  	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
  	client_id       = keycloak_openid_client.openid_client.id

  	claim_name      = "foo"
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client" {
  	name           = "%s"
	realm_id       = data.keycloak_realm.realm.id
  	client_id      = keycloak_openid_client.openid_client.id
  	user_attribute = "foo"
  	claim_name     = "bar"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientUserAttributeAndUserPropertyMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client" {
  	name           = "%s"
	realm_id       = data.keycloak_realm.realm.id
  	client_id      = keycloak_openid_client.openid_client.id
  	user_attribute = "foo-attribute"
  	claim_name     = "bar-attribute"
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client" {
  	name          = "%s"
	realm_id      = data.keycloak_realm.realm.id
  	client_id     = keycloak_openid_client.openid_client.id
  	user_property = "foo-property"
  	claim_name    = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientUserPropertyAndHardcodedClaimMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"

	access_type = "BEARER-ONLY"
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client" {
  	name          = "%s"
	realm_id      = data.keycloak_realm.realm.id
  	client_id     = keycloak_openid_client.openid_client.id
  	user_property = "foo-property"
  	claim_name    = "bar-property"
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_mapper_client" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_id        = keycloak_openid_client.openid_client.id

	claim_name       = "foo"
	claim_value      = "bar"
	claim_value_type = "String"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeGroupMembershipMapper(clientScopeId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar"
}`, testAccRealm.Realm, clientScopeId, mapperName)
}

func testGenericProtocolMapperValidation_clientUserSessionNoteAndRealmRoleMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"
	access_type = "BEARER-ONLY"
}
resource "keycloak_openid_user_session_note_protocol_mapper" "user_session_note_mapper_validation" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_id        = keycloak_openid_client.openid_client.id
	claim_name       = "foo"
	claim_value_type = "String"
}
resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_id        = keycloak_openid_client.openid_client.id
	claim_name       = "foo"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientRealmRoleMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_client" "openid_client" {
	realm_id    = data.keycloak_realm.realm.id
	client_id   = "%s"
	access_type = "BEARER-ONLY"
}
resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_id        = keycloak_openid_client.openid_client.id
	claim_name       = "foo"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeFullNameMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_full_name_protocol_mapper" "full_name_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserAttributeMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_attribute  = "foo-attribute"
	claim_name      = "bar-attribute"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserPropertyMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_property   = "foo-property"
	claim_name      = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserRealmRoleMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName)

}

func testGenericProtocolMapperValidation_clientScopeUserClientRoleMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}
resource "keycloak_openid_user_client_role_protocol_mapper" "user_client_role_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName)

}

func testGenericProtocolMapperValidation_clientScopeFullNameAndGroupMembershipMapper(clientScopeId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar"
}

resource "keycloak_openid_full_name_protocol_mapper" "full_name_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
}`, testAccRealm.Realm, clientScopeId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeGroupMembershipAndUserAttributeMapper(clientScopeId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar"
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_attribute  = "foo"
	claim_name      = "bar"
}`, testAccRealm.Realm, clientScopeId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserAttributeAndUserPropertyMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_attribute  = "foo-attribute"
	claim_name      = "bar-attribute"
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_property   = "foo-property"
	claim_name      = "bar-property"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserPropertyAndHardcodedClaimMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	user_property   = "foo-property"
	claim_name      = "bar-property"
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_scope_id  = keycloak_openid_client_scope.client_scope.id

	claim_name       = "foo"
	claim_value      = "bar"
	claim_value_type = "String"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserRealmRoleAndHardcodedClaimMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}

resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar-property"
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_scope_id  = keycloak_openid_client_scope.client_scope.id

	claim_name       = "foo"
	claim_value      = "bar"
	claim_value_type = "String"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserClientRoleAndHardcodedClaimMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}
resource "keycloak_openid_user_client_role_protocol_mapper" "user_client_role_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "bar-property"
}
resource "keycloak_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	client_scope_id  = keycloak_openid_client_scope.client_scope.id
	claim_name       = "foo"
	claim_value      = "bar"
	claim_value_type = "String"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testGenericProtocolMapperValidation_clientScopeUserSessionNoteAndRealmRoleMapper(clientId, mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_client_scope" "client_scope" {
	name     = "%s"
	realm_id = data.keycloak_realm.realm.id
}
resource "keycloak_openid_user_session_note_protocol_mapper" "user_session_note_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name       = "foo"
	claim_value_type = "String"
}
resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client_scope" {
	name            = "%s"
	realm_id        = data.keycloak_realm.realm.id
	client_scope_id = keycloak_openid_client_scope.client_scope.id
	claim_name      = "foo"
}`, testAccRealm.Realm, clientId, mapperName, mapperName)
}

func testKeycloakOpenIdFullNameProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_full_name_protocol_mapper" "full_name_mapper_validation" {
	name       = "%s"
	realm_id   = data.keycloak_realm.realm.id
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdGroupMembershipProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_group_membership_protocol_mapper" "group_membership_mapper_validation" {
	name       = "%s"
	realm_id   = data.keycloak_realm.realm.id
	claim_name = "bar"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdUserAttributeProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_user_attribute_protocol_mapper" "user_attribute_mapper_validation" {
	name           = "%s"
	realm_id       = data.keycloak_realm.realm.id
	user_attribute = "foo"
	claim_name     = "bar"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdUserPropertyProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_user_property_protocol_mapper" "user_property_mapper_validation" {
	name          = "%s"
	realm_id      = data.keycloak_realm.realm.id
	user_property = "foo"
	claim_name    = "bar"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdHardcodedClaimProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id

	claim_name       = "foo"
	claim_value      = "bar"
	claim_value_type = "String"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdUserRealmRoleProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_openid_user_realm_role_protocol_mapper" "user_realm_role_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id

	claim_name       = "foo"
	claim_value_type = "String"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdUserClientRoleProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_user_client_role_protocol_mapper" "user_client_role_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	claim_name       = "foo"
	claim_value_type = "String"
}`, testAccRealm.Realm, mapperName)
}

func testKeycloakOpenIdUserSessionNoteProtocolMapper_parentResourceValidation(mapperName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}
resource "keycloak_openid_user_session_note_protocol_mapper" "user_session_note_mapper_client_scope" {
	name             = "%s"
	realm_id         = data.keycloak_realm.realm.id
	claim_name       = "foo"
	claim_value_type = "String"
}`, testAccRealm.Realm, mapperName)
}
