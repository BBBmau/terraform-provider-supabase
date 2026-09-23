// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/oapi-codegen/nullable"
	"github.com/supabase/cli/pkg/api"
)

const (
	apiKeyIDDescription          = "API key identifier"
	apiKeyProjectRefDescription  = "Project reference ID"
	apiKeyNameDescription        = "Name of the API key"
	apiKeyNameValidationMessage  = "Name must start with a lowercase letter or an underscore, followed only by lowercase alphanumeric characters or underscore"
	apiKeyDescriptionDescription = "Description of the API key"
	apiKeyTypeDescription        = "Type of the API key"
	apiKeyValueDescription       = "API key"

	apiKeySecretJWTTemplateDescription = "Secret JWT template"
	apiKeySecretJWTRoleDescription     = "Role of the secret JWT template"

	apiKeyDataSourceSecretNameDescription  = "Name of the secret key"
	apiKeyDataSourceSecretValueDescription = "The secret API key value"

	apiKeyServiceRole = "service_role"
	apiKeyDefaultName = "default"
)

var apiKeyNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

var (
	apiKeyIDAttribute = newStringSchemaAttribute(apiKeyIDDescription).
				withComputed().
				withPlanModifiers(stringplanmodifier.UseStateForUnknown())
	apiKeyProjectRefAttribute = newStringSchemaAttribute(apiKeyProjectRefDescription).
					withRequired()
	apiKeyNameAttribute = newStringSchemaAttribute(apiKeyNameDescription).
				withRequired().
				withValidators(stringvalidator.RegexMatches(apiKeyNamePattern, apiKeyNameValidationMessage))
	apiKeyDescriptionAttribute = newStringSchemaAttribute(apiKeyDescriptionDescription).
					withOptional()
	apiKeyTypeAttribute = newStringSchemaAttribute(apiKeyTypeDescription).
				withComputed().
				withPlanModifiers(stringplanmodifier.UseStateForUnknown())
	apiKeyValueAttribute = newStringSchemaAttribute(apiKeyValueDescription).
				withComputed().
				withSensitive()
	apiKeySecretJWTRoleAttribute = newStringSchemaAttribute(apiKeySecretJWTRoleDescription).
					withComputed()
)

func apiKeySecretJWTTemplateResource(mods ...planmodifier.Object) rschema.SingleNestedAttribute {
	return rschema.SingleNestedAttribute{
		MarkdownDescription: apiKeySecretJWTTemplateDescription,
		Computed:            true,
		PlanModifiers:       mods,
		Attributes: map[string]rschema.Attribute{
			"role": apiKeySecretJWTRoleAttribute.resource(),
		},
	}
}

func serviceRoleJWTTemplate() map[string]interface{} {
	return map[string]interface{}{"role": apiKeyServiceRole}
}

func secretJWTTemplateObject(role types.String) (types.Object, diag.Diagnostics) {
	return types.ObjectValue(secretJwtTemplateAttrTypes, map[string]attr.Value{
		"role": role,
	})
}

func apiKeyDescription(value types.String) nullable.Nullable[string] {
	if value.IsNull() || value.IsUnknown() {
		return nullable.Nullable[string]{}
	}
	return nullable.NewNullableWithValue(value.ValueString())
}

func apiKeyIsDefaultPublishable(key api.ApiKeyResponse) bool {
	if key.Name != apiKeyDefaultName || !key.Type.IsSpecified() || key.Type.IsNull() {
		return false
	}
	return key.Type.MustGet() == api.ApiKeyResponseTypePublishable
}
