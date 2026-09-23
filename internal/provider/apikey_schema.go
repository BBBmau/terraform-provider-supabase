// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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

// apiKeyStringAttribute is the shared definition of an API key schema field.
// The managed resource and data source use different schema packages, so each
// caller converts this value into the package it needs.
type apiKeyStringAttribute struct {
	markdownDescription string
	required            bool
	optional            bool
	computed            bool
	sensitive           bool
	validateName        bool
}

func (a apiKeyStringAttribute) withDescription(description string) apiKeyStringAttribute {
	a.markdownDescription = description
	return a
}

func (a apiKeyStringAttribute) asComputed() apiKeyStringAttribute {
	a.required = false
	a.optional = false
	a.computed = true
	a.validateName = false
	return a
}

func (a apiKeyStringAttribute) resource(mods ...planmodifier.String) rschema.StringAttribute {
	return rschema.StringAttribute{
		MarkdownDescription: a.markdownDescription,
		Required:            a.required,
		Optional:            a.optional,
		Computed:            a.computed,
		Sensitive:           a.sensitive,
		Validators:          a.validators(),
		PlanModifiers:       mods,
	}
}

func (a apiKeyStringAttribute) dataSource() dschema.StringAttribute {
	return dschema.StringAttribute{
		MarkdownDescription: a.markdownDescription,
		Required:            a.required,
		Optional:            a.optional,
		Computed:            a.computed,
		Sensitive:           a.sensitive,
		Validators:          a.validators(),
	}
}

func (a apiKeyStringAttribute) validators() []validator.String {
	if !a.validateName {
		return nil
	}
	return []validator.String{
		stringvalidator.RegexMatches(apiKeyNamePattern, apiKeyNameValidationMessage),
	}
}

var (
	apiKeyIDAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyIDDescription,
		computed:            true,
	}
	apiKeyProjectRefAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyProjectRefDescription,
		required:            true,
	}
	apiKeyNameAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyNameDescription,
		required:            true,
		validateName:        true,
	}
	apiKeyDescriptionAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyDescriptionDescription,
		optional:            true,
	}
	apiKeyTypeAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyTypeDescription,
		computed:            true,
	}
	apiKeyValueAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeyValueDescription,
		computed:            true,
		sensitive:           true,
	}
	apiKeySecretJWTRoleAttribute = apiKeyStringAttribute{
		markdownDescription: apiKeySecretJWTRoleDescription,
		computed:            true,
	}
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
