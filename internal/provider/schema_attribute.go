// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// schemaAttribute is a provider schema field that can be added to a managed
// resource or a data source. Resource plan modifiers are ignored by data sources.
//
// stringSchemaAttribute is the example implementation. Other attribute kinds
// can follow the same resource and dataSource methods.
type schemaAttribute interface {
	resource() rschema.Attribute
	dataSource() dschema.Attribute
}

// stringSchemaAttribute is a string field shared by managed resources and data sources.
type stringSchemaAttribute struct {
	markdownDescription string
	required            bool
	optional            bool
	computed            bool
	sensitive           bool
	validators          []validator.String
	planModifiers       []planmodifier.String
}

// newStringSchemaAttribute starts a string field with the given description.
// Callers set required, optional, computed, sensitive, validators, and plan
// modifiers, then render it with resource or dataSource.
func newStringSchemaAttribute(description string) stringSchemaAttribute {
	return stringSchemaAttribute{markdownDescription: description}
}

func (a stringSchemaAttribute) withDescription(description string) stringSchemaAttribute {
	a.markdownDescription = description
	return a
}

func (a stringSchemaAttribute) withRequired() stringSchemaAttribute {
	a.required = true
	return a
}

func (a stringSchemaAttribute) withOptional() stringSchemaAttribute {
	a.optional = true
	return a
}

func (a stringSchemaAttribute) withComputed() stringSchemaAttribute {
	a.computed = true
	return a
}

func (a stringSchemaAttribute) withSensitive() stringSchemaAttribute {
	a.sensitive = true
	return a
}

func (a stringSchemaAttribute) withValidators(validators ...validator.String) stringSchemaAttribute {
	a.validators = validators
	return a
}

func (a stringSchemaAttribute) withPlanModifiers(mods ...planmodifier.String) stringSchemaAttribute {
	a.planModifiers = mods
	return a
}

// asComputed makes the field read-only. Config validators and plan modifiers
// from the source field are cleared because they apply to practitioner input.
func (a stringSchemaAttribute) asComputed() stringSchemaAttribute {
	a.required = false
	a.optional = false
	a.computed = true
	a.validators = nil
	a.planModifiers = nil
	return a
}

func (a stringSchemaAttribute) resource() rschema.Attribute {
	return rschema.StringAttribute{
		MarkdownDescription: a.markdownDescription,
		Required:            a.required,
		Optional:            a.optional,
		Computed:            a.computed,
		Sensitive:           a.sensitive,
		Validators:          a.validators,
		PlanModifiers:       a.planModifiers,
	}
}

func (a stringSchemaAttribute) dataSource() dschema.Attribute {
	return dschema.StringAttribute{
		MarkdownDescription: a.markdownDescription,
		Required:            a.required,
		Optional:            a.optional,
		Computed:            a.computed,
		Sensitive:           a.sensitive,
		Validators:          a.validators,
	}
}

var _ schemaAttribute = stringSchemaAttribute{}
