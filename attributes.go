package lldap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type AttributeType string

const (
	AttributeTypeString    AttributeType = "STRING"
	AttributeTypeInteger   AttributeType = "INTEGER"
	AttributeTypeJPEGPhoto AttributeType = "JPEG_PHOTO"
	AttributeTypeDateTime  AttributeType = "DATE_TIME"
)

type ObjectClassInfo struct {
	ObjectClass string `json:"objectClass"`
	IsHardcoded bool   `json:"isHardcoded"`
}

type AttributeSchema struct {
	Name          string        `json:"name"`
	AttributeType AttributeType `json:"attributeType"`
	IsList        bool          `json:"isList"`
	IsVisible     bool          `json:"isVisible"`
	IsEditable    bool          `json:"isEditable"`
	IsHardcoded   bool          `json:"isHardcoded"`
	IsReadonly    bool          `json:"isReadonly"`
}

type AttributeList struct {
	Attributes             []AttributeSchema `json:"attributes"`
	ExtraLDAPObjectClasses []string          `json:"extraLdapObjectClasses"`
	LDAPObjectClasses      []ObjectClassInfo `json:"ldapObjectClasses"`
}

type Schema struct {
	UserSchema  AttributeList `json:"userSchema"`
	GroupSchema AttributeList `json:"groupSchema"`
}

const attributeSchemaFields = `
fragment AttributeSchemaFields on AttributeSchema {
  name
  attributeType
  isList
  isVisible
  isEditable
  isHardcoded
  isReadonly
}
`

const groupListFields = `
fragment GroupListFields on Group {
  id
  displayName
  creationDate
  uuid
  attributes {
    name
    value
    schema { ...AttributeSchemaFields }
  }
}
` + attributeSchemaFields

const groupFields = `
fragment GroupFields on Group {
  id
  displayName
  creationDate
  uuid
  attributes {
    name
    value
    schema { ...AttributeSchemaFields }
  }
  users { id displayName }
}
` + attributeSchemaFields

const attributeListFields = `
fragment AttributeListFields on AttributeList {
  attributes { ...AttributeSchemaFields }
  extraLdapObjectClasses
  ldapObjectClasses {
    objectClass
    isHardcoded
  }
}
` + attributeSchemaFields

func (c *Client) GetSchema(ctx context.Context) (*Schema, error) {
	const q = `
query GetSchema {
  schema {
    userSchema { ...AttributeListFields }
    groupSchema { ...AttributeListFields }
  }
}
` + attributeListFields

	var data struct {
		Schema Schema `json:"schema"`
	}
	if err := c.do(ctx, q, nil, &data); err != nil {
		return nil, err
	}
	return &data.Schema, nil
}

// UserCustomAttributes 只返回用户自定义字段，
// 过滤掉 user_id/mail/display_name 等硬编码字段。
func (s *Schema) UserCustomAttributes() []AttributeSchema {
	var out []AttributeSchema
	for _, a := range s.UserSchema.Attributes {
		if !a.IsHardcoded {
			out = append(out, a)
		}
	}
	return out
}

func (s *Schema) GroupCustomAttributes() []AttributeSchema {
	var out []AttributeSchema
	for _, a := range s.GroupSchema.Attributes {
		if !a.IsHardcoded {
			out = append(out, a)
		}
	}
	return out
}

type AttributeDefinitionInput struct {
	Name          string
	AttributeType AttributeType
	IsList        bool
	IsVisible     bool
	IsEditable    bool
}

func (in AttributeDefinitionInput) vars() map[string]any {
	return map[string]any{
		"name":          in.Name,
		"attributeType": in.AttributeType,
		"isList":        in.IsList,
		"isVisible":     in.IsVisible,
		"isEditable":    in.IsEditable,
	}
}

func (c *Client) AddUserAttribute(
	ctx context.Context,
	in AttributeDefinitionInput,
) error {
	const q = `
mutation AddUserAttribute(
  $name: String!
  $attributeType: AttributeType!
  $isList: Boolean!
  $isVisible: Boolean!
  $isEditable: Boolean!
) {
  addUserAttribute(
    name: $name
    attributeType: $attributeType
    isList: $isList
    isVisible: $isVisible
    isEditable: $isEditable
  ) { ok }
}`

	var data struct {
		AddUserAttribute Success `json:"addUserAttribute"`
	}
	if err := c.do(ctx, q, in.vars(), &data); err != nil {
		return err
	}
	return checkSuccess("addUserAttribute", data.AddUserAttribute)
}

func (c *Client) AddGroupAttribute(
	ctx context.Context,
	in AttributeDefinitionInput,
) error {
	const q = `
mutation AddGroupAttribute(
  $name: String!
  $attributeType: AttributeType!
  $isList: Boolean!
  $isVisible: Boolean!
  $isEditable: Boolean!
) {
  addGroupAttribute(
    name: $name
    attributeType: $attributeType
    isList: $isList
    isVisible: $isVisible
    isEditable: $isEditable
  ) { ok }
}`

	var data struct {
		AddGroupAttribute Success `json:"addGroupAttribute"`
	}
	if err := c.do(ctx, q, in.vars(), &data); err != nil {
		return err
	}
	return checkSuccess("addGroupAttribute", data.AddGroupAttribute)
}

func (c *Client) DeleteUserAttribute(
	ctx context.Context,
	name string,
) error {
	const q = `
mutation DeleteUserAttribute($name: String!) {
  deleteUserAttribute(name: $name) { ok }
}`

	var data struct {
		DeleteUserAttribute Success `json:"deleteUserAttribute"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"name": name},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("deleteUserAttribute", data.DeleteUserAttribute)
}

func (c *Client) DeleteGroupAttribute(
	ctx context.Context,
	name string,
) error {
	const q = `
mutation DeleteGroupAttribute($name: String!) {
  deleteGroupAttribute(name: $name) { ok }
}`

	var data struct {
		DeleteGroupAttribute Success `json:"deleteGroupAttribute"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"name": name},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("deleteGroupAttribute", data.DeleteGroupAttribute)
}

func (c *Client) CreateGroupWithDetails(
	ctx context.Context,
	in CreateGroupInput,
) (*Group, error) {
	const q = `
mutation CreateGroupWithDetails($request: CreateGroupInput!) {
  createGroupWithDetails(request: $request) { ...GroupFields }
}
` + groupFields

	var data struct {
		CreateGroupWithDetails Group `json:"createGroupWithDetails"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"request": in},
		&data,
	); err != nil {
		return nil, err
	}
	return &data.CreateGroupWithDetails, nil
}

// UpdateUserAttributes 只改自定义字段，不动 email/displayName。
func (c *Client) UpdateUserAttributes(
	ctx context.Context,
	userID string,
	insert []AttributeValueInput,
	remove []string,
) error {
	return c.UpdateUser(ctx, UpdateUserInput{
		ID:               userID,
		InsertAttributes: insert,
		RemoveAttributes: remove,
	})
}

func (c *Client) UpdateGroupAttributes(
	ctx context.Context,
	groupID int,
	insert []AttributeValueInput,
	remove []string,
) error {
	return c.UpdateGroup(ctx, UpdateGroupInput{
		ID:               groupID,
		InsertAttributes: insert,
		RemoveAttributes: remove,
	})
}

// ---------- 值构造器 ----------

func StringAttribute(
	name string,
	values ...string,
) AttributeValueInput {
	return AttributeValueInput{
		Name:  name,
		Value: values,
	}
}

func IntegerAttribute(
	name string,
	values ...int64,
) AttributeValueInput {
	ss := make([]string, len(values))
	for i, v := range values {
		ss[i] = strconv.FormatInt(v, 10)
	}
	return AttributeValueInput{
		Name:  name,
		Value: ss,
	}
}

func DateTimeAttribute(
	name string,
	values ...time.Time,
) AttributeValueInput {
	ss := make([]string, len(values))
	for i, v := range values {
		ss[i] = v.UTC().Format(time.RFC3339)
	}
	return AttributeValueInput{
		Name:  name,
		Value: ss,
	}
}

func JPEGAttribute(name string, jpeg []byte) AttributeValueInput {
	return AttributeValueInput{
		Name:  name,
		Value: []string{base64.StdEncoding.EncodeToString(jpeg)},
	}
}

// ---------- 读取辅助 ----------

func FindAttribute(
	values []AttributeValue,
	name string,
) (AttributeValue, bool) {
	for _, v := range values {
		if strings.EqualFold(v.Name, name) {
			return v, true
		}
	}
	return AttributeValue{}, false
}

func (u *User) Attribute(name string) (AttributeValue, bool) {
	return FindAttribute(u.Attributes, name)
}

func (g *Group) Attribute(name string) (AttributeValue, bool) {
	return FindAttribute(g.Attributes, name)
}

// ValidateAttributeName 只做客户端预校验；
// 服务端允许字母/数字/-，大小写不敏感。
func ValidateAttributeName(name string) error {
	if name == "" {
		return errors.New("lldap: attribute name is empty")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf(
				"lldap: invalid character %q in attribute name %q (allowed: a-z A-Z 0-9 -)",
				r,
				name,
			)
		}
	}
	return nil
}
