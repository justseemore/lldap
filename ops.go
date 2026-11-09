package lldap

import (
	"context"
	"fmt"
)

type Success struct {
	OK bool `json:"ok"`
}

type AttributeValue struct {
	Name   string           `json:"name"`
	Value  []string         `json:"value"`
	Schema *AttributeSchema `json:"schema,omitempty"`
}

type Group struct {
	ID           int              `json:"id"`
	DisplayName  string           `json:"displayName"`
	CreationDate string           `json:"creationDate"`
	UUID         string           `json:"uuid"`
	Attributes   []AttributeValue `json:"attributes"`
	Users        []User           `json:"users"`
}

type User struct {
	ID           string           `json:"id"`
	Email        string           `json:"email"`
	DisplayName  string           `json:"displayName"`
	FirstName    string           `json:"firstName"`
	LastName     string           `json:"lastName"`
	Avatar       *string          `json:"avatar"`
	CreationDate string           `json:"creationDate"`
	UUID         string           `json:"uuid"`
	Attributes   []AttributeValue `json:"attributes"`
	Groups       []Group          `json:"groups"`
}

type EqualityConstraint struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type RequestFilter struct {
	Any        []RequestFilter     `json:"any,omitempty"`
	All        []RequestFilter     `json:"all,omitempty"`
	Not        *RequestFilter      `json:"not,omitempty"`
	Eq         *EqualityConstraint `json:"eq,omitempty"`
	MemberOf   *string             `json:"memberOf,omitempty"`
	MemberOfID *int                `json:"memberOfId,omitempty"`
}

type AttributeValueInput struct {
	Name  string   `json:"name"`
	Value []string `json:"value"`
}

type CreateUserInput struct {
	ID          string                `json:"id"`
	Email       *string               `json:"email,omitempty"`
	DisplayName *string               `json:"displayName,omitempty"`
	FirstName   *string               `json:"firstName,omitempty"`
	LastName    *string               `json:"lastName,omitempty"`
	Avatar      *string               `json:"avatar,omitempty"`
	Attributes  []AttributeValueInput `json:"attributes,omitempty"`
}

type UpdateUserInput struct {
	ID               string                `json:"id"`
	Email            *string               `json:"email,omitempty"`
	DisplayName      *string               `json:"displayName,omitempty"`
	FirstName        *string               `json:"firstName,omitempty"`
	LastName         *string               `json:"lastName,omitempty"`
	Avatar           *string               `json:"avatar,omitempty"`
	RemoveAttributes []string              `json:"removeAttributes,omitempty"`
	InsertAttributes []AttributeValueInput `json:"insertAttributes,omitempty"`
}

type CreateGroupInput struct {
	DisplayName string                `json:"displayName"`
	Attributes  []AttributeValueInput `json:"attributes,omitempty"`
}

type UpdateGroupInput struct {
	ID               int                   `json:"id"`
	DisplayName      *string               `json:"displayName,omitempty"`
	RemoveAttributes []string              `json:"removeAttributes,omitempty"`
	InsertAttributes []AttributeValueInput `json:"insertAttributes,omitempty"`
}

const userFields = `
fragment UserFields on User {
  id
  email
  displayName
  firstName
  lastName
  avatar
  creationDate
  uuid
  attributes {
    name
    value
    schema { ...AttributeSchemaFields }
  }
  groups { id displayName }
}
` + attributeSchemaFields

func (c *Client) APIVersion(ctx context.Context) (string, error) {
	const q = `query { apiVersion }`

	var data struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := c.do(ctx, q, nil, &data); err != nil {
		return "", err
	}
	return data.APIVersion, nil
}

func (c *Client) ListUsers(
	ctx context.Context,
	filter *RequestFilter,
) ([]User, error) {
	const q = `
query ListUsers($filters: RequestFilter) {
  users(filters: $filters) { ...UserFields }
}
` + userFields

	var data struct {
		Users []User `json:"users"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"filters": filter},
		&data,
	); err != nil {
		return nil, err
	}
	return data.Users, nil
}

func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	const q = `
query GetUser($userId: String!) {
  user(userId: $userId) { ...UserFields }
}
` + userFields

	var data struct {
		User User `json:"user"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"userId": userID},
		&data,
	); err != nil {
		return nil, err
	}
	return &data.User, nil
}

func (c *Client) CreateUser(
	ctx context.Context,
	in CreateUserInput,
) (*User, error) {
	const q = `
mutation CreateUser($user: CreateUserInput!) {
  createUser(user: $user) { ...UserFields }
}
` + userFields

	var data struct {
		CreateUser User `json:"createUser"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"user": in},
		&data,
	); err != nil {
		return nil, err
	}
	return &data.CreateUser, nil
}

func (c *Client) UpdateUser(
	ctx context.Context,
	in UpdateUserInput,
) error {
	const q = `
mutation UpdateUser($user: UpdateUserInput!) {
  updateUser(user: $user) { ok }
}`

	var data struct {
		UpdateUser Success `json:"updateUser"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"user": in},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("updateUser", data.UpdateUser)
}

func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	const q = `
mutation DeleteUser($userId: String!) {
  deleteUser(userId: $userId) { ok }
}`

	var data struct {
		DeleteUser Success `json:"deleteUser"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"userId": userID},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("deleteUser", data.DeleteUser)
}

func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	const q = `
query {
  groups { ...GroupListFields }
}
` + groupListFields

	var data struct {
		Groups []Group `json:"groups"`
	}
	if err := c.do(ctx, q, nil, &data); err != nil {
		return nil, err
	}
	return data.Groups, nil
}

func (c *Client) GetGroup(
	ctx context.Context,
	groupID int,
) (*Group, error) {
	const q = `
query GetGroup($groupId: Int!) {
  group(groupId: $groupId) { ...GroupFields }
}
` + groupFields

	var data struct {
		Group Group `json:"group"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"groupId": groupID},
		&data,
	); err != nil {
		return nil, err
	}
	return &data.Group, nil
}

func (c *Client) CreateGroup(
	ctx context.Context,
	name string,
) (*Group, error) {
	const q = `
mutation CreateGroup($name: String!) {
  createGroup(name: $name) {
    id
    displayName
    creationDate
    uuid
  }
}`

	var data struct {
		CreateGroup Group `json:"createGroup"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"name": name},
		&data,
	); err != nil {
		return nil, err
	}
	return &data.CreateGroup, nil
}

func (c *Client) UpdateGroup(
	ctx context.Context,
	in UpdateGroupInput,
) error {
	const q = `
mutation UpdateGroup($group: UpdateGroupInput!) {
  updateGroup(group: $group) { ok }
}`

	var data struct {
		UpdateGroup Success `json:"updateGroup"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{"group": in},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("updateGroup", data.UpdateGroup)
}

func (c *Client) AddUserToGroup(
	ctx context.Context,
	userID string,
	groupID int,
) error {
	const q = `
mutation AddUserToGroup($userId: String!, $groupId: Int!) {
  addUserToGroup(userId: $userId, groupId: $groupId) { ok }
}`

	var data struct {
		AddUserToGroup Success `json:"addUserToGroup"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{
			"userId":  userID,
			"groupId": groupID,
		},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("addUserToGroup", data.AddUserToGroup)
}

func (c *Client) RemoveUserFromGroup(
	ctx context.Context,
	userID string,
	groupID int,
) error {
	const q = `
mutation RemoveUserFromGroup($userId: String!, $groupId: Int!) {
  removeUserFromGroup(userId: $userId, groupId: $groupId) { ok }
}`

	var data struct {
		RemoveUserFromGroup Success `json:"removeUserFromGroup"`
	}
	if err := c.do(
		ctx,
		q,
		map[string]any{
			"userId":  userID,
			"groupId": groupID,
		},
		&data,
	); err != nil {
		return err
	}
	return checkSuccess("removeUserFromGroup", data.RemoveUserFromGroup)
}

func checkSuccess(op string, s Success) error {
	if !s.OK {
		return fmt.Errorf("lldap: %s returned ok=false", op)
	}
	return nil
}
