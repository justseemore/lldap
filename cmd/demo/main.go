package main

import (
	"context"
	"log"
	"time"

	"github.com/justseemore/lldap"
)

func main() {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	// 1. GraphQL 管理通道
	api, err := lldap.New("http://localhost:17170")
	if err != nil {
		log.Fatal(err)
	}
	if err := api.Login(
		ctx,
		"admin",
		"adminPassword",
	); err != nil {
		log.Fatal(err)
	}

	version, err := api.APIVersion(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("lldap API version: %s", version)

	schema, err := api.GetSchema(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range schema.UserCustomAttributes() {
		log.Printf(
			"user attr: %s type=%s list=%v",
			a.Name,
			a.AttributeType,
			a.IsList,
		)
	}
	for _, a := range schema.GroupCustomAttributes() {
		log.Printf(
			"group attr: %s type=%s list=%v",
			a.Name,
			a.AttributeType,
			a.IsList,
		)
	}

	// 2. 定义用户自定义字段
	err = api.AddUserAttribute(
		ctx,
		lldap.AttributeDefinitionInput{
			Name:          "employee-id",
			AttributeType: lldap.AttributeTypeString,
			IsList:        false,
			IsVisible:     true,
			IsEditable:    false,
		},
	)
	if err != nil {
		log.Printf("add user attr: %v", err)
	}

	// 3. 创建用户并赋值
	email := "alice@example.com"
	displayName := "Alice"
	alice, err := api.CreateUser(
		ctx,
		lldap.CreateUserInput{
			ID:          "alice",
			Email:       &email,
			DisplayName: &displayName,
			Attributes: []lldap.AttributeValueInput{
				lldap.StringAttribute(
					"employee-id",
					"E-1001",
				),
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("created user uuid=%s", alice.UUID)

	// 4. 更新用户自定义字段
	err = api.UpdateUserAttributes(
		ctx,
		alice.ID,
		[]lldap.AttributeValueInput{
			lldap.StringAttribute(
				"employee-id",
				"E-1002",
			),
		},
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. 定义组自定义字段
	err = api.AddGroupAttribute(
		ctx,
		lldap.AttributeDefinitionInput{
			Name:          "cost-center",
			AttributeType: lldap.AttributeTypeString,
			IsList:        false,
			IsVisible:     true,
			IsEditable:    false,
		},
	)
	if err != nil {
		log.Printf("add group attr: %v", err)
	}

	// 6. 创建组并赋值
	eng, err := api.CreateGroupWithDetails(
		ctx,
		lldap.CreateGroupInput{
			DisplayName: "engineering",
			Attributes: []lldap.AttributeValueInput{
				lldap.StringAttribute(
					"cost-center",
					"CC-42",
				),
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("created group id=%d", eng.ID)

	// 7. 读取自定义字段
	u, err := api.GetUser(ctx, "alice")
	if err != nil {
		log.Fatal(err)
	}
	if v, ok := u.Attribute("employee-id"); ok {
		log.Printf("employee-id = %v", v.Value)
	}

	g, err := api.GetGroup(ctx, eng.ID)
	if err != nil {
		log.Fatal(err)
	}
	if v, ok := g.Attribute("cost-center"); ok {
		log.Printf("cost-center = %v", v.Value)
	}

	// 8. LDAP：设置密码 + 验证密码
	ldapClient, err := lldap.NewLDAPClient(
		lldap.LDAPConfig{
			URL:          "ldap://localhost:3890",
			BaseDN:       "dc=example,dc=com",
			BindDN:       "uid=admin,ou=people,dc=example,dc=com",
			BindPassword: "adminPassword",
			Timeout:      10 * time.Second,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	err = ldapClient.SetPassword(
		ctx,
		"alice",
		"correct-horse-battery-staple",
	)
	if err != nil {
		log.Fatal(err)
	}
	err = ldapClient.Authenticate(
		ctx,
		"alice",
		"correct-horse-battery-staple",
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("password set and verified")

	// 9. 加入管理员组
	groups, err := api.ListGroups(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, group := range groups {
		if group.DisplayName == "lldap_admin" {
			if err := api.AddUserToGroup(
				ctx,
				alice.ID,
				group.ID,
			); err != nil {
				log.Fatal(err)
			}
			break
		}
	}
}
