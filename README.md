# lldap Go SDK

`github.com/justseemore/lldap` 是一个轻量的 LLDAP Go 客户端，封装了：

- `/auth/simple/login` 登录、JWT 刷新
- GraphQL 用户/组 CRUD
- 用户/组自定义字段定义与赋值
- LDAP Bind 认证
- LDAP PasswordModify 改密
- LDAP 用户查询

## 安装

```bash
go get github.com/justseemore/lldap
```

## 快速开始

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/justseemore/lldap"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	api, err := lldap.New("http://localhost:17170")
	if err != nil {
		log.Fatal(err)
	}
	if err := api.Login(ctx, "admin", "adminPassword"); err != nil {
		log.Fatal(err)
	}

	users, err := api.ListUsers(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, u := range users {
		log.Printf("%s <%s>", u.ID, u.Email)
	}
}
```

## LDAP 认证

```go
ldapClient, err := lldap.NewLDAPClient(lldap.LDAPConfig{
	URL:    "ldap://localhost:3890",
	BaseDN: "dc=example,dc=com",
	Timeout: 10 * time.Second,
})
if err != nil {
	log.Fatal(err)
}

if err := ldapClient.Authenticate(ctx, "alice", "password"); err != nil {
	log.Fatal("invalid credentials")
}
```

## 自定义字段

```go
err := api.AddUserAttribute(ctx, lldap.AttributeDefinitionInput{
	Name:          "employee-id",
	AttributeType: lldap.AttributeTypeString,
	IsList:        false,
	IsVisible:     true,
	IsEditable:    false,
})

email := "alice@example.com"
_, err = api.CreateUser(ctx, lldap.CreateUserInput{
	ID:    "alice",
	Email: &email,
	Attributes: []lldap.AttributeValueInput{
		lldap.StringAttribute("employee-id", "E-1001"),
	},
})
```

## 注意

- LLDAP 的 GraphQL API 不提供改密接口，改密走 LDAP `PasswordModify`。
- `User.attributes` / `Group.attributes` 包含硬编码字段，取自定义字段时用 `Schema.UserCustomAttributes()` / `GroupCustomAttributes()` 或检查 `IsHardcoded`。
- `isVisible` 只影响 LLDAP Web UI，不是访问控制。
- 生产环境请通过 HTTPS 调用 LLDAP HTTP API。
