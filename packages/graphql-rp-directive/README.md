# graphql-rp-directive

This is used to do authorization in graphql using directives. You can use permission based directive to implement the authorization using this package as per your requirements.

## Usage

1. Install the dependency.

```bash
npm install @baijanstack/graphql-rp-directive
```

2. Update your typedefs with the necessary directive.

```ts
const typedefs = gql`
  directive @hasPermission(permissions: [String!]) on FIELD_DEFINITION | OBJECT

  # your other typedefs
  # ...
`;
```

3. Create your role and permission data.

> Note: If you have static role and permission, you can create the role and permission object as below: However, if you have dynamic role and permissions, you can pass it from the context like we pass the user object.

```ts
import { getAuthorizedSchema, TRolePermission } from '@baijanstack/graphql-rp-directive';

const rolePermissionsData: TRolePermission = {
  ADMIN: {
    permissions: ['READ_SECURE_DATA', 'READ_RESTRICTED_FIELD', 'READ_MUTATION_RESPONSE', 'CREATE_FIELD'],
  },
  PUBLIC: {
    permissions: ['READ_MUTATION_RESPONSE'],
  },
};
```

4. Create your executable schema with your typedefs and resolvers.

```ts
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});
```

5. Add the permission directives to your schema.

```ts
const schemaWithPermissionDirective = getAuthorizedSchema(schema, {
  rolePermissionsData,
});
```

6. Pass `schemaWithPermissionDirective` as schema to your graphql server and return the `user` object from the context.

> Note: If you have a dynamic role and permissions, you have to pass the dynamic `roleAndPermission` object of type `TRolePermission` as shown below. The dynamic permissions take priority than the static permission if you passed both of them.

```ts
const server = new ApolloServer<{
  user: {
    roles: Array<string>;
  };
  roleAndPermission?: TRolePermission;
}>({
  schema: schemaWithPermissionDirective,
  context: {
    user: {
      roles: ['PUBLIC'],
    },
    // This context can be async function and you can pass the `roleAndPermission`
    // by quering your database or reading from cache.
    roleAndPermission: {
      ADMIN: {
        permissions: ['READ_SECURE_DATA', 'READ_RESTRICTED_FIELD', 'READ_MUTATION_RESPONSE', 'CREATE_FIELD'],
      },
      PUBLIC: {
        permissions: ['READ_MUTATION_RESPONSE'],
      },
    },
  },
});
```

7. By default, all your resolvers request will be denied unless you specify the directive on the field or object.

8. Apply directives to your typedefs.

```ts
const typeDefs = `
directive @hasPermission(permissions: [String!]) on FIELD_DEFINITION | OBJECT

type Query {
  # this api will be denied request because it is missing the directive
  publicFields: PublicField
  restrictedFields: RestrictedField @hasPermission(permissions: ["READ_RESTRICTED_FIELD"])
  secureFields: SecureField @hasPermission(permissions: ["READ_SECURE_DATA"])
}

type PublicField {
  name: String!
}

type RestrictedField {
  name: String!
}

type SecureField @hasPermission(permissions: ["READ_SECURE_DATA"]) {
  name: String!
  email: String!
}

type Mutation {
  createFields(id: Int!): MutationResponse! @hasPermission(permissions: ["CREATE_FIELD"])
}

type MutationResponse @hasPermission(permissions: ["READ_MUTATION_RESPONSE"]) {
  done: Boolean!
}
`;
```
