import { makeExecutableSchema } from '@graphql-tools/schema';
import { getAuthorizedSchema } from './directives';
import { TRolePermission } from './types';

const rolePermissionsData: TRolePermission = {
  ADMIN: {
    permissions: ['READ_SECURE_DATA', 'READ_RESTRICTED_FIELD'],
  },
  PUBLIC: {
    permissions: [],
  },
};

const typeDefs = `
directive @hasPermission(permissions: [String!]) on FIELD_DEFINITION | OBJECT

type Query {
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

`;

const resolvers = {
  Query: {
    publicFields: () => ({ name: 'public field' }),
    restrictedFields: () => ({ name: 'restricted field' }),
    secureFields: () => ({ name: 'secure field', email: 'test@test.com' }),
  },
};

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

export const schemaWithPermissionDirective = getAuthorizedSchema(schema, {
  rolePermissionsData,
});
