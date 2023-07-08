import { makeExecutableSchema } from '@graphql-tools/schema';
import { getAuthorizedSchema } from './directives';
import { TRolePermission } from './types';

const rolePermissionsData: TRolePermission = {
  ADMIN: {
    permissions: [
      'READ_SECURE_DATA',
      'READ_RESTRICTED_FIELD',
      'READ_MUTATION_RESPONSE',
      'CREATE_FIELD',
    ],
  },
  PUBLIC: {
    permissions: ['READ_MUTATION_RESPONSE'],
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

type Mutation {
  createFields(id: Int!): MutationResponse! @hasPermission(permissions: ["CREATE_FIELD"])
}

type MutationResponse @hasPermission(permissions: ["READ_MUTATION_RESPONSE"]) {
  done: Boolean!
}

`;

const resolvers = {
  Query: {
    publicFields: () => ({ name: 'public field' }),
    restrictedFields: () => ({ name: 'restricted field' }),
    secureFields: () => ({ name: 'secure field', email: 'test@test.com' }),
  },
  Mutation: {
    createFields: () => ({ done: true }),
  },
};

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

export const schemaWithPermissionDirective = getAuthorizedSchema(schema, {
  rolePermissionsData,
});
