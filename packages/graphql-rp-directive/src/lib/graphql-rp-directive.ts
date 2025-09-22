import { makeExecutableSchema } from '@graphql-tools/schema';
import { getAuthorizedSchema } from './directives';
import { TRolePermission } from './types';

export const rolePermissionsData: TRolePermission = {
  ADMIN: {
    permissions: [
      'READ_SECURE_DATA',
      'READ_RESTRICTED_FIELD',
      'READ_MUTATION_RESPONSE',
      'CREATE_FIELD',
      'READ_POST',
    ],
  },
  USER: {
    permissions: [
      'READ_SECURE_DATA',
      'READ_RESTRICTED_FIELD',
      'READ_MUTATION_RESPONSE',
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
  posts: [Post]
}

type Post @hasPermission(permissions: ["READ_POST"]) {
  title: String!
  isPublished: Boolean!
}

type Mutation {
  createFields(id: Int!): MutationResponse! @hasPermission(permissions: ["CREATE_FIELD"])
}

type MutationResponse @hasPermission(permissions: ["READ_MUTATION_RESPONSE"]) {
  done: Boolean!
}

`;

const newTypeDefs = `
directive @hasPermission(permissions: [String!]) on FIELD_DEFINITION | OBJECT

type Query  {
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
  posts: [Post]
}

type Post @hasPermission(permissions: ["READ_POST"]) {
  title: String!
  isPublished: Boolean!
}

type Mutation @hasPermission(permissions: ["CREATE_FIELD"]){
  createFields(id: Int!): MutationResponse! 
}

type MutationResponse @hasPermission(permissions: ["READ_MUTATION_RESPONSE"]) {
  done: Boolean!
}

`;

const resolvers = {
  Query: {
    publicFields: () => ({ name: 'public field' }),
    restrictedFields: () => ({ name: 'restricted field' }),
    secureFields: () => ({
      name: 'secure field',
      email: 'test@test.com',
      posts: [
        { title: 'test post', isPublished: true },
        { title: 'test post 2', isPublished: false },
      ],
    }),
  },
  Mutation: {
    createFields: () => ({ done: true }),
  },
};

const schema = makeExecutableSchema({
  typeDefs: newTypeDefs,
  resolvers,
});

export const schemaWithPermissionDirective = getAuthorizedSchema(schema, {
  rolePermissionsData,
});

export const schemaWithPermissionDirectiveWithDynamicPermission =
  getAuthorizedSchema(schema, {});
