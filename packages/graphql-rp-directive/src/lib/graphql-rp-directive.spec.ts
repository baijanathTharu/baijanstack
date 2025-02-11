import {
  rolePermissionsData,
  schemaWithPermissionDirective,
  schemaWithPermissionDirectiveWithDynamicPermission,
} from './graphql-rp-directive';
import { ApolloServer, gql } from 'apollo-server-express';

describe('hasPermissionDirective', () => {
  // ******** static permissions test cases starts ********
  it('should allow access when user has all the required permissions', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: ['ADMIN'],
        },
      },
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['secureFields']).toEqual({
      email: 'test@test.com',
      name: 'secure field',
    });
  });
  it('should not allow access when user has not required permissions', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: ['PUBLIC'],
        },
      },
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Unauthorized access to Query.secureFields'
    );
    expect(res?.data?.['secureFields']).toBeNull();
  });

  it('should not access the api that is missing the directive', async () => {
    const publicFieldsQuery = gql`
      query {
        publicFields {
          name
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: [],
        },
      },
    });

    const res = await server.executeOperation({
      query: publicFieldsQuery,
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Access denied for Query.publicFields'
    );
    // expect(res?.data?.['secureFields']).toBeNull();
  });

  it('should not access create api without required permission', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: ['PUBLIC'],
        },
      },
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Unauthorized access to Mutation.createFields'
    );
  });

  it('should access create api with required permission and multiple roles', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: ['PUBLIC', 'ADMIN'],
        },
      },
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['createFields']).toEqual({ done: true });
  });

  it('should access create api with required permission', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirective,
      context: {
        user: {
          roles: ['ADMIN'],
        },
      },
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['createFields']).toEqual({ done: true });
  });
  // ******** static permissions test cases ends ********

  // ******** dynamic permissions test cases starts ********
  it('should allow access when user has all the required permissions', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['ADMIN'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['secureFields']).toEqual({
      email: 'test@test.com',
      name: 'secure field',
    });
  });

  it('should perform permission check only if the field is requested and user does not have required permission', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
          posts {
            title
            isPublished
          }
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['USER'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeDefined();
  });

  it('should perform permission check only if the field is requested and user has required permission', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
          posts {
            title
            isPublished
          }
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['ADMIN'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['secureFields']).toEqual({
      email: expect.any(String),
      name: expect.any(String),
      posts: expect.any(Array),
    });
  });

  it('should not allow access when user has not required permissions', async () => {
    const secureFieldsQuery = gql`
      query {
        secureFields {
          name
          email
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,

      context: async () => ({
        user: {
          roles: ['PUBLIC'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: secureFieldsQuery,
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Unauthorized access to Query.secureFields'
    );
    expect(res?.data?.['secureFields']).toBeNull();
  });

  it('should not access the api that is missing the directive', async () => {
    const publicFieldsQuery = gql`
      query {
        publicFields {
          name
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: [],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: publicFieldsQuery,
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Access denied for Query.publicFields'
    );
    // expect(res?.data?.['secureFields']).toBeNull();
  });

  it('should not access create api without required permission', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['PUBLIC'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeDefined();
    expect(res.errors?.[0].message).toBe(
      'Unauthorized access to Mutation.createFields'
    );
  });

  it('should access create api with required permission and multiple roles', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['PUBLIC', 'ADMIN'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['createFields']).toEqual({ done: true });
  });

  it('should access create api with required permission', async () => {
    const createMutation = gql`
      mutation createFields($id: Int!) {
        createFields(id: $id) {
          done
        }
      }
    `;

    const server = new ApolloServer<{
      user: {
        roles: Array<string>;
      };
    }>({
      schema: schemaWithPermissionDirectiveWithDynamicPermission,
      context: async () => ({
        user: {
          roles: ['ADMIN'],
        },
        roleAndPermission: rolePermissionsData,
      }),
    });

    const res = await server.executeOperation({
      query: createMutation,
      variables: {
        id: 1,
      },
    });
    expect(res.errors).toBeUndefined();
    expect(res?.data?.['createFields']).toEqual({ done: true });
  });
  // ******** dynamic permissions test cases ends ********
});
