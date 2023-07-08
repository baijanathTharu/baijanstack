import { schemaWithPermissionDirective } from './graphql-rp-directive';
import { ApolloServer, gql } from 'apollo-server-express';

describe('hasPermissionDirective', () => {
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
    expect(res.errors?.[0].message).toBe('Unauthorized');
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
    expect(res.errors?.[0].message).toBe('Unauthorized');
    // expect(res?.data?.['secureFields']).toBeNull();
  });
});
