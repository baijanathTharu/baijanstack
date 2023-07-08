import { mapSchema, getDirective, MapperKind } from '@graphql-tools/utils';
import { GraphQLSchema, defaultFieldResolver } from 'graphql';
import { TIsAuthorizedArgs, TRolePermission } from './types';

function denyRequest({
  fieldPermissions,
  typePermissions,
  fieldName,
  typeName,
}: {
  fieldPermissions: Array<string>;
  typePermissions: Array<string>;
  fieldName: string;
  typeName: string;
}) {
  if (fieldName.startsWith('_') || typeName.startsWith('_')) {
    return false;
  }
  const hasNoPermissions =
    fieldPermissions.length === 0 && typePermissions.length === 0;
  return hasNoPermissions;
}

function isAuthorized({
  fieldPermissions,
  typePermissions,
  user,
  ROLE_PERMISSIONS,
}: TIsAuthorizedArgs) {
  const userRoles = user?.roles ?? [];
  const userPermissions = new Set();
  userRoles.forEach((roleKey) => {
    const role = ROLE_PERMISSIONS[roleKey] ?? ROLE_PERMISSIONS['PUBLIC'];
    role.permissions?.forEach((permission) => userPermissions.add(permission));
  });

  for (const permission of fieldPermissions) {
    if (userPermissions.has(permission)) {
      return true;
    }
  }

  if (fieldPermissions.length === 0) {
    for (const typePermission of typePermissions) {
      if (userPermissions.has(typePermission)) {
        return true;
      }
    }
  }
  return false;
}

function gatherTypePermissions(schema: GraphQLSchema) {
  const typePermissionMapping = new Map();
  mapSchema(schema, {
    [MapperKind.OBJECT_TYPE]: (typeConfig) => {
      const typeAuthDirective = getDirective(
        schema,
        typeConfig,
        'hasPermission'
      )?.[0];
      const typeLevelPermissions = typeAuthDirective?.['permissions'] ?? [];
      typePermissionMapping.set(typeConfig.name, typeLevelPermissions);
      return typeConfig;
    },
  });
  return typePermissionMapping;
}

export function getAuthorizedSchema(
  schema: GraphQLSchema,
  { rolePermissionsData }: { rolePermissionsData: TRolePermission }
) {
  const typePermissionMapping = gatherTypePermissions(schema);

  const authorizedSchema = mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig, fieldName, typeName) => {
      const fieldAuthDirective = getDirective(
        schema,
        fieldConfig,
        'hasPermission'
      )?.[0];
      const fieldPermissions = fieldAuthDirective?.['permissions'] ?? [];
      const typePermissions = typePermissionMapping.get(typeName) ?? [];

      if (
        denyRequest({ fieldPermissions, typePermissions, fieldName, typeName })
      ) {
        fieldConfig.resolve = () => {
          throw new Error(`Denied Request for ${typeName}.${fieldName}`);
        };
        return fieldConfig;
      }

      if (fieldPermissions.length > 0 || typePermissions.length > 0) {
        const originalResolver = fieldConfig.resolve ?? defaultFieldResolver;
        fieldConfig.resolve = (source, args, context, info) => {
          const user = context.user;
          if (
            !isAuthorized({
              fieldPermissions,
              typePermissions,
              user,
              ROLE_PERMISSIONS: rolePermissionsData,
            })
          ) {
            throw new Error('Unauthorized');
          }
          return originalResolver(source, args, context, info);
        };
      }
      return fieldConfig;
    },
  });
  return authorizedSchema;
}
