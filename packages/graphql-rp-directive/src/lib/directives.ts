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
  {
    rolePermissionsData,
  }: {
    /**
     * If you have static roles and permission, you can pass it here.
     * However, if they are dynamic or must be ready asyncronously from
     * any source, you can pass it in the context like we pass the user
     * object.
     */
    rolePermissionsData?: TRolePermission;
  }
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

      // Inherit type-level permissions if field has no directive
      const typePermissions = typePermissionMapping.get(typeName) ?? [];
      const effectivePermissions =
        fieldPermissions.length > 0 ? fieldPermissions : typePermissions;

      // If no permissions are set at all, deny access by default
      if (effectivePermissions.length === 0) {
        fieldConfig.resolve = () => {
          throw new Error(`Access denied for ${typeName}.${fieldName}`);
        };
        return fieldConfig;
      }

      const originalResolver = fieldConfig.resolve ?? defaultFieldResolver;

      fieldConfig.resolve = async (source, args, context, info) => {
        const user = context.user;
        const dynamicRoleAndPermissionData = context.roleAndPermission;

        if (
          !isAuthorized({
            fieldPermissions: effectivePermissions, // Use inherited permissions
            typePermissions: [], // Already included in effectivePermissions
            user,
            ROLE_PERMISSIONS:
              dynamicRoleAndPermissionData ?? rolePermissionsData,
          })
        ) {
          throw new Error(`Unauthorized access to ${typeName}.${fieldName}`);
        }

        return originalResolver(source, args, context, info);
      };

      return fieldConfig;
    },
  });

  return authorizedSchema;
}
