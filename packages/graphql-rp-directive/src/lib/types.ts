export type TRolePermission = Record<
  string,
  {
    permissions: Array<string>;
  }
>;

export type TIsAuthorizedArgs = {
  fieldPermissions: Array<string>;
  typePermissions: Array<string>;
  user: {
    roles: Array<string>;
  };
  ROLE_PERMISSIONS: TRolePermission;
};
