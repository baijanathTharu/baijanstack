export interface IFilter {
  /**
   * field (optional): The field on which the filtering will be performed.
   */
  field?: string;
  /**
   * operator (optional): The comparison operator used for filtering the field.
   */
  operator?: 'gte' | 'lte' | 'equals' | 'contains';
  /**
   * value (optional): The value against which the field will be compared using the specified operator.
   */
  value?: any;
  /**
   * logicalOperator (optional): Specifies the logical operator used to combine multiple filters. It can be either 'AND' or 'OR'.
   */
  logicalOperator?: 'AND' | 'OR';
  /**
   * filters (optional): An array of nested IFilter objects used to create complex filter conditions.
   */
  filters?: IFilter[];
}

export function buildFilter(filter: IFilter) {
  if (!filter) return {};

  const where: any = {};

  if (filter.field && filter.operator && filter.value) {
    const fieldParts = filter.field.split('.');
    let currentWhere = where;

    for (let i = 0; i < fieldParts.length - 1; i++) {
      if (!currentWhere[fieldParts[i]]) {
        currentWhere[fieldParts[i]] = {};
      }
      currentWhere = currentWhere[fieldParts[i]];
    }

    if (!currentWhere[fieldParts[fieldParts.length - 1]]) {
      currentWhere[fieldParts[fieldParts.length - 1]] = {};
    }

    if (filter.operator) {
      currentWhere[fieldParts[fieldParts.length - 1]][filter.operator] =
        filter.value;
    }
  }

  if (filter.filters) {
    if (filter.logicalOperator && filter.filters?.length > 0) {
      const nestedConditions = filter.filters.map(buildFilter);

      if (filter.logicalOperator === 'AND') {
        where.AND = nestedConditions;
      } else if (filter.logicalOperator === 'OR') {
        where.OR = nestedConditions;
      }
    }
  }

  return where;
}
