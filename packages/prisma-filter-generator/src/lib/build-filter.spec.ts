import { IFilter, buildFilter } from './build-filter';

describe('buildFilter', () => {
  test('should return an empty object for null input', () => {
    const filter = null as unknown as IFilter;
    expect(buildFilter(filter)).toEqual({});
  });

  test('should build a basic single filter', () => {
    const filter: IFilter = {
      field: 'name',
      operator: 'equals',
      value: 'John',
    };
    expect(buildFilter(filter)).toEqual({
      name: {
        equals: 'John',
      },
    });
  });

  test('should build a single nested filter with AND', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [
        {
          field: 'age',
          operator: 'gte',
          value: 30,
        },
        {
          field: 'createdAt',
          operator: 'lte',
          value: '2022-02-01',
        },
      ],
    };
    expect(buildFilter(filter)).toEqual({
      AND: [
        {
          age: {
            gte: 30,
          },
        },
        {
          createdAt: {
            lte: '2022-02-01',
          },
        },
      ],
    });
  });

  test('should build a single nested filter with OR', () => {
    const filter: IFilter = {
      logicalOperator: 'OR',
      filters: [
        {
          field: 'isPublished',
          operator: 'equals',
          value: true,
        },
        {
          field: 'isDraft',
          operator: 'equals',
          value: true,
        },
      ],
    };
    expect(buildFilter(filter)).toEqual({
      OR: [
        {
          isPublished: {
            equals: true,
          },
        },
        {
          isDraft: {
            equals: true,
          },
        },
      ],
    });
  });

  test('should build complex nested filters', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [
        {
          field: 'author.name',
          operator: 'contains',
          value: 'John',
        },
        {
          logicalOperator: 'OR',
          filters: [
            {
              field: 'author.age',
              operator: 'gte',
              value: 30,
            },
            {
              logicalOperator: 'AND',
              filters: [
                {
                  field: 'author.createdAt',
                  operator: 'gte',
                  value: '2022-01-01',
                },
                {
                  field: 'author.createdAt',
                  operator: 'lte',
                  value: '2022-02-01',
                },
              ],
            },
          ],
        },
      ],
    };
    expect(buildFilter(filter)).toEqual({
      AND: [
        {
          author: {
            name: { contains: 'John' },
          },
        },
        {
          OR: [
            {
              author: {
                age: {
                  gte: 30,
                },
              },
            },
            {
              AND: [
                {
                  author: {
                    createdAt: {
                      gte: '2022-01-01',
                    },
                  },
                },
                {
                  author: {
                    createdAt: {
                      lte: '2022-02-01',
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
  });

  test('should handle invalid filter (Missing Field)', () => {
    const filter: IFilter = {
      operator: 'equals',
      value: 'Test',
    };
    expect(buildFilter(filter)).toEqual({});
  });

  test('should handle nested filters with empty inner filters array', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [],
    };
    expect(buildFilter(filter)).toEqual({});
  });

  test('should handle nested filters with one empty inner filter', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [{}],
    };
    expect(buildFilter(filter)).toEqual({
      AND: [{}],
    });
  });
});

/**
 * test cases for every, none and some
 */
describe('User Posts Filtering', () => {
  test('should filter users who have every post published', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [
        {
          field: 'posts.every.isPublished',
          operator: 'equals',
          value: true,
        },
      ],
    };
    const generatedFilter = buildFilter(filter);

    expect(generatedFilter).toEqual({
      AND: [
        {
          posts: {
            every: {
              isPublished: {
                equals: true,
              },
            },
          },
        },
      ],
    });
  });

  test('should filter users who have none of their posts published', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [
        {
          field: 'posts.none.isPublished',
          operator: 'equals',
          value: true,
        },
      ],
    };
    const generatedFilter = buildFilter(filter);

    expect(generatedFilter).toEqual({
      AND: [
        {
          posts: {
            none: {
              isPublished: {
                equals: true,
              },
            },
          },
        },
      ],
    });
  });

  test('should filter users who have at least one post published', () => {
    const filter: IFilter = {
      logicalOperator: 'AND',
      filters: [
        { field: 'posts.some.isPublished', operator: 'equals', value: true },
      ],
    };
    const generatedFilter = buildFilter(filter);

    expect(generatedFilter).toEqual({
      AND: [
        {
          posts: {
            some: {
              isPublished: {
                equals: true,
              },
            },
          },
        },
      ],
    });
  });
});
