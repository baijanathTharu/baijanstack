# prisma-filter-generator

The motivation behind creating this library is to simplify the structure of filter that we have to send from frontend to backend implemented with Prisma ORM.

The buildFilter function is a utility function designed to generate a filter structure based on the provided filter object. This filter structure can be used to query and filter data from database using prisma.

## Usage

1. Install the dependency.

```bash
npm install @baijanstack/prisma-filter-generator
```

- Import the dependencies in your project

```ts
import { IFilter, buildFilter } from './build-filter';
```

- Your filter input should satisfy the given interface.

```ts
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
```

- Examples of filter input and their output.

### Simple Filter

#### Code

```ts
const filter: IFilter = {
  field: 'name',
  operator: 'equals',
  value: 'John',
};
```

#### Output

```ts
{
  name: {
    equals: 'John',
  },
}
```

### Single Nested Filter

#### Code

```ts
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
```

#### Output

```ts
{
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
}
```

### Complex Nested Filter

#### Code

```ts
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
```

#### Output

```ts
{
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
}
```

### Some, none and every filter can be implemented using example below:

#### Code

```ts
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
```

#### Output

```ts
{
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
}
```
