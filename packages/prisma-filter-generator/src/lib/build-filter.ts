export function buildFilter(filter: any) {
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

  if (filter.logicalOperator && filter.filters?.length > 0) {
    const nestedConditions = filter.filters.map(buildFilter);

    if (filter.logicalOperator === 'AND') {
      where.AND = nestedConditions;
    } else if (filter.logicalOperator === 'OR') {
      where.OR = nestedConditions;
    }
  }

  return where;
}

// const filter1 = {
//   logicalOperator: 'OR',
//   filters: [
//     {
//       field: 'author.name',
//       operator: 'contains',
//       value: 'John',
//     },
//     {
//       logicalOperator: 'OR',
//       filters: [
//         {
//           field: 'author.age',
//           operator: 'gte',
//           value: 30,
//         },
//         {
//           logicalOperator: 'AND',
//           filters: [
//             {
//               field: 'author.createdAt',
//               operator: 'gte',
//               value: '2022-01-01',
//             },
//             {
//               field: 'author.createdAt',
//               operator: 'lte',
//               value: '2022-02-01',
//             },
//           ],
//         },
//       ],
//     },
//   ],
// };

/**
// find users from country Nepal with at least one published post

 - a post can have multiple authors.
 - an author can write many posts.

 prisma.user.findMany({
  where: {
    country: {
      name: {
        equals: "Nepal"
      }
    },
    posts: {
      some: {
        isPublished: {
          equals: true
        }
      }
    }
  }
 })
 */
const filter1 = {
  logicalOperator: 'AND',
  filters: [
    {
      field: 'country.id.not',
      operator: 'equals',
      value: 'Nepal',
    },
    {
      field: 'posts.some.isPublished',
      operator: 'equals',
      value: true,
    },
  ],
};

const generatedFilter = buildFilter(filter1);
console.log('generatedFilter', JSON.stringify(generatedFilter, null, 2));
