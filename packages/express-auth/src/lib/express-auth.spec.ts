import { expressAuth } from './express-auth';

describe('expressAuth', () => {
  it('should work', () => {
    expect(expressAuth()).toEqual('express-auth');
  });
});
