import { sayHello } from './index';

describe('simple test setup', () => {
  it('should say hello', () => {
    expect(sayHello()).toBe('hello');
  });
});
