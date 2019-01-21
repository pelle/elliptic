import { EC } from '../src/elliptic'

describe('EC API', () => {
  it('should instantiate with secp256k1', () => {
    var ec = new EC()

    expect(ec).toBeDefined()
  })
})
