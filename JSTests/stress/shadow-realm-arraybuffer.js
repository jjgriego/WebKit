//@ requireOptions("--useShadowRealm=1", "--allowSharedArrayBuffersCrossRealm=1")

function shouldBe(actual, expected) {
    if (actual !== expected)
        throw new Error(`expected ${expected} but got ${actual}`);
}

function shouldNotBe(actual, expected) {
    if (actual === expected)
        throw new Error(`expected ${expected} to be distinct from ${actual}`);
}

function shouldThrow(func, errorType, assertionFn) {
    let error;
    try {
        func();
    } catch (e) {
        error = e;
    }

    if (!(error instanceof errorType))
        throw new Error(`Expected ${errorType.name} but got ${error.name}`);

    assertionFn(error);
}

{
    let realm = new ShadowRealm();
    let sab = new SharedArrayBuffer(1024);
    let arr = new Uint8Array(sab);
    arr[0] = 1;
    arr[1] = 42;
    arr[2] = 100;

    let result = realm.evaluate(`(sab) => {
      let arr = new Uint8Array(sab);
      let res = arr[0] + arr[1] + arr[2];
      arr[0] = 255;
      return res;
    }`)(sab);

    realm.evaluate(`(sab, shouldBe) => {
      shouldBe(Object.getPrototypeOf(sab) ===  SharedArrayBuffer.prototype, true)
    }`)(sab, shouldBe);

    shouldBe(result, 143);
    shouldBe(arr[0], 255);

    // the SAB that passes through the shadow realm and back should alias the
    // same memory but be a new object
    let sab2 = realm.evaluate(`(x) => x`)(sab);
    shouldNotBe(sab2, sab);
    shouldBe(Object.getPrototypeOf(sab2), SharedArrayBuffer.prototype);

    let arr2 = new Uint8Array(sab2);
    arr2[0] = 53;
    shouldBe(arr[0], 53);
}
