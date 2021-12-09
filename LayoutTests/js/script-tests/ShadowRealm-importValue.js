description("Test to ensure correct behaviour of ShadowRealm.prototype.importValue");

function assert_closed_opener(w, closed, opener) {
  assert_equals(w.closed, closed);
  assert_equals(w.opener, opener);
}

function wrappedLog(prefix) {
    return function (msg) {
        debug(prefix + ": " + msg);
    };
}

promise_test(async t => {
  // const openee = window.open("", "greatname");
  const outerShadowRealm = new ShadowRealm();
  const checkFn = await outerShadowRealm.importValue("./example-module.js", "check");
  assert_equals(checkFn(wrappedLog("shadowRealm")), true);

  const ourModule = await import("./example-module.js");
  assert_equals(ourModule.value, true, "bloop");
  ourModule.setValue(42);
  assert_equals(ourModule.value, 42);

  const importedVal = await outerShadowRealm.importValue("./example-module.js", "value");
  assert_equals(importedVal, true);
  const setValueImported = await outerShadowRealm.importValue("./example-module.js", "setValue");
  setValueImported(100);
  const importedVal2 = await outerShadowRealm.importValue("./example-module.js", "value");
  assert_equals(importedVal2, 100);
  assert_equals(ourModule.value, 42);
}, "can import module in a shadow realm");

promise_test(async t => {
    // const openee = window.open("", "greatname");
    const outerShadowRealm = new ShadowRealm();
    const checkFn = await outerShadowRealm.importValue("./example-module.js", "check_nested");
    assert_equals(checkFn(wrappedLog("shadowRealm")), true);
}, "can nest realms");
