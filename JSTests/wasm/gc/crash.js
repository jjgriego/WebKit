load("wast.js");
 
function compile(wat) {
    print(wat);
  return WebAssemblyText.encode(wat);
}
 
compile(`
  (module
    (type (func))
  )
`);
compile(`
  (module
    (type (func))
    (type (func))
  )
`);
compile(`
  (module
    (type (func))
    (type (func))
    (type (func))
  )
`);
compile(`
  (module
    (type (func))
    (type (func))
    (type (func))
    (type (func))
  )
`);
compile(`
  (module
    (type (func))
    (type (func))
    (type (func))
    (type (func))
    (type (func))
  )
`);
compile(`
  (module
    (type (func))
    (type (func))
    (type (func))
    (type (func))
    (type (func))
    (type (func))
  )
`); 
