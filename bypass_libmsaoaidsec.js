function stacktrace() {
  Java.perform(function () {
    let AndroidLog = Java.use("android.util.Log");
    let ExceptionClass = Java.use("java.lang.Exception");
    console.warn(AndroidLog.getStackTraceString(ExceptionClass.$new()));
  });
}


function hook_dlopen() {
  var soName = "libmsaoaidsec.so";
  Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function (args) {
      var pathptr = args[0];
      if (pathptr) {
        var path = ptr(pathptr).readCString();
        console.log("Loading: " + path);
        if (path.indexOf(soName) >= 0) {
          console.log("Already loading: " + soName);
          hook_system_property_get();
        }
      }
    },
  });
}

function hook_system_property_get() {
  var system_property_get_addr = Module.findExportByName(
    null,
    "__system_property_get"
  );
  if (!system_property_get_addr) {
    console.log("__system_property_get not found");
    return;
  }

  Interceptor.attach(system_property_get_addr, {
    onEnter: function (args) {
      var nameptr = args[0];
      if (nameptr) {
        var name = ptr(nameptr).readCString();
        if (name.indexOf("ro.build.version.sdk") >= 0) {
          console.log("Found ro.build.version.sdk, need to patch");
          hook_pthread_create();
          //  bypass()
        }
      }
    },
  });
}

function hook_pthread_create() {
  var pthread_create = Module.findExportByName("libc.so", "pthread_create");
  var libmsaoaidsec = Process.findModuleByName("libmsaoaidsec.so");

  if (!libmsaoaidsec) {
    console.log("libmsaoaidsec.so not found");
    return;
  }

  console.log("libmsaoaidsec.so base: " + libmsaoaidsec.base);

  if (!pthread_create) {
    console.log("pthread_create not found");
    return;
  }

  Interceptor.attach(pthread_create, {
    onEnter: function (args) {
      var rounting_ptr = args[2];
      if (
        rounting_ptr.compare(libmsaoaidsec.base) < 0 ||
        rounting_ptr.compare(libmsaoaidsec.base.add(libmsaoaidsec.size)) >= 0
      ) {
        console.log("pthread_create other thread: " + rounting_ptr);
      } else {
        //  stacktrace();
        console.log(
          "pthread_create libmsaoaidsec.so thread: " +
            rounting_ptr +
            " offset: " +
            rounting_ptr.sub(libmsaoaidsec.base)
        );
        // console.log(Instruction.parse(ptr(rounting_ptr.sub(8))).toString());
        // console.log(Instruction.parse(ptr(rounting_ptr.sub(4))).toString());
        console.log(Instruction.parse(ptr(rounting_ptr)).toString());
        // NOP(rounting_ptr);
        // console.log(Instruction.parse(ptr(rounting_ptr.sub(8))).toString());
        // console.log(Instruction.parse(ptr(rounting_ptr.sub(4))).toString());
        // console.log(Instruction.parse(ptr(rounting_ptr)).toString());
        //  bypass();
         Interceptor.replace(rounting_ptr,new NativeCallback(function(){
                   console.log("Interceptor.replace: " + rounting_ptr.sub(libmsaoaidsec.base))
                  },"void",[]))
        console.log(Instruction.parse(ptr(rounting_ptr)).toString());

      }
    },
    onLeave: function (retval) {},
  });
}

function NOP(addr) {
  console.log(JSON.stringify(Process.getRangeByAddress(ptr(addr))));
  Memory.patchCode(ptr(addr), 4, (code) => {
    // const cw = new Arm64Writer(code, { pc: ptr(addr) }); arch:amr64
    const cw = new ArmWriter(code, {pc: ptr(addr)}); // arch arm32
    cw.putNop();
    cw.flush();
  });
  console.log("do NOP at:" + ptr(addr));
}

// dirty code
function bypass() {
  let module = Process.findModuleByName("libmsaoaidsec.so");
  NOP(module.base.add(0x1c544));
  NOP(module.base.add(0x1b8d4));
  NOP(module.base.add(0x26e5c));
}

setImmediate(hook_dlopen());
