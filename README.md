# unrasp_guard

Anti Tamper & Anti Frida Bypass For Our Lovely LolGuard

Why I Am Doing This - To Help Reversing Community .
Even Malware Owners Using Such RASP on malwares to protect itself but RASP companies forcing down the
guys who want to analyse such malware packed with their RASP . 
for you companies - Why you selling your products to such guys without verification - oh why should you care- you guys just need thousands of $ for your shitty protection 

Before Start doing any reversing, lets see what things are loaded from linker for our target app

```sh
var do_dlopen = null;
var call_ctor = null;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    var library = this.context['x0'].readUtf8String();
    console.log(library);
})
```
and we got output as

```sh
/data/app/~~randomshit==/com.our.target.apk-randomshit==/oat/arm64/base.odex
/data/app/~~94aZRAHXOJ9Z6tyWBj3tfA==/com.our.target.apk-randomshit==/lib/arm64/libdgrt.so
/data/local/tmp/frida-c8xyz......./frida-agent-64.so
..... 
```
output truncated because list is long

so first out classes.dex is loaded in form on .odex and then lolguard's library. 

lets think in how many way it can check for static Anti Tampering
1. By opening base.apk and extract meta-inf and compare it . hash or crc whatever 
2. by invoking some java api and calculate signature from those and compare it
many other way there but these are 2 common way to check .
path to base.apk can be retrieved from various way and can be checked normally or with syscall . our selected apk not doing any syscall
operation so we sticking with java side hooks

lets think how can be base.apk is faked so apk think it is not tampered.

1. we can copy original base.apk into asset and extract it at first startup to /data/data/package directory and then we can fake it
2. or copy base.apk into lib directory of apk so apk extract it at install time for us

if we go for 1st method then we need to add smali codes which we don't do as we Tampering apk , not adding additional codes
and if we go for 2nd method then we got opportunity to hook code from very early without needing to add anything.

so what we will do -

1. redirect base.apk path to our faked path which we decide later.
2. some of signature method to provide fake signature 

first we need to get original signature of apk so we can put in our script to fake. 

lets check 
https://stackoverflow.com/questions/5578871/how-to-get-apk-signing-signature
to get how can we get signatures. if we convert similer java code javascript. it will be

```sh
Java.perform(function() {
    try {
        var SignArray = [];
        var Signatures;
        var BuildVersion = Java.use("android.os.Build$VERSION");
        var PackageManager = Java.use("android.content.pm.PackageManager");
        var Context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        Signatures = 28 <= BuildVersion.SDK_INT.value ? Context.getPackageManager().getPackageInfo(Context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES.value).signingInfo.value.getApkContentsSigners() : Context.getPackageManager().getPackageInfo(Context.getPackageName(), PackageManager.GET_SIGNATURES.value).signatures.value;
        for (var iterate = 0; iterate < Signatures.length; iterate += 1) {
            SignArray.push(Signatures[iterate].toCharsString())
        }
        console.warn("Original Signature : ", SignArray);
    } catch (e) {
        console.error(e);
    }
})
```
and we get our signature as

308202cf308201....... truncated to not reveal about app or developer

now we have to think how app might check for its own signature. 

from 
https://gist.github.com/scottyab/b849701972d57cf9562e

```sh
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;

public class TamperCheck {


private static final String APP_SIGNATURE = "1038C0E34658923C4192E61B16846";
	public boolean validateAppSignature(Context context) throws NameNotFoundException {

		PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
				getPackageName(), PackageManager.GET_SIGNATURES);
		for (Signature signature : packageInfo.signatures) {
			String sha1 = getSHA1(signature.toByteArray());
			return APP_SIGNATURE.equals(sha1);
		}

		return false;
	}
  
  public static String getSHA1(byte[] sig) {
  		MessageDigest digest = MessageDigest.getInstance("SHA1");
			digest.update(sig);
			byte[] hashtext = digest.digest();
			return bytesToHex(hashtext);
	}
  
  public static String bytesToHex(byte[] bytes) {
  	final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for (int j = 0; j < bytes.length; j++) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}
```

we see that it making use of these classes -

```sh
android.content.Context;
android.content.pm.PackageInfo;
android.content.pm.PackageManager;
android.content.pm.Signature;
```

so we can get a rough idea what we need to hook. but first we need to decide when should we hook
as we first need to get path of base.apk , this is random on every time apk is installed or reinstalled like

```sh
/data/app/com.package~~97aZR....==/base.apk
/data/app/~~14aOR...../Package~~randomshit==/base.apk
```

so we need to calculate correct path first . 

as we seen from first linker hook that it loaded base.odex at very first , we can use that path to calculate new path

if this is odex loader path
/data/app/~~94aZRAHXOJ9Z6tyWBj3tfA==/com.hatunnel.plus-bX8pBJxMKAxXi3GZjy1Zbw==/oat/arm64/base.odex
then we can make our new path by removing "oat/arm64/base.odex" from it and adding base.apk. 

now . lets start doing work 

1. make a copy of original apk , lets say we given it name as copy.apk
2. in lib folder of original.apk - push copy.apk 

like before
original apk have

```sh
/lib/arm64-v8a/libdgrt.so
```
we make it

```sh
/lib/arm64-v8a/libdgrt.so
/lib/arm64-v8a/copy.apk
```

but wait android doesn't count .apk as valid extension to extract at runtime from lib folder
so we renamimg copy.apk to libbaseapk.so , so android extract it easily.
and we got final fix as 

```sh
/lib/arm64-v8a/libdgrt.so
/lib/arm64-v8a/libbaseapk.so
```

Note - Apk might refuse to install after adding new library if its AndroidManifest.xml have a specific tag set as
```sh
android:extractNativeLibs="false"
```
so it may need to change to true
```sh
android:extractNativeLibs="true"
```

lets make script to get our new path

```sh
var do_dlopen = null;
var call_ctor = null;
var packagename = "com.our.target.apk"
var Check;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    var library = this.context['x0'].readUtf8String();    
    if (library != null) {
        if (library.indexOf(packagename) >= 0 && library.indexOf("base.odex") >= 0) {
            console.log("[*] Odex Loading : " + library);
            Check = library.replace("oat/arm64/base.odex", "lib/arm64/libbaseapk.so");            
          }
      }
})
```

what we did -
we got odex path and with a little replacement of path we adjusted it to our libbaseapk.so
so we don't need to care about random installation path anymore.
now our variable "Check" have path to faked original base.apk and we can start redirecting app to it
if it checking for it

lets start Hook Java api for signature checks 

1. android.content.Context

context class is widely used and every apk use it somewhere for proper working but whole class
is not useful for us . we need to filter few method of context class which may be used in anti tamper checks.

searching on 
https://developer.android.com/reference/android/content/Context
some get* give use 2 method
```sh
getPackageCodePath()
getPackageResourcePath()
```
both return a path to base.apk so they should be hooked.

you guys might go and do like

```sh
var Context = Java.use('android.content.Context');
```

but wait it not gonna work . there exist a different class which implements context 
and that it 

```sh
android.app.ContextImpl
var Context = Java.use('android.app.ContextImpl');
```

```sh
var Context = Java.use('android.app.ContextImpl');
Context.getPackageCodePath.overload().implementation = function() {
    return what; // we need to write our faked apk path but how
}
```

from above our variable Check location , we can call a function which have Check as argument.
like this

```sh
var do_dlopen = null;
var call_ctor = null;
var packagename = "com.our.target.apk"
var Check;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    var library = this.context['x0'].readUtf8String();    
    if (library != null) {
        if (library.indexOf(packagename) >= 0 && library.indexOf("base.odex") >= 0) {
            console.log("[*] Odex Loading : " + library);
            Check = library.replace("oat/arm64/base.odex", "lib/arm64/libbaseapk.so");  
            Hook(Check);          
          }
      }
})

function Hook(input) {
 // our java hook here , as odex is loaded already , at this moment Java.available won't return null 

}
```
inside Hook function we need to choose between
Java.perform or Java.performNow but we prefer Java.performNow for early hook purpose.


```sh
var do_dlopen = null;
var call_ctor = null;
var packagename = "com.our.target.apk"
var Check;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    var library = this.context['x0'].readUtf8String();    
    if (library != null) {
        if (library.indexOf(packagename) >= 0 && library.indexOf("base.odex") >= 0) {
            console.log("[*] Odex Loading : " + library);
            Check = library.replace("oat/arm64/base.odex", "lib/arm64/libbaseapk.so");  
            Hook(Check);          
          }
      }
})

function Hook(Input) {

 Java.performNow(function() {
       var Context = Java.use('android.app.ContextImpl');
       Context.getPackageCodePath.overload().implementation = function() {
                return Input;
       }
       Context.getPackageResourcePath.overload().implementation = function() {
                return Input;
       }      
}
```

context class's work is over . lets goto 2nd class

2. android.content.pm.Signature

looking on https://developer.android.com/reference/android/content/pm/Signature
we get few public methods 
1. toByteArray
2. toChars . 2 method with different overload
3. toCharsString

lets hook each of them .

toByteArray expect retval as byte array . so quick search on google give us
https://stackoverflow.com/questions/6226189/how-to-convert-a-string-to-bytearray

and we form functions as

```sh
function TBA() {
    var output = Java.array('byte', HTB(OriginalSign));
    return output;
}
function HTB(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}
```

what is OriginalSign here ? its that long signature string starting with 3082.... which we got early.

```sh
var OriginalSign = "3082.......";
var ACPSign = Java.use("android.content.pm.Signature");
ACPSign["toByteArray"].overload().implementation = function() {
    console.log("android.content.pm.Signature;->toByteArray called");
    var Fix = TBA();
    return Fix;
};
```
lets hook rest method of android.content.pm.Signature class
toChars - 2 method with different overload

it expect retval in character array , as our signature is already in string form , its gonna easy.

```sh
function TCA() {
    var ArraySignChar = Array.from(OriginalSign);
    return ArraySignChar;
}
ACPSign["toChars"].overload().implementation = function() {
    console.log("android.content.pm.Signature;->toChars called");   
    var Fix = TCA();
    return Fix;  
}
ACPSign["toChars"].overload("[C", "[I").implementation = function(ch, into) {
    console.log("android.content.pm.Signature;->toChars 2nd called");
    var Fix = TCA();
    return Fix;
}
```

lets do again for 3rd method toCharString
it expect retval as string and our input is already in string form so we can directly return it.

```sh
ACPSign["toCharsString"].overload().implementation = function() {
    console.log("android.content.pm.Signature;->toCharsString called");   
    return OriginalSign;
}
```

this class hook is over . lets go for another class
PackageManager
```sh
android.content.pm.PackageManager
```
so we try to hook it but again wait , this class won't trigger because this is base class and some other class implements it

```sh
android.app.ApplicationPackageManager
```
there are lots of method of PackageManager class but we hooking only few because those are sufficient, adding more and more hook
doesn't guarantees of proper working . they often leads to crash.

let hook getApplicationInfo of PackageManager class . 
But think what we need to hook in that - from past experience we know that
2 field can grab base.apk location which is sourcDir and publicSourceDir which is available in getApplicationInfo.

now hooking them

```sh
var PackageManager = Java.use("android.app.ApplicationPackageManager");
PackageManager.getApplicationInfo.implementation = function(pn, flags) {
    var ret = this.getApplicationInfo(pn, flags);
    if (pn === packagename) {
        ret.sourceDir = Input;
        ret.publicSourceDir  = Input;
        console.log("android.app.ApplicationPackageManager;->(sourceDir) Hooked");
    }
    return ret;
}
```

but when we run it , we see that it not work . lets search as usually and found that
https://github.com/frida/frida/issues/510 issue . From that we can see that it need .value to work properly. 

a quick modification in script

```sh
var PackageManager = Java.use("android.app.ApplicationPackageManager");
PackageManager.getApplicationInfo.implementation = function(pn, flags) {
    var ret = this.getApplicationInfo(pn, flags);
    if (pn === packagename) {
        ret.sourceDir.value = Input;
        ret.publicSourceDir.value  = Input;
        console.log("android.app.ApplicationPackageManager;->(sourceDir) Hooked");
    }
    return ret;
}
```
doing same for context class

```sh
Context.getApplicationInfo.overload().implementation = function() {
    var ret = this.getApplicationInfo();
    console.log("android.app.ContextImpl;->getApplicationInfo called");
    ret.sourceDir.value = Input;
    ret.publicSourceDir.value = Input;
    return ret;
}
```

we repeat same sourceDir hook on a low level package manager class
android.content.pm.IPackageManager$Stub$Proxy

```sh
var Stub = Java.use("android.content.pm.IPackageManager$Stub$Proxy");
Stub.getApplicationInfo.overload("java.lang.String", "int", "int").implementation = function(pkgname, flag, flag2) {
    var ret = this.getApplicationInfo.call(this, pkgname, flag, flag2);
    if (pkgname == packagename) {
        console.log("android.content.pm.IPackageManager$Stub$Proxy;->getApplicationInfo(sourceDir) called");
        ret.sourceDir.value = Input;
        ret.publicSourceDir.value = Input;
    }
    return ret;
}
```

From same issue from https://github.com/frida/frida/issues/510
we can make hook for android.content.pm.ApplicationInfo
but that depends upon android.app.ActivityThread , we can't put that into Java.performNow else it give 
error such as - context not found


```sh
if (Java.available) {
    Java.perform(function() {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const PackageInfo = Java.use('android.content.pm.PackageInfo');
        const ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        var context = ActivityThread.currentApplication().getApplicationContext();
        var packageManager = context.getPackageManager();
        var appsinfo = packageManager.getInstalledPackages(0);
        for (var i = 0; i < appsinfo.size(); i++) {
            var app = Java.cast(appsinfo.get(i), PackageInfo);
            if (app.packageName.value == packagename) {
                app.applicationInfo.value.sourceDir.value = Check;
                console.log("sourceDir Hooked : ", app.applicationInfo.value.sourceDir.value);
            }
        }
    });
}
```


These are enough for Bypassing Certificate Check /Anti-Tamper of LolGuard

lets combine all parts of script.

```sh
var do_dlopen = null;
var call_ctor = null;
var packagename = "com.our.target.apk"
var Check;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    var library = this.context['x0'].readUtf8String();
    console.log(library);
    if (library != null) {
        if (library.indexOf(packagename) >= 0 && library.indexOf("base.odex") >= 0) {
            console.log("[*] Odex Loading : " + library);
            Check = library.replace("oat/arm64/base.odex", "lib/arm64/libbaseapk.so");
            Hook(Check)
        }
    }
})

function JavaHook(Input) {
    var OriginalSign = "3082........";
    Java.performNow(function() {
        try {
            var Context = Java.use('android.app.ContextImpl');
            Context.getPackageCodePath.overload().implementation = function() {
                return Input;
            }
            Context.getPackageResourcePath.overload().implementation = function() {
                return Input;
            }
            Context.getApplicationInfo.overload().implementation = function() {
                var ret = this.getApplicationInfo();
                console.log("android.app.ContextImpl;->getApplicationInfo called");
                ret.sourceDir.value = Input;
                ret.publicSourceDir.value = Input;
                return ret;
            }

            function TBA() {
                var output = Java.array('byte', HTB(OriginalSign));
                return output;
            }

            function TCA() {
                var ArraySignChar = Array.from(OriginalSign);
                return ArraySignChar;
            }

            function HTB(hex) {
                for (var bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
                return bytes;
            }
            var Verf = Java.use("java.security.Signature");
            Verf.verify.overload("[B").implementation = function(by) {
                return true;
            }
            var Stub = Java.use("android.content.pm.IPackageManager$Stub$Proxy");
            Stub.getApplicationInfo.overload("java.lang.String", "int", "int").implementation = function(pkgname, flag, flag2) {
                var ret = this.getApplicationInfo.call(this, pkgname, flag, flag2);
                if (pkgname == packagename) {
                    console.log("android.content.pm.IPackageManager$Stub$Proxy;->getApplicationInfo(sourceDir) called");
                    ret.sourceDir.value = Input;
                    ret.publicSourceDir.value = Input;
                }
                return ret;
            }
            var PackageManager = Java.use("android.app.ApplicationPackageManager");
            PackageManager.getApplicationInfo.implementation = function(pn, flags) {
                var ret = this.getApplicationInfo(pn, flags);
                if (pn === pkg) {
                    ret.sourceDir.value = Input;
                    ret.publicSourceDir.value = Input;
                    console.log("android.app.ApplicationPackageManager;->(sourceDir) Hooked");
                }
                return ret;
            }
            var ACPSign = Java.use("android.content.pm.Signature");
            ACPSign["toByteArray"].overload().implementation = function() {
                console.log("android.content.pm.Signature;->toByteArray called");
                var Fix = TBA();
                return Fix;
            };
            ACPSign["hashCode"].overload().implementation = function() {
                var ret = this["hashCode"]();
                console.log("Hash : ", ret);
                // return 189889969; This we need to grab from original apk first 
                return ret
            }
            ACPSign["toCharsString"].overload().implementation = function() {
                console.log("android.content.pm.Signature;->toCharsString called");
                return OriginalSign;
            }
            ACPSign["toChars"].overload().implementation = function() {
                console.log("android.content.pm.Signature;->toChars called");
                var Fix = TCA();
                return Fix;
            }
            ACPSign["toChars"].overload("[C", "[I").implementation = function(ch, into) {
                console.log("android.content.pm.Signature;->toChars 2nd called");
                var Fix = TCA();
                return Fix;
            }
        } catch (e) {
            console.error("Error Trigger : ", e);
        }
    })
}
if (Java.available) {
    Java.perform(function() {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const PackageInfo = Java.use('android.content.pm.PackageInfo');
        const ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        var context = ActivityThread.currentApplication().getApplicationContext();
        var packageManager = context.getPackageManager();
        var appsinfo = packageManager.getInstalledPackages(0);
        for (var i = 0; i < appsinfo.size(); i++) {
            var app = Java.cast(appsinfo.get(i), PackageInfo);
            if (app.packageName.value == pkg) {
                app.applicationInfo.value.sourceDir.value = Check;
                console.log("sourceDir Hooked : ", app.applicationInfo.value.sourceDir.value);
            }
        }
    });
}
```

Now if we installed our modified apk which have libbaseapk.so in its library folder and start with above frida script. it will start fine instead of crashing.
there are many more hooks available to share but for this i thought sufficient, may be they are for more better packer

Note - Anti-Frida part yet to be written because i can't found any LolGuard apk with frida detection yet . if you found such please share apk or hash on telegram.
http://t.me/apkunpacker

If You Like it. Consider Buying me a ☕

https://www.paypal.com/paypalme/apkunpacker

paypal.me/apkunpacker
