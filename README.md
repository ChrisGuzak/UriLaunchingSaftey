# Uri Launching Safety - Local Only Uri Schemes

This project demonstrates how applications (WebBrowsers) that launch uris from untrusted sources 
can mitigate the danger created by enabling uris to be identified as "local only" for launching.

This is based on a naming system where `local+` is use as a prefix for schemes to identify them as
local only. It also allows the schemes registration to specify this.

## The Security Threat

Web pages and other untrusted programs can launch uris that are not safe to launch. For example, a web page
can invoke `ms-setting:` or `shell:` which can launch applications that are intended to be run from the web.

Uri scheme creators have to consider this threat when they design their scheme and its handling.
Untrusted invokes are possible. In some cases, this eliminates the possibility of using uri launching in designs.

This threat is currently mitigated by this dialog.
![Uri Launch Warning U I](UriLaunchWarningUI.png).

Web Browsers should display the name of the program that is going
to be launched to help users make decisions like based on the Windows APIs that provide access to this when
launching with `ShellExecuteExW()` using `IHandlerActivationHost`/`IHandlerInfo`.

## Detecting Local only

### `local+` Prefix match

Schemes with the prefix are considered local only. Here is the template for the registry configuration
for such a scheme.
```
HKCR\local+<scheme suffix>
    "URL Protocol"
```

### Registry Configuration

For existing schemes that don't have a `local+` prefix that want this behavior, they opt in via registration
using the `LocalOnly` registry value.

```
HKCR\<scheme>
    "URL Protocol"
    LocalOnly
```

## Design Questions

- Is it useful to allow schemes to specify a minimum zone too? 
That would enable Web Pages on the Intranet to launch some schemes.
- What about `EditFlags` `FTA_SafeForElevation`, what role should it have?
- Should specific handlers register their safety rather than the uri scheme itself? 
- That is, for the same scheme, handled by different apps could one be local only where the other is not?
- Is a a hard coded list of known local only schemes (like the public suffix) useful?
- Should this system provide a user override, so a user could opt-out a scheme (making it less safe?)

## TODOs for the os.
- Update all of the OS provided schemes that don't specify EditFlags FTA_SafeForElevation to add LocalOnly.

