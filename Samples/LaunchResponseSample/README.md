# Launch/response matrix sample

`LaunchResponseSample.exe` demonstrates the launch-and-respond packaging matrix. The
unpackaged requester and responder are ordinary command-line processes. The packaged
single-instance case uses `Windows.ApplicationModel.AppInstance`.

The resident instance prints `READY` with its PID, process instance discriminator, and
package family name. By default the discriminator is the documented process creation time.
Every activation prints `ACTIVATED kind=... uri=...`; a URI ending in `:stop`
ends the resident process. This makes the real target of a redirected protocol activation
visible without incorrectly treating the transient second process as the recipient.

## Unpackaged launch and response

The requester creates a per-request shared response record and completion event, then
starts the responder directly. The responder reopens the requester and accepts only if
both the PID and instance key still identify that same process. It writes its result and
its own identity to the record, signals completion, and exits. The requester waits for
that completion or responder exit for ten seconds by default, and accepts only a result
from the exact responder process it started.

```powershell
$exe = ".\x64\Debug\LaunchResponseSample.exe"
& $exe --unpackaged --role requester --response-timeout-seconds 10
```

The requester prints `RESPONSE ACCEPTED` on a verified result, `RESPONSE REFUSED` if the
result does not belong to the launched responder, and `RESPONSE TIMEOUT` if no result
arrives by the deadline. Use `--response-delay-seconds 2 --response-timeout-seconds 1`
to demonstrate the timeout. This path has no package registration or Windows App Runtime
bootstrap requirement.

## Build and package

Build `Samples.sln` for `Debug|x64`. `Build-Packages.ps1` creates two registration
layouts from the executable:

```powershell
.\Build-Packages.ps1
```

Register the unsigned layouts directly:

```powershell
Add-AppxPackage -Register .\AppxLayout.Requester\AppxManifest.xml
Add-AppxPackage -Register .\AppxLayout.Responder\AppxManifest.xml
```

The manifests register `targetedlaunch-request:` and `targetedlaunch-response:`, plus
`targetedlaunch-forresults:` on the Responder with `ReturnResults="always"` — that last one
is what makes the Responder a real for-results provider (see below). A full package
installation is required to test those protocol activations. Activate one scheme,
then activate it again with another URI. The first package instance remains resident and
prints the URI received through its `Activated` handler; the second prints `REDIRECTED`
and exits:

```powershell
Start-Process "targetedlaunch-response:first"
Start-Sleep -Seconds 1
Start-Process "targetedlaunch-response:second"
Start-Sleep -Seconds 1
Start-Process "targetedlaunch-response:stop"
```

The requester and responder packages deliberately have distinct package identities.
Activate packaged roles through their registered `targetedlaunch-request:` and `targetedlaunch-response:`
protocols. Do not launch the installed packaged executable directly. The `--unpackaged`
and `--role` switches are only for the unpackaged executable scenario.

## Matrix

| Requester | Responder/receiver | Invocation |
|---|---|---|
| unpackaged | unpackaged | Run the requester; it starts the responder and waits for its verified response |
| packaged | packaged | Launch `targetedlaunch-request:` and `targetedlaunch-response:` |
| unpackaged | packaged | Start the requester with `--unpackaged`; launch `targetedlaunch-response:` |
| packaged | unpackaged | Launch `targetedlaunch-request:`; start the responder with `--unpackaged` |
| packaged app, first invocation | packaged app, second invocation | Launch the same `matrix-*:` URI twice; the second activation redirects to the resident first instance |

The parent line reports the immediate OS parent and whether its sequence number is older
than the child. This is an ancestry plausibility check, not proof of semantic causality.
Packaged activation should not use parentage as the requester identity; use the explicit
request token, COM call context, or a registered target window instead.

## Launching for results, and discovering who can answer

`--screencapture <mode>` demonstrates the "who gets the response" problem against real,
installed providers rather than only the sample's own matrix.

The key API is capability discovery:

```cpp
Launcher::FindUriSchemeHandlersAsync(scheme, LaunchQuerySupportType::UriForResults)
```

It returns only the apps whose manifest declares `ReturnResults` for that scheme — so a
caller can find out *before launching* whether anything is able to answer, instead of
launching and hoping and then having to interpret an avoidable failure.

`ReturnResults` has three values, and they place a handler in different lists:

| `ReturnResults` | Appears under `Uri` | Appears under `UriForResults` |
|---|---|---|
| `none` (default) | yes | no |
| `optional` | yes | yes |
| `always` | **no** | yes |

So a handler that shows up under `UriForResults` but *not* under `Uri` is normal, not a
discovery bug — `always` means the app can only ever be started with a result contract in
place. `discover` mode prints both lists side by side to make this visible.

Two file-handoff directions both go through `SharedStorageAccessManager`, so neither side
ever exchanges a raw path (and a `ValueSet` payload is capped at 100 KB, which is why
tokens exist at all):

* **provider mints the file** — it calls `AddFile` and returns a single-use token the
  caller redeems with `RedeemTokenForFileAsync`. This is the `ms-screenclip` shape, and
  the shape this sample's own provider implements.
* **caller shares the file** — the caller calls `AddFile` on a file it created and passes
  the token as *input*; the provider writes into it. This is the camera picker's shape.

Docs: [Launch an app for results](https://learn.microsoft.com/en-us/windows/uwp/launch-resume/how-to-launch-an-app-for-results)
and [`LaunchUriForResultsAsync`](https://learn.microsoft.com/en-us/uwp/api/windows.system.launcher.launchuriforresultsasync).

### Providers this sample can talk to

| `--scheme` | Provider | Status |
|---|---|---|
| `targetedlaunch-forresults` | this sample's own `Responder` package | **Works end to end.** Register `AppxLayout.Responder` first. Discovery finds it, the launch is pinned to its package family name, the provider replies `code=200` with a `file-access-token`, and the caller redeems it. Deterministic and non-interactive. |
| `microsoft.windows.camera.picker` | inbox Windows Camera | **Works end to end**, interactively. Undocumented inbox contract; the caller shares a file and Camera writes the capture into it. Use `--media photo\|video`. |
| `ms-screenclip` | Screen Snipping / Snipping Tool | **No provider yet.** Neither handler declares `ReturnResults` on current builds, so discovery reports `RESPONSE NO-PROVIDER` and nothing is launched. The request code is kept and marked `TODO: verify once the updated screen clipping apps are available.` |

```powershell
# fully self-contained round trip against this sample's own provider
.\x64\Debug\LaunchResponseSample.exe --screencapture forresults --scheme targetedlaunch-forresults

# contrast the "can be launched" and "can answer" lists for any scheme
.\x64\Debug\LaunchResponseSample.exe --screencapture discover --scheme ms-screenclip

# a real inbox provider, caller-shares-the-file direction (interactive)
.\x64\Debug\LaunchResponseSample.exe --screencapture forresults --scheme microsoft.windows.camera.picker --media photo

# no provider can answer: reported without launching anything
.\x64\Debug\LaunchResponseSample.exe --screencapture forresults --scheme ms-screenclip

# no response contract at all, for comparison
.\x64\Debug\LaunchResponseSample.exe --screencapture legacy
```

### The redirect-uri fallback

`--screencapture redirect` is the general-purpose fallback for a target that has no
for-results support. It simulates the contract by hand: it registers a resident
`AppInstance`, embeds a correlation id and its own `targetedlaunch-screenclip-response:`
redirect URI in the request, and waits for a *second, independent* activation carrying the
answer. Requires the packaged `Requester` identity and a manual snip, and is marked
`TODO: verify once the updated screen clipping apps are available` — no shipping build
honors the contract yet.

That second activation is exactly the risk this repo is about: nothing except the
correlation id proves the response answers *this* request rather than a stale or injected
one, so the caller must check it. The for-results path gets that property for free, because
the reply arrives on the very operation the caller is awaiting — the sample still asserts
the echoed correlation id there, to show the difference costs nothing.

**Ranking, most to least safe:** `forresults` whenever discovery says the target supports
it — the OS correlates request and response, so there is no redirect-uri registration to
get wrong and no second activation to race. `redirect` only for targets that support
nothing better. Plain fire-and-forget (`legacy`) has no response contract at all and should
not be used where the response matters.

### Diagnostics

A packaged, broker-activated process may have no visible console, and the broker does not
propagate the launching shell's environment block — so `TARGETEDLAUNCH_LOG_PATH` may never
arrive. The sample therefore falls through a list of candidate log paths until one actually
opens (`%LOCALAPPDATA%`, then `%TEMP%`, then beside the executable) and prints the chosen
path as its first `START` line. The install directory of a *packaged* app is read-only, so
the beside-the-executable location works only for unpackaged runs and must never be the
only candidate.

> **Packaging gotcha:** both manifests set `ProcessorArchitecture="x64"` on `<Identity>`.
> Without it the package registers as `neutral`, and on an ARM64 machine Windows resolves
> the **arm64** `WindowsAppRuntime` framework for the **x64** binary. The activated process
> then dies at startup with `0x800700C1` (`ERROR_BAD_EXE_FORMAT`) before it can report
> anything — the launch still reports success and the caller just sees an empty response.
