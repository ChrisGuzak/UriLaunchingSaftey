# TargetedLaunch - constraining *who* may receive a launch

Status: implementation in `Tests/TargetedLaunch.h`, demonstrated by `Tests/TargetedLaunchTests.cpp`.
This document is the design; the header is the authority on details.

## Problem

URI launching has two separable security questions, and this repo now answers both.

| | Question | Mitigation |
|---|---|---|
| Source | *Who is allowed to invoke this scheme?* | "local only" schemes (the pre-existing work; see `README.md`) |
| Destination | *Who is allowed to receive this launch?* | **TargetedLaunch** (this document) |

The destination question matters because a launch is normally addressed to a *scheme*, and
whoever the association system happens to resolve that scheme to gets the payload. If an
attacker can influence the association, or can register a colliding scheme, they receive
data intended for someone else. That is a hijack, and nothing about the launch API today
lets the caller say "I only meant this for that specific process/binary."

## Two motivating shapes

1. **Request/response** - simulating `LaunchUriForResults` out of two one-way launches.
   The response leg must land in *the exact process instance* that made the request.
2. **Anti-hijack for ordinary launches** - the caller trusts exactly one handler binary
   ("only ever launch `explorer.exe` this way"), by full path or by file name.

Both are expressed with one policy type, so a caller in case 2 can also pin to a live
process instance if that is what it holds.

## Core idea: a process id is not an identity

PIDs are recycled. A pid captured when a request is made can name a *completely different
process* by the time the response is launched - which is a hijack primitive, not a
theoretical concern.

`ProcessIdentity` is therefore `{processId, sequenceNumber, executablePath,
packageFamilyName}`, but these are not one identity - they are three, of different
strength:

- **processId + sequenceNumber** - together these name one live process *instance*. This
  is the strong case: the pair can never be satisfied by a recycled pid or an unrelated
  process. The **process sequence number** is a monotonically increasing, never-reused
  kernel value (`NtQueryInformationProcess`, `ProcessSequenceNumber` = 92, linked
  statically via `ntdll.lib`, which ships in the SDK).
- **executablePath** - names a *kind* of process (whatever binary happens to be running at
  that path), not an instance. This is the weak case: it says nothing about which running
  instance, and nothing about whether the file at that path is still the file it was when
  captured.
- **packageFamilyName** - names a *package*, not a process. This is strong within its own
  question (an unpackaged process cannot forge a PFN it doesn't own), but it is slightly
  less precise than pid+sequence: a package can contain multiple apps, and a PFN policy is
  satisfied by any instance of any app the package's manifest owns, not one specific
  process. That imprecision is not a hijack surface, though - one app in a package
  impersonating a sibling app in the *same* package is not the threat this policy defends
  against; the package boundary is what mattered.

A policy names exactly which of these three it trusts; they are not interchangeable.

Design rules that fall out of the pid+sequence case:

- Matching requires pid **and** sequence number to agree.
- If either side lacks a sequence number, the match **refuses** rather than guessing.
- Creation time was considered as a fallback and **deliberately removed**: it answers the
  same question less precisely, and having two discriminators invites the bug where the
  weaker one silently decides a security question.
- Sequence numbers also answer *ancestry*: a real ancestor always has a lower one, so a
  "parent" with a higher sequence number is a recycled pid, not the process that
  launched us.

## DirectLaunch as a target-resolution source

DirectLaunch is a separate shell launch path, not the `TargetedLaunch` API. It is the
"accelerated launch" feature documented at
[Accelerate warm launches of your Windows app](https://learn.microsoft.com/windows/apps/develop/launch/accelerated-launch).
The documented accelerated-launch contract is HWND-based:

- [`IExperimentalAPIInvoker`](https://learn.microsoft.com/windows/apps/develop/launch/accelerated-launch)
  is obtained from `CLSID_ExperimentalAPIInvoker`.
- The running handler calls `RegisterAcceleratedUriLaunch`.
- The `"targetWindow"` property identifies the HWND that receives the launch.
- The `"schemes"` property limits registration to URI schemes for which that process is
  the default handler.
- The URI is delivered to that HWND as a null-terminated UTF-16 string in `WM_COPYDATA`.

Therefore DirectLaunch does not return a PID from a general "resolve this URI" call. It
selects a previously registered handler window and sends the launch directly to the
already-running process. Given the registered HWND, TargetedLaunch derives the target
process the same way it would for any other HWND it is handed - `GetWindowThreadProcessId`
followed by `TryGetProcessIdentity`, the same conversion used for e.g. `GetShellWindow()`
when targeting Explorer. Nothing about DirectLaunch changes that conversion; it just
supplies the HWND.

The DirectLaunch policy path is consequently:

1. Obtain the DirectLaunch handler HWND from the registration or integration layer.
2. Convert the HWND to `ProcessIdentity` before sending or accepting the launch.
3. Require PID and sequence number when the policy names an exact process instance. If
   the integration layer cannot provide the registered HWND, an exact process-instance
   policy must return an unverifiable/refused result rather than guessing from an
   association path.

This gives TargetedLaunch two complementary paths:

- **DirectLaunch** targets an already-running process through its registered HWND.
- **ShellExecute site callbacks** expose the shell's resolved executable path, command
  line, process id, and (for COM handlers) the class object - which may itself be a
  proxy - enabling path, process, and COM-handler policies.

## Identity sources

A caller holds the peer in whatever representation it happens to have. All of these
converge on the same `ProcessIdentity`, so a policy never cares which was used:

| Representation | Entry point | Notes |
|---|---|---|
| process id | `TryGetProcessIdentity(DWORD)` | |
| process HANDLE | `TryGetProcessIdentity(HANDLE)` | works when the handle could not have been reopened by pid |
| HWND | `TryGetProcessIdentity(HWND)` | the peer is a UI process |
| incoming COM call | `TryGetComCallerIdentity<Mode, Source>()` | the calling process, from the call itself |
| caller of a specific object | `TryGetComCallerIdentityForObject(server)` | scoped to the call into *that* object |
| parent process | `TryGetParentProcessIdentity(pid, levels)` | walks the parentage chain; unpackaged only, see below |

The COM case is the important one: the identity comes from what the call layer recorded,
so a caller cannot spoof itself by passing a pid as an argument. There are two forms, and
they answer slightly different questions:

- **"for calling process"** (`TryGetComCallerIdentity`) reads the *ambient* context of the
  thread servicing the call. For a normal, non-partial-trust server, placing this at the
  COM entry point is correct. It can be approximated wrongly only when an unrelated
  in-process path can reach the same thread, in which case the ambient context describes
  whatever call the thread is nested inside.
- **"for caller of object"** (`TryGetComCallerIdentityForObject`) asks about the call into
  a specific object, so it cannot make that mistake.

`Source` selects the mechanism for the ambient form:

| `ComCallerSource` | API | Public? | Yields |
|---|---|---|---|
| `Rpc` (default) | `RpcServerInqCallAttributesW` + `RPC_QUERY_CLIENT_PID` | yes, `rpcasync.h` | a **pid**, reopened to capture identity |
| `CallContext` | `ICallingProcessInfo::OpenCallerProcessHandle` | no | a **handle**, no reopen step |

The default stays on public surface. The private mode is strictly more precise: a handle
cannot fall victim to pid recycling, whereas the pid must be reopened. That window is
very narrow - a synchronous caller is blocked awaiting the reply and so cannot have
exited - but it is not nothing if the caller is killed mid-call.

**"For caller of object" has no public equivalent.** RPC call attributes are ambient to
the thread; there is no per-object query. Documenting `ICallingProcessInfo` would let
every caller have the precise form without a private dependency. A test makes a real
cross-process call and asserts both routes name the same process.

Known limitation, captured as its own test: **in-process cross-apartment COM calls carry
no call context.** COM short-circuits them so they never reach LRPC. This must not be
mistaken for "no caller, therefore unconstrained".

**Parent process is effectively unpackaged-only.** The walk follows
`InheritedFromUniqueProcessId`, which holds for classic child-process creation. Packaged
activation goes through the platform activation broker, so the recorded parent names
infrastructure rather than the requester - and it returns a plausible-but-wrong identity
instead of failing, which is the dangerous shape.

## Packaging neutrality without paying for it

Identity capture also resolves `packageFamilyName`, and by default it does so
neutrally: it queries `GetPackageFamilyName` and accepts whatever the answer is,
without assuming anything is or isn't packaged. That neutrality is the right default
for code that genuinely doesn't know, but some callers *do* know - and for them the
neutral path is unnecessary work and an unstated assumption they'd rather have checked.

There are **two independent questions**, so there are two template parameters:

- **`CallerPackagingMode`** - is the process hosting *this code* packaged? A broker that
  only ever ships inside a package knows; a classic desktop tool knows it never is. A DLL
  that loads into both cannot know, and must detect at runtime.
- **`TargetPackagingMode`** - is the *peer* packaged? Independently answerable: an
  unpackaged tool may talk only to packaged apps, and vice versa.

Each takes three states, and they are deliberately **distinct enum types** so one cannot
be passed where the other was meant:

| Mode | Use when | Behavior |
|---|---|---|
| `RuntimeDetected` (default) | packaging-neutral code, or a DLL loaded into both | always queries, accepts either answer |
| `NeverPackaged` | known to never be packaged | query is retained only to fail-fast verify the assumption; nothing downstream is compiled in |
| `AlwaysPackaged` | known to always be packaged | fail-fasts if there is no package identity |

These are template arguments rather than runtime flags, so the unneeded branch compiles
out entirely instead of merely being skipped:

```cpp
// A packaged broker inspecting an unpackaged peer - both stated, both checked.
auto peer = TryGetProcessIdentity<TargetPackagingMode::NeverPackaged>(pid);
auto self = GetCurrentProcessIdentity<CallerPackagingMode::AlwaysPackaged>();
```

A wrong assumption fails fast rather than throwing: it means the calling code was
built for the wrong shape of process, which is a programming error to fix, not a runtime
condition to catch and handle. Code that must stay packaging neutral should never
specify a mode other than the default.

## Failure is ordinary, not exceptional

The expected failure cases are part of the design, not error handling bolted onto it:

- **Elevated or cross-session peers** - `OpenProcess` is denied for a process at a higher
  integrity level or in another session, which is *precisely* the scenario this mitigation
  exists for.
- **Races** - the peer exits between being named and being opened, so its pid now names
  nothing, or something else entirely.
- **Missing registration** - the scheme has no handler, or the handler has no package
  identity to match against.

None of these are exceptions. The Try-shaped call fails and returns the error information:
identity capture returns `std::optional<ProcessIdentity>`, where the empty case is
expected, and resolution returns a `TargetedLaunchDecision` carrying an explicit status:

```
Allowed | Refused | Unverifiable | NoHandler | NoLiveTarget | LaunchFailed
```

`Refused` (the mitigation firing) is deliberately distinct from `LaunchFailed` (the OS
itself could not start the resolved, policy-accepted target - a missing file, a
half-uninstalled handler), so "we stopped it" is never confused with "it broke" - and
both are distinct from `NoHandler`/`NoLiveTarget` (there was nothing to judge in the
first place). Every top-level entry point in this header - `ResolveTargetedUriLaunch`,
`LaunchUriWithTarget`, `LaunchUriWithSiteEnforcedTarget`, `ProbeUriLaunchTarget`,
`ProbeResolvedLaunchTarget` - reports outcomes through this same status (or an
`std::optional`/`std::nullopt` built from it), never by throwing. A missing or
misconfigured app registration, a cancelled site chain, or a failed `ShellExecuteExW`
call are exactly the conditions this library exists to defend a caller against, and a
library that throws on the very inputs it is meant to make safe would force every caller
to wrap it in a `try`/`catch` just to stay defended - worse than the unchecked-HRESULT
problem it replaces.

What *is* still worth throwing for is different in kind: a null or scheme-less uri is the
caller's own argument, not something the machine or an app's registration reported, so
`ResolveTargetedUriLaunch` (and transitively `LaunchUriWithTarget`) throws
`E_INVALIDARG` via `wil::ResultException` for it - admitting a caller bug into the status
set above would let a programming error read as a security or environmental outcome.
The only other thing allowed to propagate uncaught is a catastrophic failure such as
`std::bad_alloc` - nothing in this header catches or converts those, by design. A
violated compile-time packaging assertion fails fast for the same "this is a bug, not a
runtime condition" reason: it means the code was built for the wrong shape of peer.

## The policy

```
LaunchTargetMatch::None                  // unconstrained - the status quo, hijackable
LaunchTargetMatch::ProcessIdAndSequence  // exactly one live process instance
LaunchTargetMatch::ExecutablePath        // one binary, by full path
LaunchTargetMatch::ExecutableFileName    // any binary with this name
LaunchTargetMatch::PackageFamilyName    // one packaged target, by PFN
```

Two comparison rules that are easy to get wrong:

- Full paths are compared **whole**, so `c:\evil\notepad.exe` can never satisfy a policy
  naming `c:\windows\system32\notepad.exe`.
- File names are compared against the **file name component**, never as a string suffix -
  otherwise `explorer.exe` would be satisfied by `c:\evil\notexplorer.exe`.

## Selecting a non-default handler

Everything above *rejects* a wrong handler; none of it can *pick* a right one that isn't
the scheme's default. `Windows.System.Launcher.LaunchUriAsync` has
`LauncherOptions.PreferredApplicationPackageFamilyName` /
`PreferredApplicationId` for exactly this - "launch this uri with *that* app, not
whatever is registered as default." Classic `ShellExecute` has no such parameter, and
`AssocQueryString`/`TryGetUriSchemeHandlerExecutablePath` can only ever answer "what is
the default", never "is this other, non-default app also a legitimate registered choice."

The fix asks the same association system a different question. `IAssocHandler`, reached
through the public `SHAssocEnumHandlersForProtocolByApplication`, enumerates every
application registered for a scheme - already deduplicated to one entry per app, the same
list behind the shell's own "Open with" picker. A caller matches by whichever identifier
it happens to have:

| `UriHandlerSelector` | Identifies | Matched against |
|---|---|---|
| `AppUserModelId` | a packaged app, by AUMID | `IAssocHandler::GetName()`, when it contains `!` |
| `ExecutablePath` | a classic handler, by full path | `IAssocHandler::GetName()`, when it does not |
| `ExecutableFileName` | a classic handler, by file name only | the file name component of the same |
| `ProgId` | any handler, by its association ProgId | `IObjectWithProgID::GetProgID()` |

`GetName()` is the one primitive both shapes resolve through: for a classic handler it
returns the full `.exe` path, for a packaged handler the AUMID
(`PackageFamilyName!AppId`) - and a file system path can never contain `!`, which is what
tells the two apart without a separate packaged/unpackaged branch.

Once a handler is found, its ProgId is what actually drives the launch:
`ShellExecuteExW`'s `SEE_MASK_CLASSNAME` / `lpClass` forces resolution to a specific
class, exactly the mechanism the shell's own picker uses to launch a non-default app.
That is also why this composes with the enforcement site chain for free - the site chain
judges whatever the shell resolves the class to, and does not care whether the class
came from the scheme's own default or from an override.

`ResolveTargetedUriLaunch` takes a `UriHandlerSelection` alongside the policy: a
selection is resolved once, up front, and if it names nothing currently registered that
is `NoHandler` - "not installed" is a different, more specific answer than "resolves to
the wrong thing," which is what `Refused` still means when a selection *does* resolve but
the policy doesn't accept it. Selecting an app is not a way to bypass the policy; it only
changes which target the policy is evaluated against.

Selection is orthogonal to the two live-process policies (`ProcessIdAndSequence`,
`PackageFamilyName`): those answer "is the launch reaching the peer I already know is
running," which has nothing to do with which registered app it dispatches through, so a
selection alongside either of those is simply ignored.

Most of the selection tests prove the mechanism against a scheme's *default* handler,
which every machine has exactly one of - that alone cannot prove picking a genuine
non-default choice works, since selecting the only registered app proves nothing about
choosing *among several*. `SelectingARealNonDefaultHandlerResolvesWithoutLaunching`
instead looks at the real machine it runs on: it enumerates `http`/`https`/`mailto` (the
schemes most likely to have more than one browser or mail client installed) until it
finds one with genuine contention, selects whichever registered handler is not the
default, and resolves it with `dryRun = true` - which returns after
`ResolveTargetedUriLaunch` and before `ShellExecuteExW` is ever reached - so the test
proves the non-default choice resolves correctly without spawning either application. If
no candidate scheme has more than one handler on the machine running the test, it logs
and skips rather than failing, since contention is a property of the machine, not of the
resolver.

### Package-target policy

Packaged app-to-app communication has a stronger target selector than a process path:
the **Package Family Name (PFN)**. `LauncherOptions.TargetApplicationPackageFamilyName`
can be supplied to both `Launcher.LaunchUriAsync` and
`Launcher.LaunchUriForResultsAsync`; the results API requires a valid target PFN.

TargetedLaunch should therefore expose a package policy alongside the process and path
policies:

```
RequirePackageFamilyName(pfn)
```

For the incoming-caller case, obtain the caller process identity from the COM call
context, then obtain its package identity from that process. The package policy uses the
caller package's PFN as the destination selector and launches through the WinRT
`Launcher` API. If the incoming caller is unpackaged, there is no PFN to carry forward,
so this policy must refuse rather than silently fall back to a default URI handler.

This is the same pattern as a response to a packaged caller: identify the package at the
boundary, carry the PFN into the response launch, and let the platform choose that
package's protocol handler. The policy is specifically for packaged-target
communication; it does not turn an unpackaged process path into a package identity.

The package selector is not expressible through `SHELLEXECUTEINFO`. `ShellExecuteExW`
can provide a site (`SEE_MASK_FLAG_HINST_IS_SITE`) so the caller can observe and reject
the shell's resolved handler, but the structure has no
`TargetApplicationPackageFamilyName` equivalent. Therefore:

- use `Launcher.LaunchUriAsync` when the target is a package and no result is needed;
- use `Launcher.LaunchUriForResultsAsync` when the target is a package and structured
  results are needed;
- use the `ShellExecuteExW` site-chain path for unpackaged targets, executable-path
  policies, process-instance policies, and probe/enforce behavior where the shell's
  resolved target is the authority.

The package policy is not interchangeable with a process policy. A PFN identifies the
package, not a particular running process instance. When the response must return to the
exact requesting process, use `ProcessIdAndSequence`; when the platform package contract
is the intended boundary, use the PFN policy and the WinRT Launcher API.

## Enforcement: the ShellExecute site chain

Pre-resolving the handler with `AssocQueryString` answers "what *would* ShellExecute
pick?" - but it is a **separate lookup** from the one ShellExecute actually performs. The
two can disagree, and the association answer is an unexpanded registration string.

The site chain closes that gap. Passing a site via `SEE_MASK_FLAG_HINST_IS_SITE` (site in
`hInstApp`) makes the shell call back at each internal decision point, *before* the launch
commits. Failing any callback cancels the launch, and the failure surfaces from
`ShellExecuteExW`.

| Hook | Service | Yields |
|---|---|---|
| `IHandlerActivationHost::BeforeCoCreateInstance` | `SID_SHandlerActivationHost` | handler CLSID + `IHandlerInfo` |
| `IHandlerActivationHost::BeforeCreateProcess` | `SID_SHandlerActivationHost` | **fully expanded** app path + real command line |
| `ICreatingProcess::OnCreating` | `SID_ExecuteCreatingProcess` | `ICreateProcessInputs` - can rewrite path/args/flags |

All four of these interfaces are **public**, in `ShObjIdl_core.h` (verified against SDK
10.0.26100). `SEE_MASK_NOASYNC` keeps callbacks on the calling thread so observations are
complete when the call returns.

### Probe mode

The same site runs in `LaunchSiteMode::Probe`: a *fake* launch that records the shell's
resolved target and then cancels every callback with `ERROR_CANCELLED`. This gives a
caller the real, expanded target **without launching anything**, which is useful for
building a policy or for showing the user what would happen.

Probe is a convenience, not the enforcement point - what it reports can go stale (TOCTOU).
`Enforce` mode, judging the shell's own resolved target inline, is authoritative.

### Rejected: after-create validation (`ICreatedProcess`)

`ICreatingProcess` is only the *before* half of a pair. A private `ICreatedProcess`
(IID `c2b937aa-3110-4398-8a56-f34c6342d244`, sequential with `ICreatingProcess` at `...a9`)
is the *after* half, handed an `ICreateProcessOutputs` exposing the **real process handle,
pid and thread handle**. It looks like the way to close the gap between judging a *path* -
what the shell intends to run - and proving what actually ran.

It is **not used**, for two independent reasons:

1. **It answers about the wrong process.** A newly created process cannot be the peer a
   response is owed to: it wasn't running when the request was made, so it isn't the
   requester. For a single-instance app it is worse than useless - the created process
   forwards to the already-running instance and exits, so the handle names a transient stub.
2. **It offers nothing new.** The fully expanded path already arrives *before* the launch
   via `BeforeCreateProcess`, where a policy can still veto and no process is ever created.
   That also covers the COM handler case, where no process is created at all and the
   after-hook never fires.

Acting after creation leaves `TerminateProcess` as the only remedy - killing something
already running, having gained no information that wasn't available earlier and more safely.

Exact process-instance policies are therefore answered from an identity captured from the
**live peer** - the COM caller, an HWND, a parent, or an explicit pid - never from the
launch. That is the right shape anyway: the peer is the process that asked, and it was
already running.

## COM server resolution (CLSID -> binary)

When the handler is a COM handler, the target is the server binary. There is **no COM API**
that answers "server path for a CLSID" - registry parsing of the registrations COM itself
uses is the only route. (There is an API that names the server *process* for a live proxy,
but it is gated behind a developer license - see below.)

Classic:
- `CLSID\{clsid}\LocalServer32` -> exe
- `CLSID\{clsid}\InProcServer32` -> dll (**no process of its own, so nothing to pin**)
- `AppID\{id}\DllSurrogate` -> surrogate; empty value means the system `dllhost.exe`

Packaged (MSIX) COM is **not** in `HKCR\CLSID` at all - verified empirically: of 170
`ClassIndex` entries, 0 had a classic CLSID key. It lives in a separate hive:

```
HKCR\PackagedCom\ClassIndex\{clsid}\<packageFullName>
HKCR\PackagedCom\Package\<pfn>\Class\{clsid}   -> ServerId, DllPath
HKCR\PackagedCom\Package\<pfn>\Server\<id>     -> Executable | identity/surrogate values
```

`Executable` is **package-relative**; resolved to absolute via `GetPackagePathByFullName`.

### Rejected: asking a live proxy (`CoDecodeProxy`)

For an already-running local server it is tempting to skip the registry entirely: activate
the object and ask the proxy who serves it. `CoDecodeProxy` (`combaseapi.h`, public since
Win8) does exactly that, returning `ServerInformation { dwServerPid, dwServerTid,
ui64ServerAddress }`, and it is authoritative in a way registry parsing can never be - it
names the process actually on the other end of the pipe.

**It requires a developer license, so it is unusable here.** The gate is in the SCM, not
the caller-side API, and it is the *first* check performed - before the caller lookup,
the Medium-IL check, and the impersonation
(`onecore/com/combase/rpcss/olescm/scmif.cxx`):

```cpp
// Developer License must be installed.
RETURN_IF_FAILED(IsDeveloperLicenseInstalled(&fDevLicenseInstalled));
RETURN_HR_IF(E_ACCESSDENIED, !fDevLicenseInstalled);
```

Measured on a developer machine: `CoCreateInstance(CLSID_ShellWindows, CLSCTX_LOCAL_SERVER)`
succeeds, then `CoDecodeProxy` returns `E_ACCESSDENIED` for the resulting proxy. The tell is
the control case - an *in-proc* `IShellItem` returns the **same** `E_ACCESSDENIED`, where a
genuine decode failure would give `RPC_E_INVALID_IPID`. Nothing was decoded; the call never
got past the gate. Note also that `AllowDevelopmentWithoutDevLicense=1` (developer *mode*)
does **not** satisfy `IsDeveloperLicenseInstalled` - these are different things.

The API is built for debuggers, as its own source comment says ("The caller (debugger,
usually) must have permissions to open the client (debuggee, usually)"). A mitigation that
fails closed on every customer machine is not a mitigation, so this approach is dropped.

Two further reasons it would not have fit even if the gate were removed, worth recording so
the idea is not revived on the strength of "but it's authoritative":

- **The probe would have to run in `BeforeCoCreateInstance`**, because there is no "after"
  hook - `IHandlerActivationHost` has exactly two methods, both `Before*`, and no v2 or
  private variant exists. The interface is deliberately veto-only.
- **`CoCreateInstance` with `CLSCTX_LOCAL_SERVER` launches the server if it is not already
  running.** A check that starts the process it is vetting is a bad trade.

Two real bugs found here, both worth knowing about:

1. **In-proc packaged servers keep `DllPath` on the *Class* key, not the Server key.**
2. **A class is commonly indexed under several package *versions*, only one installed.**
   Taking the first enumerated entry let **enumeration order decide a security-relevant
   path**. Every candidate is now tried, and the one that resolves wins.

## Testing

`Tests/TargetedLaunchTests.cpp` - 9 test classes covering each case above, including a
genuine cross-process COM call (a helper process binds via the ROT and calls in, proving
the identity came from the wire), and a dedicated class for handler selection
(`TargetedLaunchHandlerSelection`) that resolves the machine's own default `http` handler
back through the enumeration, by path, by file name, and confirms an unregistered
selector is `NoHandler` rather than a silent fallback.

A **sweep** runs every COM registration on the machine through the resolver (~7900 classic
+ ~170 packaged, under 2s). It asserts *invariants*, never specific paths, because the
machine's contents are not the test's to control:

- failure is clean (nothing left behind a policy could act on)
- success is absolute and fully expanded
- results are **deterministic** - the same CLSID resolves the same way every time

That last one is what caught the enumeration-order bug.

Packaged paths are deliberately **not** probed on disk: `WindowsApps` is ACL'd, and
stub/on-demand packages are registered and healthy while their payload has not been
streamed in - so a filesystem answer there says nothing about the resolver.

## Comparison with LaunchUriForResults

`LaunchUriForResultsAsync` requires MSIX packaging and a `ReturnResults` attribute on
`<uap:Protocol>`; TargetedLaunch is the unpackaged path to the same guarantee - an exact
process instance receives the response, verified by pid and sequence number rather than
by platform-enforced package identity.
