# Contributor and Copilot instructions

Conventions for this repository. These are review rules, not preferences —
changes that violate them get sent back.

## C++ namespace conventions

### Never write `using namespace winrt;`

It drags the entire namespace in. `winrt` is large and full of short, common
names (`Uri`, `hstring`, `ValueSet`, `Launcher`), so this reliably collides
with local types and with the Win32 headers.

### Avoid long flat lists of `using winrt::X;` at file scope

A list of individual `using` statements looks more disciplined than
`using namespace`, but it has the same failure mode: it accumulates. Each new
entry drops one more short name into file scope, and the collision arrives
later, in an unrelated change, as a confusing error.

### Instead: reopen the namespace and pull types into it

Declare the specific types the file uses inside `namespace winrt`, then spell
every call site `winrt::`:

```cpp
namespace winrt
{
    using Windows::Foundation::Uri;
    using Windows::System::Launcher;
    using Windows::System::LauncherOptions;
}

// call sites
winrt::Launcher::LaunchUriAsync(winrt::Uri(uri), options);
```

Call sites stay short, but the qualifier still says where the name came from,
and nothing lands in the global namespace.

### Hard rule: no namespace-scope aliases in headers

A `using` at namespace scope in a `.h` leaks into every translation unit that
includes it, so a header can silently impose collisions on files that never
asked for it. Headers spell names out in full:

```cpp
// TargetedLaunch.h
inline winrt::Windows::Foundation::IAsyncOperation<bool> LaunchUriAsync(...);
```

Verbose, but correct. Do not "clean this up" with an alias block.

A `using` **inside** an inline function body is fine — its scope ends at the
closing brace, so it cannot leak.

### Scope of these rules

They target `winrt` and other large system or third-party namespaces, where the
collision risk is real.

They are not meant to ban `using namespace` for this project's own small,
purpose-built namespaces. `Tests/TargetedLaunchTests.cpp` may say
`using namespace TargetedLaunch;` at file scope: that namespace is ours, it is
small, and the file exists only to exercise it.
