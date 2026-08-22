#pragma once
//
// TargetedLaunch - constrain *who* is allowed to receive a launch.
//
// The "local only" mitigation in this project restricts launches by *source* (an
// untrusted, low privileged host must not be able to invoke a scheme). TargetedLaunch is
// the complementary half: it restricts a launch by *destination*. The launcher names the
// process that is permitted to receive the invoke, and the launch is refused if the
// resolved handler is anything else.
//
// This matters in two shapes:
//
//  1. Request/response (the LaunchUriForResults shape, built out of two one-way uri
//     launches). The response leg must land in the exact process instance that made the
//     request - matched on process id *and* process sequence number so a recycled pid
//     can't impersonate the requester.
//
//  2. Anti-hijack for ordinary launches. The caller only trusts one specific handler
//     binary, so it pins the launch to a full executable path, or (looser) to an
//     executable file name ("only ever launch explorer.exe this way"). A caller here can
//     equally pin to a live process instance - the two shapes share one policy type.
//
// The target is resolved through the association system: a uri scheme maps to the
// registered handler's .exe. Where the peer is a live process instead of a registration,
// its identity is captured from whatever representation the caller happens to hold - a
// process id, a process HANDLE, an HWND, an incoming COM call, an IUnknown proxy to the
// caller, or the parent process. See the ProcessIdentity capture functions below; they
// all converge on the same identity, so a policy never cares which one was used.
//

#include <windows.h>
#include <shlwapi.h>
#include <appmodel.h>
#include <rpc.h>
#include <rpcdce.h>
#include <rpcasync.h>
#include <winternl.h>
#include <objidl.h>

#include <optional>
#include <string>
#include <string_view>

#include <wil/com.h>
#include <wil/registry.h>
#include <wil/resource.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.System.h>
#include <wil/result_macros.h>
#include <wil/win32_helpers.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")

namespace TargetedLaunch
{

// The site chain hooks it consumes -
// IHandlerActivationHost, IHandlerInfo, ICreatingProcess and ICreateProcessInputs - are
// all declared in ShObjIdl_core.h (verified against Windows SDK 10.0.26100).
//
// ICreatingProcess is only the *before* half of a pair. A non-public ICreatedProcess
// exists as the *after* half, handed an ICreateProcessOutputs exposing the launched
// process as a real handle rather than a registration string. It is deliberately *not*
// used here, for two independent reasons:
//
//  - It answers about the wrong process. A newly created process cannot be the peer a
//    response is owed to: it was not running when the request was made, so it is not the
//    requester. Worse, for a single-instance app the created process forwards to the
//    already-running first instance and exits, so the handle names a transient stub.
//  - It offers nothing new. The fully expanded path is already delivered *before* the
//    launch by BeforeCreateProcess, where a policy can still veto and no process is ever
//    created, and it covers the COM handler case where no process is created at all.
//
// Acting after creation would leave TerminateProcess as the only remedy - killing
// something already running, having gained no information. Exact process-instance
// policies are therefore answered by an identity captured from the live peer (the COM
// caller, an HWND, a parent, or an explicit pid), never from the launch.

// Process identity.
//
// A process id alone is not an identity: pids are recycled, so a pid captured at request
// time can name a completely different process by the time the response is launched. The
// sequence number - a monotonically increasing, never-reused kernel value - closes that
// window, and is the only discriminator used here. It is available for any process whose
// handle we can open at all, so there is no need for a weaker fallback: creation time
// would answer the same question less precisely, and having two answers invites the bug
// where the weaker one silently decides a security question.
//
// This struct carries three identities of different strength, not one:
//   - processId + sequenceNumber together name one live process *instance*. This is the
//     strong case - the pair can never be satisfied by a recycled pid or an unrelated
//     process, and it is what SameProcessInstance below judges.
//   - executablePath names a *kind* of process (whatever binary happens to be running at
//     that path), not an instance. It is the weak case: it says nothing about which
//     instance, or whether the path is still the same file it was when captured.
//   - packageFamilyName names a *package*, not a process. It is strong within its own
//     question (which package produced this process cannot be spoofed by an unpackaged
//     process claiming a PFN), but it is slightly less precise than pid+sequence: a
//     package can contain multiple apps, so a PFN policy can be satisfied by any instance
//     of any app the package's manifest owns. That imprecision is not a hijack surface -
//     one app in a package impersonating a sibling app in the *same* package is not the
//     threat this policy defends against; the package boundary is what mattered.
// A policy should be explicit about which of these three it is trusting; they are not
// interchangeable substitutes for one another.
struct ProcessIdentity
{
    DWORD processId{};
    ULONGLONG sequenceNumber{};
    std::wstring executablePath;
    std::wstring packageFamilyName;

    bool IsValid() const noexcept
    {
        return (processId != 0) && (sequenceNumber != 0);
    }

    // Both halves must agree. The sequence number is what makes this safe against pid
    // reuse; without one on either side there is no instance discriminator, so this
    // refuses rather than guessing.
    bool SameProcessInstance(ProcessIdentity const& other) const noexcept
    {
        return IsValid() && other.IsValid() &&
               (processId == other.processId) && (sequenceNumber == other.sequenceNumber);
    }
};

namespace details
{
    // ProcessSequenceNumber has no documented Win32 wrapper, but NtQueryInformationProcess
    // itself is declared in winternl.h and ntdll.lib ships in the SDK, so it links
    // statically - no GetProcAddress, no per-call resolution, and a link error rather
    // than a silent runtime null if it ever goes away.
    constexpr PROCESSINFOCLASS ProcessSequenceNumberClass = static_cast<PROCESSINFOCLASS>(92);

    inline ULONGLONG QueryProcessSequenceNumber(HANDLE process) noexcept
    {
        ULONGLONG sequenceNumber{};
        ULONG returnLength{};
        if (!NT_SUCCESS(NtQueryInformationProcess(process, ProcessSequenceNumberClass,
                &sequenceNumber, sizeof(sequenceNumber), &returnLength)))
        {
            return 0;
        }
        return sequenceNumber;
    }

    // The parent pid comes straight from PROCESS_BASIC_INFORMATION. A toolhelp snapshot
    // would answer the same question by copying the entire process list to find one field.
    //
    // winternl.h publishes the struct with most fields reserved: the parent pid is the
    // field it calls Reserved3. The layout is contractual - the reserved names exist so
    // the shape stays fixed - but the intent is not obvious at the use site, so it is
    // named here rather than at the call.
    inline DWORD QueryParentProcessId(HANDLE process) noexcept
    {
        PROCESS_BASIC_INFORMATION basicInformation{};
        ULONG returnLength{};
        if (!NT_SUCCESS(NtQueryInformationProcess(process, ProcessBasicInformation,
                &basicInformation, sizeof(basicInformation), &returnLength)))
        {
            return 0;
        }
        // Reserved3 == InheritedFromUniqueProcessId.
        return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basicInformation.Reserved3));
    }
}

// Packaging modes. There are two independent questions here, and conflating them is a
// mistake: *this* process may be packaged, and the *peer* process may be packaged, and
// knowing one says nothing about the other.
//
// Each question has the same three answers, but they are separate template parameters so
// a caller states them independently - and so neither can be passed where the other was
// meant. Each is a template argument rather than a runtime flag, so 'if constexpr'
// compiles the unneeded path out entirely rather than merely skipping it at runtime.
//
//   - AlwaysPackaged  - known at compile time to be packaged.
//   - NeverPackaged   - known at compile time not to be packaged.
//   - RuntimeDetected - not known at compile time; detected at runtime and either answer
//     accepted. This is the only correct choice for code that genuinely cannot know.
//
// The two compile-time answers are assertions, and they are fail-fast checked: if the
// process turns out to be the other thing, that is a build/deployment error - the code
// was compiled for a shape it is not running in - not a security refusal and not an
// ordinary runtime outcome. Fail fast rather than silently mismodeling the process.

// The process hosting this code.
//
// A binary that is only ever shipped inside a package, or only ever as a classic desktop
// binary, knows this at compile time. A DLL that can load into either kind of host does
// not, and must use RuntimeDetected.
enum class CallerPackagingMode
{
    RuntimeDetected,
    NeverPackaged,
    AlwaysPackaged,
};

// The peer process being identified or targeted.
//
// A broker that only ever talks to packaged apps knows this at compile time; so does a
// tool that only ever targets classic desktop binaries. Code that must work against
// either - or that resolves its peer from an association, where the answer depends on
// what happens to be registered - must use RuntimeDetected.
enum class TargetPackagingMode
{
    RuntimeDetected,
    NeverPackaged,
    AlwaysPackaged,
};

namespace details
{
    inline std::optional<std::wstring> TryQueryPackageFamilyName(HANDLE process) noexcept try
    {
        UINT32 length{};
        const LONG firstResult = GetPackageFamilyName(process, &length, nullptr);
        if (firstResult != ERROR_INSUFFICIENT_BUFFER)
        {
            return std::nullopt;
        }

        std::wstring packageFamilyName(length, L'\0');
        if (GetPackageFamilyName(process, &length, packageFamilyName.data()) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }
        packageFamilyName.resize(length);
        if (!packageFamilyName.empty() && packageFamilyName.back() == L'\0')
        {
            packageFamilyName.pop_back();
        }
        return packageFamilyName;
    }
    catch (...)
    {
        return std::nullopt;
    }

    // Both mode enums reduce to the same three assumptions; the implementation is shared
    // so the two questions stay independent at the API without duplicating the logic.
    enum class PackagingAssumption
    {
        Detect,         // no assumption - query and accept either answer
        AssertNone,     // asserted unpackaged
        AssertPackaged, // asserted packaged
    };

    constexpr PackagingAssumption ToAssumption(CallerPackagingMode mode) noexcept
    {
        return (mode == CallerPackagingMode::NeverPackaged)  ? PackagingAssumption::AssertNone :
               (mode == CallerPackagingMode::AlwaysPackaged) ? PackagingAssumption::AssertPackaged :
                                                               PackagingAssumption::Detect;
    }

    constexpr PackagingAssumption ToAssumption(TargetPackagingMode mode) noexcept
    {
        return (mode == TargetPackagingMode::NeverPackaged)  ? PackagingAssumption::AssertNone :
               (mode == TargetPackagingMode::AlwaysPackaged) ? PackagingAssumption::AssertPackaged :
                                                               PackagingAssumption::Detect;
    }

    // Fills identity.packageFamilyName according to the assumption, compiled per-case:
    //   - Detect:         always queries, accepts either answer - no assumption to check.
    //   - AssertNone:     still queries, once, purely to fail-fast verify the assertion -
    //                     asserting "never packaged" and being wrong is a build or
    //                     deployment error, and must be caught rather than silently
    //                     accepted. What compiles out is everything downstream of the
    //                     query: packageFamilyName is never populated or branched on in
    //                     this mode, so code compiled this way carries no cost for
    //                     package-aware paths it will never exercise.
    //   - AssertPackaged: always queries; fail-fasts when the process asserted to be
    //                     packaged has no package identity.
    template <PackagingAssumption Assumption>
    inline void ApplyPackagingAssumption(HANDLE process, ProcessIdentity& identity) noexcept
    {
        if constexpr (Assumption == PackagingAssumption::AssertNone)
        {
            FAIL_FAST_HR_IF_MSG(E_UNEXPECTED, details::TryQueryPackageFamilyName(process).has_value(),
                "TargetedLaunch: NeverPackaged asserted for a packaged process");
        }
        else if constexpr (Assumption == PackagingAssumption::AssertPackaged)
        {
            auto packageFamilyName = details::TryQueryPackageFamilyName(process);
            FAIL_FAST_HR_IF_MSG(E_UNEXPECTED, !packageFamilyName.has_value(),
                "TargetedLaunch: AlwaysPackaged asserted for an unpackaged process");
            identity.packageFamilyName = std::move(*packageFamilyName);
        }
        else // Detect
        {
            if (auto packageFamilyName = details::TryQueryPackageFamilyName(process))
            {
                identity.packageFamilyName = std::move(*packageFamilyName);
            }
        }
    }

    template <TargetPackagingMode Mode>
    inline void ApplyTargetPackagingMode(HANDLE process, ProcessIdentity& identity) noexcept
    {
        ApplyPackagingAssumption<ToAssumption(Mode)>(process, identity);
    }

    template <CallerPackagingMode Mode>
    inline void ApplyCallerPackagingMode(HANDLE process, ProcessIdentity& identity) noexcept
    {
        ApplyPackagingAssumption<ToAssumption(Mode)>(process, identity);
    }
}

// Capture identity from a process HANDLE the caller already holds - avoids reopening,
// and works when the caller has a handle it could not have obtained by pid.
//
// These capture a *peer*, so they take a TargetPackagingMode. It defaults to
// RuntimeDetected, the neutral case; code that must remain packaging neutral should never
// supply a different argument. NeverPackaged and AlwaysPackaged are opt-in for callers who
// already know the peer's shape and want the unneeded branch (and, for NeverPackaged, the
// query itself) compiled out.
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected>
inline std::optional<ProcessIdentity> TryGetProcessIdentity(HANDLE process) noexcept try
{
    ProcessIdentity identity;
    identity.processId = GetProcessId(process);
    identity.sequenceNumber = details::QueryProcessSequenceNumber(process);
    if (!identity.IsValid())
    {
        return std::nullopt;
    }

    // Best effort: an identity is still usable for instance matching without a path.
    wil::unique_cotaskmem_string executablePath;
    if (SUCCEEDED(wil::QueryFullProcessImageNameW(process, 0, executablePath)))
    {
        identity.executablePath = executablePath.get();
    }
    details::ApplyTargetPackagingMode<Mode>(process, identity);
    return identity;
}
catch (...)
{
    return std::nullopt;
}

// Capture the full identity of a process by id.
//
// Failure is ordinary, not exceptional: OpenProcess is denied for a process at a higher
// integrity level or in another session, which is exactly the situation this mitigation
// exists for. So the result is optional and callers are expected to handle empty - the
// contract is "you may not get one", not "check an error code".
//
// PROCESS_QUERY_LIMITED_INFORMATION is the least privilege that yields the image path
// and sequence number, and it works across integrity levels for the common cases.
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected>
inline std::optional<ProcessIdentity> TryGetProcessIdentity(DWORD processId) noexcept
{
    wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process)
    {
        return std::nullopt;
    }
    return TryGetProcessIdentity<Mode>(process.get());
}

// Capture identity from a window - the representation a caller holds when the peer is a
// UI process it is talking to. Nothing here is specific to any one launch mechanism: this
// is the same HWND -> identity conversion used for any window handle, whether it came
// from a DirectLaunch registration or from something like GetShellWindow().
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected>
inline std::optional<ProcessIdentity> TryGetProcessIdentity(HWND window) noexcept
{
    DWORD processId{};
    if ((GetWindowThreadProcessId(window, &processId) == 0) || (processId == 0))
    {
        return std::nullopt;
    }
    return TryGetProcessIdentity<Mode>(processId);
}

// Capture *this* process's identity - so it takes a CallerPackagingMode, the other
// question entirely. A binary that only ever ships packaged (or only ever unpackaged) can
// assert that here and have it verified; a DLL that loads into either kind of host must
// leave this at RuntimeDetected.
template <CallerPackagingMode Mode = CallerPackagingMode::RuntimeDetected>
inline ProcessIdentity GetCurrentProcessIdentity()
{
    ProcessIdentity identity;
    const HANDLE process = GetCurrentProcess();
    identity.processId = GetProcessId(process);
    identity.sequenceNumber = details::QueryProcessSequenceNumber(process);
    THROW_HR_IF(E_UNEXPECTED, !identity.IsValid());

    wil::unique_cotaskmem_string executablePath;
    if (SUCCEEDED(wil::QueryFullProcessImageNameW(process, 0, executablePath)))
    {
        identity.executablePath = executablePath.get();
    }
    details::ApplyCallerPackagingMode<Mode>(process, identity);
    return identity;
}

// Launch a uri, targeting one specific package by family name.
//
// A launch that the platform simply declines - no handler, the target package isn't
// installed, the user isn't entitled to it - is the ordinary "no" this mitigation exists
// to represent, so those outcomes come back as 'false', not as an exception.
//
// Everything else is not ordinary here and is left to propagate:
//   - a null uri or an empty package family name is a caller usage error (THROW_HR_IF),
//     not a launch outcome - it means the caller built the request wrong.
//   - CO_E_NOTINITIALIZED (no apartment on this thread) and RPC_E_WRONG_THREAD (an ASTA
//     violation) are likewise usage errors, not launch outcomes - the caller invoked this
//     from a context it must not, and that is a bug in the caller, not "no handler".
//   - any other catastrophic failure (allocation failure, marshaling corruption) is not
//     a "no" either, and swallowing it here would hide it from the caller.
//
// So only the WinRT exceptions that correspond to an ordinary declined launch are
// caught; every other 'hresult_error' - and anything that is not one at all, such as
// 'std::bad_alloc' - is left to unwind uncaught.
inline winrt::Windows::Foundation::IAsyncOperation<bool>
TryLaunchUriWithPackageTargetAsync(PCWSTR uri, std::wstring_view packageFamilyName)
{
    THROW_HR_IF_NULL(E_INVALIDARG, uri);
    THROW_HR_IF(E_INVALIDARG, packageFamilyName.empty());

    try
    {
        winrt::Windows::System::LauncherOptions options;
        options.TargetApplicationPackageFamilyName(packageFamilyName);
        const bool launched = co_await winrt::Windows::System::Launcher::LaunchUriAsync(
            winrt::Windows::Foundation::Uri(uri), options);
        co_return launched;
    }
    catch (const winrt::hresult_error& error)
    {
        switch (error.code())
        {
        case HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND):
        case HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION):
        case E_ACCESSDENIED:
            // The platform declined the launch outright - an ordinary "no", answered
            // the same way IsSatisfiedBy/Try-style callers elsewhere expect.
            co_return false;
        default:
            // Not a declined-launch outcome - includes CO_E_NOTINITIALIZED and
            // RPC_E_WRONG_THREAD (caller usage errors: wrong apartment/thread) as well
            // as any other unanticipated failure. Rethrowing keeps a real bug from
            // being reported as "just no".
            throw;
        }
    }
}

// Identity source: the incoming COM caller.
//
// When the launch request arrives as a COM call, the peer to target is the caller on the
// other end of that call, not whatever the caller *claims* to be. Asking the call context
// for it means a caller cannot spoof its own identity by passing a pid as a parameter.
//
// There are two ways to ask, and they trade publicness against precision:
//
//  - ComCallerSource::Rpc (the default) uses RpcServerInqCallAttributesW with
//    RPC_QUERY_CLIENT_PID - entirely public SDK surface (rpcasync.h, since Vista). It
//    yields a *pid*, which must then be opened. That reintroduces a reopen-by-pid step,
//    and so a recycled-pid window. The window is very narrow in practice, because a
//    synchronous caller is blocked awaiting the reply and therefore cannot have exited,
//    but it is not nothing if the caller is killed mid-call. The captured sequence number
//    is what makes a later match still meaningful.
//
//  - ComCallerSource::CallContext uses ICallingProcessInfo, which opens a handle to the
//    calling process directly. A handle rather than a pid closes the window entirely: the
//    identity is captured from the very process COM was talking to, with no reopen step
//    in between. This interface is not in the public SDK. It is stable in practice - it
//    is re-published in the UndockedDevKit (udk/com_apis.h) under the same IID, with a
//    contract test asserting the IID does not change - but code that must stay on
//    documented surface cannot use it.
//
// Documenting ICallingProcessInfo would let every caller have the precise form without
// the private dependency; until then the default stays public and the precise mode is
// opt-in.
enum class ComCallerSource
{
    Rpc,           // public: RpcServerInqCallAttributesW, yields a pid
    CallContext,   // private: ICallingProcessInfo, yields a handle
};

namespace details
{
    inline HMODULE GetCombaseModule() noexcept
    {
        static HMODULE s_module = LoadLibraryExW(L"combase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        return s_module;
    }

    // The call context on the object being served, rather than the ambient call context
    // of the thread. Scoping the question to the server object is what makes the answer
    // exact: the thread's ambient context describes whatever call the thread is nested
    // inside, which is not necessarily the call into *this* object.
    inline HRESULT CoGetCallContextOfObject(
        IUnknown* server, REFIID riid, _COM_Outptr_result_maybenull_ void** result) noexcept
    {
        *result = nullptr;
        static auto s_fn = reinterpret_cast<decltype(&CoGetCallContextOfObject)>(
            GetProcAddress(GetCombaseModule(), MAKEINTRESOURCEA(167)));
        return s_fn ? s_fn(server, riid, result) : E_NOTIMPL;
    }
}

MIDL_INTERFACE("68c6a1b9-de39-42c3-8d28-bf40a5126541")
ICallingProcessInfo : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE OpenCallerProcessHandle(
        DWORD desiredAccess, _Out_ HANDLE* callerProcessHandle) = 0;
};

// The shared abstraction. Every COM entry point below ends in one of these two, so a
// policy never has to care which was used, and each capture step exists exactly once.
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected>
inline std::optional<ProcessIdentity> TryGetCallerIdentityFromCallContext(
    _In_opt_ ICallingProcessInfo* callingProcessInfo) noexcept
{
    if (!callingProcessInfo)
    {
        return std::nullopt;
    }

    wil::unique_handle callerProcess;
    if (FAILED(callingProcessInfo->OpenCallerProcessHandle(
            PROCESS_QUERY_LIMITED_INFORMATION, &callerProcess)) || !callerProcess)
    {
        return std::nullopt;
    }
    return TryGetProcessIdentity<Mode>(callerProcess.get());
}

namespace details
{
    // The public route: the pid the RPC layer recorded for the active call. Still not
    // caller-supplied, so it cannot be spoofed by a parameter - but it is a pid, so the
    // identity is captured by reopening it.
    template <TargetPackagingMode Mode>
    inline std::optional<ProcessIdentity> TryGetRpcCallerIdentity() noexcept
    {
        RPC_CALL_ATTRIBUTES_V2_W attributes{};
        attributes.Version = 2;
        attributes.Flags = RPC_QUERY_CLIENT_PID;
        if (RpcServerInqCallAttributesW(nullptr, &attributes) != RPC_S_OK)
        {
            return std::nullopt;   // not servicing an RPC call, or it carries no context
        }

        const auto callerPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(attributes.ClientPID));
        return callerPid ? TryGetProcessIdentity<Mode>(callerPid) : std::nullopt;
    }
}

// Resolve the identity of the process that made the incoming COM call ("for calling
// process"). Must be invoked on the thread servicing that call, while it is still active.
//
// This reads the *ambient* context of the thread, so it describes whatever call the thread
// is currently nested inside. For a normal (non-partial-trust) server, placing this at the
// COM entry point is correct and the distinction never arises; it matters only when an
// unrelated in-process path can reach the same thread. Use the "for caller of object" form
// below when that is a concern and the object is available.
//
// 'Source' selects the mechanism: the public RPC query by default, or the private call
// context for an exact handle. See the ComCallerSource comment above for the trade.
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected,
          ComCallerSource Source = ComCallerSource::Rpc>
inline std::optional<ProcessIdentity> TryGetComCallerIdentity() noexcept
{
    if constexpr (Source == ComCallerSource::Rpc)
    {
        return details::TryGetRpcCallerIdentity<Mode>();
    }
    else
    {
        wil::com_ptr<ICallingProcessInfo> callingProcessInfo;
        if (FAILED(CoGetCallContext(IID_PPV_ARGS(&callingProcessInfo))))
        {
            return std::nullopt;   // not servicing a call, or the call carries no context
        }
        return TryGetCallerIdentityFromCallContext<Mode>(callingProcessInfo.get());
    }
}

// Resolve the identity of the process calling *this object* ("for caller of object").
//
// The object passes itself, and COM answers for the call into that object specifically, so
// it cannot mistake an unrelated call the thread happens to be nested inside for the caller
// of this object.
//
// This form has no public equivalent: RPC call attributes are ambient to the thread, and
// there is no per-object query. It is therefore always the private route - which is the
// strongest argument for documenting ICallingProcessInfo.
template <TargetPackagingMode Mode = TargetPackagingMode::RuntimeDetected>
inline std::optional<ProcessIdentity> TryGetComCallerIdentityForObject(_In_ IUnknown* server) noexcept
{
    wil::com_ptr<ICallingProcessInfo> callingProcessInfo;
    if (FAILED(details::CoGetCallContextOfObject(
            server, IID_PPV_ARGS(&callingProcessInfo))) || !callingProcessInfo)
    {
        return std::nullopt;
    }
    return TryGetCallerIdentityFromCallContext<Mode>(callingProcessInfo.get());
}

// Identity source: the parent process.

// Walk up the parentage chain to pick the process that should receive the response.
// 'levels' of 1 is the immediate parent. A parent pid is only a *claim* until it is
// opened and its identity captured: the recorded parent may already have exited, and its
// pid may now name an unrelated process. The sequence number recorded in the resulting
// identity is what makes a later match meaningful.
//
// This is meaningful for classic child-process creation only. Packaged activation goes
// through the platform activation broker, so the recorded parent names infrastructure
// rather than the requester - and it returns a plausible-but-wrong identity instead of
// failing, which is worse than no answer. Do not use it to identify a packaged peer.
inline std::optional<ProcessIdentity> TryGetParentProcessIdentity(DWORD processId, DWORD levels = 1) noexcept
{
    DWORD current = processId;
    for (DWORD i = 0; i < levels; ++i)
    {
        wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, current));
        if (!process)
        {
            return std::nullopt;
        }
        const DWORD parent = details::QueryParentProcessId(process.get());
        if (parent == 0)
        {
            return std::nullopt;
        }
        current = parent;
    }
    return TryGetProcessIdentity(current);
}

// A stale-parent detector. Sequence numbers are handed out in creation order and never
// reused, so a real ancestor always has a lower one than its descendant. A "parent" whose
// sequence number is higher started later - it is a recycled pid, not the process that
// launched us. This is the same value already used for instance matching, so ancestry and
// identity are decided by one discriminator rather than two that could disagree.
inline bool IsPlausibleAncestor(ProcessIdentity const& ancestor, ProcessIdentity const& child) noexcept
{
    return ancestor.IsValid() && child.IsValid() && (ancestor.sequenceNumber < child.sequenceNumber);
}

// Target resolution: uri scheme -> handler executable.

// The association system is the authority on which .exe handles a scheme, so path-based
// policies are evaluated against the handler that ShellExecute would actually pick.
// A scheme with no registered handler is an ordinary answer, not an error, so this is a
// Try: on a clean machine most schemes resolve to nothing.
inline std::optional<std::wstring> TryGetUriSchemeHandlerExecutablePath(PCWSTR scheme) noexcept try
{
    wchar_t path[MAX_PATH * 2]{};
    DWORD length = ARRAYSIZE(path);
    // ASSOCF_IS_PROTOCOL: 'scheme' is a uri scheme, not a file extension.
    if (FAILED(AssocQueryStringW(ASSOCF_IS_PROTOCOL, ASSOCSTR_EXECUTABLE, scheme, nullptr, path, &length)))
    {
        return std::nullopt;
    }

    if (path[0] == L'\0')
    {
        return std::nullopt;
    }
    return std::wstring(path);
}
catch (...)
{
    return std::nullopt;
}

inline std::wstring_view GetFileNamePart(std::wstring_view path) noexcept
{
    const auto slash = path.find_last_of(L"\\/");
    return (slash == std::wstring_view::npos) ? path : path.substr(slash + 1);
}

inline bool EqualsIgnoreCase(std::wstring_view left, std::wstring_view right) noexcept
{
    return wil::compare_string_ordinal(left, right, true) == nullptr;
}

// Selecting among multiple registered handlers.
//
// Everything above answers "what is the *default* handler for this scheme" - the same
// question ShellExecute itself answers. That is enough to reject a hijacker, but it
// cannot pick a *non-default* handler that is nonetheless a legitimate, registered
// choice: WinRT's Launcher.LaunchUriAsync has PreferredApplicationPackageFamilyName /
// PreferredApplicationId for exactly this, and classic ShellExecute has no equivalent.
//
// The fix is the same association system, asked a different question:
// SHAssocEnumHandlersForProtocolByApplication enumerates every application registered
// for the scheme (already deduplicated to one entry per app - the same list the shell's
// "Open with" picker shows), and the caller matches by whichever identifier it has:
//   - AppUserModelId - the AUMID of a packaged app ("PackageFamilyName!AppId").
//   - ExecutablePath / ExecutableFileName - a classic desktop handler, by full path or
//     by file name only, mirroring the two granularities LaunchTargetPolicy already
//     offers for pinning a launch.
//   - ProgId - the association ProgId directly, for a caller that already knows it.
//
// IAssocHandler::GetName() is the single primitive both classic and packaged cases
// resolve through: for a classic handler it returns the full .exe path; for a packaged
// handler it returns the AUMID, which is why a '!' in the name is what tells the two
// apart - a file system path can't contain one.
enum class UriHandlerSelector
{
    Default,             // whatever the association system's default answers - status quo
    ExecutablePath,      // a classic handler, by full path
    ExecutableFileName,  // a classic handler, by file name only
    AppUserModelId,      // a packaged handler, by AUMID ("PackageFamilyName!AppId")
    ProgId,              // any handler, by its association ProgId
};

struct UriHandlerSelection
{
    UriHandlerSelector selector{UriHandlerSelector::Default};
    std::wstring value;

    static UriHandlerSelection Default() noexcept
    {
        return {};
    }

    static UriHandlerSelection ByExecutablePath(std::wstring path)
    {
        return {UriHandlerSelector::ExecutablePath, std::move(path)};
    }

    static UriHandlerSelection ByExecutableFileName(std::wstring fileName)
    {
        return {UriHandlerSelector::ExecutableFileName, std::move(fileName)};
    }

    static UriHandlerSelection ByAppUserModelId(std::wstring aumid)
    {
        return {UriHandlerSelector::AppUserModelId, std::move(aumid)};
    }

    static UriHandlerSelection ByProgId(std::wstring progId)
    {
        return {UriHandlerSelector::ProgId, std::move(progId)};
    }

    bool IsDefault() const noexcept
    {
        return selector == UriHandlerSelector::Default;
    }
};

// What a selected handler resolves to: the ProgId that drives ShellExecuteExW's
// SEE_MASK_CLASSNAME override, plus the same executablePath/packageFamilyName shape
// ResolvedLaunchTarget already uses, so a selected handler can be validated by the same
// LaunchTargetPolicy as the default one.
struct ResolvedUriHandler
{
    std::wstring progId;
    std::wstring executablePath;
    std::wstring packageFamilyName;
};

namespace details
{
    // Does 'handler' match 'selection'? Each selector already states what kind of
    // identifier it is comparing, so the comparison is decided by the selector alone -
    // there is no need (and no reliable way) to guess the *shape* of GetName()'s answer
    // from its content. In particular, a bare '!' check is not a safe test for "this is
    // a packaged AUMID": packaged AUMIDs always contain one, but an unpackaged app can
    // register an explicit AppUserModelID with no '!' at all (e.g. Word's real,
    // unpackaged AppUserModelID is "Microsoft.Office.WINWORD.EXE.15") - so absence of
    // '!' says nothing about whether the caller meant to select by path or by
    // AppUserModelId.
    inline bool UriHandlerMatchesSelection(IAssocHandler* handler, UriHandlerSelection const& selection) noexcept
    {
        if (selection.selector == UriHandlerSelector::ProgId)
        {
            wil::com_ptr<IObjectWithProgID> objectWithProgId;
            wil::unique_cotaskmem_string progId;
            return SUCCEEDED(handler->QueryInterface(IID_PPV_ARGS(&objectWithProgId))) &&
                   SUCCEEDED(objectWithProgId->GetProgID(&progId)) &&
                   EqualsIgnoreCase(selection.value, progId.get());
        }

        wil::unique_cotaskmem_string name;
        if (FAILED(handler->GetName(&name)))
        {
            return false;
        }
        const std::wstring_view nameView{name.get()};

        switch (selection.selector)
        {
        case UriHandlerSelector::AppUserModelId:
        case UriHandlerSelector::ExecutablePath:
            return EqualsIgnoreCase(selection.value, nameView);
        case UriHandlerSelector::ExecutableFileName:
            return EqualsIgnoreCase(GetFileNamePart(selection.value), GetFileNamePart(nameView));
        default:
            return false;
        }
    }

    // Returns the executablePath/packageFamilyName half of a matched handler, layered
    // onto whatever 'resolved' already carries (its progId). Which field to fill is
    // taken from 'selection' - the same reasoning as above: the selector already says
    // what kind of name this is, so there is nothing to detect. Only ProgId leaves it
    // genuinely ambiguous (a ProgId can name either a packaged or classic handler), so
    // that is the one case a '!' is used as a best-effort guess.
    inline ResolvedUriHandler FillResolvedUriHandlerTarget(
        IAssocHandler* handler, UriHandlerSelection const& selection, ResolvedUriHandler resolved) noexcept
    {
        wil::unique_cotaskmem_string name;
        if (FAILED(handler->GetName(&name)))
        {
            return resolved;
        }
        const std::wstring_view nameView{name.get()};

        switch (selection.selector)
        {
        case UriHandlerSelector::AppUserModelId:
            resolved.packageFamilyName = std::wstring(nameView);
            return resolved;
        case UriHandlerSelector::ExecutablePath:
        case UriHandlerSelector::ExecutableFileName:
            resolved.executablePath = std::wstring(nameView);
            return resolved;
        default:
            break;
        }

        // ProgId: the selector doesn't say which shape to expect, so fall back to the
        // one distinguishing fact that does hold: a packaged AUMID always contains '!'.
        const auto bang = nameView.find(L'!');
        if (bang != std::wstring_view::npos)
        {
            resolved.packageFamilyName = std::wstring(nameView.substr(0, bang));
        }
        else
        {
            resolved.executablePath = std::wstring(nameView);
        }
        return resolved;
    }
} // namespace details

// Find the one application, among every application registered for 'scheme', that
// matches 'selection'. A Try, like the rest of association lookup: a selector that
// names nothing currently registered is an ordinary "not found", not an error - the
// selected app may simply not be installed.
inline std::optional<ResolvedUriHandler> TryFindUriSchemeHandler(
    PCWSTR scheme, UriHandlerSelection const& selection) noexcept
{
    if (selection.IsDefault())
    {
        return std::nullopt;
    }

    wil::com_ptr<IEnumAssocHandlers> enumHandlers;
    if (FAILED(SHAssocEnumHandlersForProtocolByApplication(scheme, IID_PPV_ARGS(&enumHandlers))))
    {
        return std::nullopt;
    }

    wil::com_ptr<IAssocHandler> handler;
    ULONG fetched = 0;
    while ((enumHandlers->Next(1, handler.put(), &fetched) == S_OK) && (fetched == 1))
    {
        auto current = std::move(handler);
        handler = nullptr;

        if (details::UriHandlerMatchesSelection(current.get(), selection))
        {
            wil::com_ptr<IObjectWithProgID> objectWithProgId;
            wil::unique_cotaskmem_string progId;
            if (FAILED(current->QueryInterface(IID_PPV_ARGS(&objectWithProgId))) ||
                FAILED(objectWithProgId->GetProgID(&progId)))
            {
                // No ProgId means nothing to hand ShellExecuteExW as SEE_MASK_CLASSNAME -
                // this handler cannot be selected, even though it matched.
                continue;
            }

            ResolvedUriHandler resolved;
            resolved.progId = progId.get();
            return details::FillResolvedUriHandlerTarget(current.get(), selection, std::move(resolved));
        }
    }
    return std::nullopt;
}

// The policy.

enum class LaunchTargetMatch
{
    None,                   // unconstrained - the status quo, and the hijackable case
    ProcessIdAndSequence,   // exactly one live process instance (the request/response leg)
    ProcessIdOrExecutablePath, // exact process, with an explicit path fallback
    ExecutablePath,         // one specific binary, by full path
    ExecutableFileName,     // any binary with this file name ("only launch explorer.exe")
    PackageFamilyName,      // a packaged target selected by package family name
};

// What the launch actually resolved to. Path-only policies need no live process, so
// 'runningProcess' is optional.
struct ResolvedLaunchTarget
{
    std::wstring executablePath;
    std::wstring packageFamilyName;
    std::optional<ProcessIdentity> runningProcess;
};

struct LaunchTargetPolicy
{
    LaunchTargetMatch match{LaunchTargetMatch::None};
    ProcessIdentity requiredProcess;    // ProcessIdAndSequence
    std::wstring requiredPath;          // ExecutablePath / ExecutableFileName
    std::wstring requiredPackageFamilyName;

    static LaunchTargetPolicy Unconstrained() noexcept
    {
        return {};
    }

    // Pin the launch to one live process instance. This is the request/response case:
    // the requester captures its own identity and the responder must match it exactly.
    static LaunchTargetPolicy PinToProcess(ProcessIdentity const& identity)
    {
        LaunchTargetPolicy policy;
        policy.match = LaunchTargetMatch::ProcessIdAndSequence;
        policy.requiredProcess = identity;
        return policy;
    }

    static LaunchTargetPolicy PinToProcessOrExecutablePath(
        ProcessIdentity const& identity, std::wstring path)
    {
        LaunchTargetPolicy policy = PinToProcess(identity);
        policy.match = LaunchTargetMatch::ProcessIdOrExecutablePath;
        policy.requiredPath = std::move(path);
        return policy;
    }

    static LaunchTargetPolicy RequireExecutablePath(std::wstring path)
    {
        LaunchTargetPolicy policy;
        policy.match = LaunchTargetMatch::ExecutablePath;
        policy.requiredPath = std::move(path);
        return policy;
    }

    // Looser than a full path: any binary with this name satisfies it. Callers that can
    // name a path should prefer RequireExecutablePath - a file name says nothing about
    // which directory the binary came from.
    static LaunchTargetPolicy RequireExecutableFileName(std::wstring fileName)
    {
        LaunchTargetPolicy policy;
        policy.match = LaunchTargetMatch::ExecutableFileName;
        policy.requiredPath = std::move(fileName);
        return policy;
    }

    static LaunchTargetPolicy RequirePackageFamilyName(std::wstring packageFamilyName)
    {
        LaunchTargetPolicy policy;
        policy.match = LaunchTargetMatch::PackageFamilyName;
        policy.requiredPackageFamilyName = std::move(packageFamilyName);
        return policy;
    }

    // Does this target satisfy the policy? A bool, because that is the entire question -
    // an HRESULT here would imply the caller should distinguish kinds of "no", and there
    // is only one kind: the target is not the one that was permitted.
    bool IsSatisfiedBy(ResolvedLaunchTarget const& target) const noexcept
    {
        switch (match)
        {
        case LaunchTargetMatch::None:
            return true;

        case LaunchTargetMatch::ProcessIdAndSequence:
            return target.runningProcess.has_value() &&
                   requiredProcess.SameProcessInstance(*target.runningProcess);

        case LaunchTargetMatch::ProcessIdOrExecutablePath:
            return (target.runningProcess.has_value() &&
                    requiredProcess.SameProcessInstance(*target.runningProcess)) ||
                   EqualsIgnoreCase(requiredPath, target.executablePath);

        case LaunchTargetMatch::ExecutablePath:
            // Compared whole, so a suffix like "c:\evil\notepad.exe" can never satisfy a
            // policy naming "c:\windows\system32\notepad.exe".
            return EqualsIgnoreCase(requiredPath, target.executablePath);

        case LaunchTargetMatch::ExecutableFileName:
            // Compared against the file name *component*, never as a string suffix -
            // otherwise "explorer.exe" would be satisfied by "c:\evil\notexplorer.exe".
            return EqualsIgnoreCase(GetFileNamePart(requiredPath), GetFileNamePart(target.executablePath));

        case LaunchTargetMatch::PackageFamilyName:
            return !requiredPackageFamilyName.empty() &&
                   EqualsIgnoreCase(requiredPackageFamilyName, target.packageFamilyName);
        }
        return false;
    }

    HRESULT Validate(ResolvedLaunchTarget const& target) const noexcept
    {
        return IsSatisfiedBy(target) ? S_OK : E_ACCESSDENIED;
    }
};

// The launch.

// Why a resolved target may be unusable. Refusal is a normal outcome here, not an error
// condition - "the policy said no" and "the machine could not answer" are different
// answers and callers act on them differently, so they are distinct values rather than
// two HRESULTs a caller has to know how to tell apart.
enum class LaunchTargetStatus
{
    Allowed,            // resolved, and the policy accepts it
    Refused,            // resolved, and the policy rejects it - the mitigation firing
    Unverifiable,       // the launch path did not expose the process needed by the policy
    NoHandler,          // the scheme has no registered handler
    NoLiveTarget,       // a live-process policy was given no peer identity
    LaunchFailed,       // the policy accepted the target, but the OS-level launch itself
                        // failed (a missing file, a half-uninstalled handler) - an
                        // ordinary environmental outcome, not a caller bug, so it is a
                        // status like the others rather than a thrown HRESULT
};

// The outcome of resolving a launch. Carries its own status, so "didn't resolve" is
// expressed by the result itself rather than by an out-param plus an HRESULT.
struct TargetedLaunchDecision
{
    LaunchTargetStatus status{LaunchTargetStatus::NoHandler};
    ResolvedLaunchTarget target;

    bool IsAllowed() const noexcept
    {
        return status == LaunchTargetStatus::Allowed;
    }

    explicit operator bool() const noexcept
    {
        return IsAllowed();
    }
};

struct LaunchSiteObservations;

inline LaunchTargetStatus LaunchUriWithSiteEnforcedTarget(
    PCWSTR uri,
    LaunchTargetPolicy const& policy,
    _Out_opt_ LaunchSiteObservations* observations,
    bool untrustedSource,
    UriHandlerSelection const& handlerSelection = UriHandlerSelection::Default());

// Resolve the uri's handler and check it against the policy *before* anything is
// launched. 'liveTarget' supplies the peer process for ProcessIdAndSequence policies
// (from the COM caller, the parent process, a HANDLE, an HWND, or an explicit pid).
// 'handlerSelection' picks a specific registered app rather than the scheme's default -
// see TryFindUriSchemeHandler above. It composes with the path-based policies (the
// selected app still has to satisfy them), and is ignored for the live-process matches,
// which are answered from 'liveTarget' rather than the registration.
//
// The uri is the caller's own argument, so a null or scheme-less one is a usage error and
// throws. It is not a LaunchTargetStatus: the statuses classify what the machine could
// answer about a well-formed request, and mixing "you called this wrong" into that set
// would let a caller bug read as a security outcome.
inline TargetedLaunchDecision ResolveTargetedUriLaunch(
    PCWSTR uri,
    LaunchTargetPolicy const& policy,
    std::optional<ProcessIdentity> const& liveTarget = std::nullopt,
    UriHandlerSelection const& handlerSelection = UriHandlerSelection::Default())
{
    THROW_HR_IF_NULL(E_INVALIDARG, uri);
    const std::wstring_view uriView{uri};
    const auto colon = uriView.find(L':');
    THROW_HR_IF(E_INVALIDARG, colon == std::wstring_view::npos);

    try
    {
        TargetedLaunchDecision decision;
        const std::wstring scheme(uriView.substr(0, colon));

        // A caller-named app is resolved once, up front: if it names nothing currently
        // registered for this scheme, that is NoHandler regardless of what the policy
        // is - the caller asked for a specific app, not "whatever satisfies the policy".
        std::optional<ResolvedUriHandler> selectedHandler;
        if (!handlerSelection.IsDefault())
        {
            selectedHandler = TryFindUriSchemeHandler(scheme.c_str(), handlerSelection);
            if (!selectedHandler)
            {
                decision.status = LaunchTargetStatus::NoHandler;
                return decision;
            }
        }

        if ((policy.match == LaunchTargetMatch::ProcessIdAndSequence) ||
            (policy.match == LaunchTargetMatch::PackageFamilyName))
        {
            // A live-process policy is answered by the peer's identity, not by the
            // registration - the response must reach that instance, whatever handles it.
            if (!liveTarget)
            {
                decision.status = (policy.match == LaunchTargetMatch::PackageFamilyName)
                    ? LaunchTargetStatus::Unverifiable
                    : LaunchTargetStatus::NoLiveTarget;
                return decision;
            }
            decision.target.runningProcess = liveTarget;
            decision.target.executablePath = liveTarget->executablePath;
            decision.target.packageFamilyName = liveTarget->packageFamilyName;
        }
        else if (selectedHandler)
        {
            // The caller-selected handler stands in for the default association lookup
            // below - it names exactly the app the launch was asked to invoke.
            decision.target.executablePath = selectedHandler->executablePath;
            decision.target.packageFamilyName = selectedHandler->packageFamilyName;
            decision.target.runningProcess = liveTarget;
        }
        else
        {
            // Path policies are answered by the association system: which .exe would
            // ShellExecute hand this uri to?
            auto handlerPath = TryGetUriSchemeHandlerExecutablePath(scheme.c_str());
            if (!handlerPath)
            {
                decision.status = LaunchTargetStatus::NoHandler;
                return decision;
            }
            decision.target.executablePath = std::move(*handlerPath);
            decision.target.runningProcess = liveTarget;
        }

        decision.status = policy.IsSatisfiedBy(decision.target)
            ? LaunchTargetStatus::Allowed
            : LaunchTargetStatus::Refused;
        return decision;
    }
    catch (...)
    {
        return {};
    }
}

// Validate, then launch. 'dryRun' stops after validation so the decision can be tested
// without spawning anything. The result is a status, not a thrown exception: a refusal
// or a missing handler is an ordinary registration-driven outcome - the same kind of
// thing this mitigation exists to police - and a caller must be able to check for it
// without a try/catch. Only a malformed uri throws, from ResolveTargetedUriLaunch, since
// that is the caller's own usage error rather than anything the machine reported.
inline LaunchTargetStatus LaunchUriWithTarget(
    PCWSTR uri,
    LaunchTargetPolicy const& policy,
    std::optional<ProcessIdentity> const& liveTarget = std::nullopt,
    bool dryRun = false,
    UriHandlerSelection const& handlerSelection = UriHandlerSelection::Default())
{
    auto decision = ResolveTargetedUriLaunch(uri, policy, liveTarget, handlerSelection);
    if (decision.status != LaunchTargetStatus::Allowed)
    {
        return decision.status;
    }
    if (dryRun)
    {
        return LaunchTargetStatus::Allowed;
    }

    return LaunchUriWithSiteEnforcedTarget(uri, policy, nullptr, false, handlerSelection);
}

// Enforcing the policy inside ShellExecuteExW, via the site chain.
//
// Pre-resolving the handler with AssocQueryString (above) answers "what would
// ShellExecute pick?", but it is a *separate* lookup from the one ShellExecute actually
// performs. That leaves a gap: the two can disagree (a re-registration in between), and
// the association answer is an unexpanded registration string, not the real target.
//
// The site chain closes that gap. Passing a site to ShellExecuteExW (via
// SEE_MASK_FLAG_HINST_IS_SITE, with the site in hInstApp) lets the shell call back into
// the caller at each internal decision point, *before* the launch commits:
//
//   IHandlerActivationHost::BeforeCoCreateInstance - the handler is a COM handler
//       (DelegateExecute / DropTarget). Yields the CLSID and an IHandlerInfo.
//   IHandlerActivationHost::BeforeCreateProcess    - the handler is a command line.
//       Yields the fully expanded application path and the real command line - the
//       exact values the shell is about to use, not a registration template.
//   ICreatingProcess::OnCreating                   - last stop before CreateProcess.
//       ICreateProcessInputs exposes (and can rewrite) the application path, command
//       line and startup flags.
//
// Returning a failure HRESULT from any of these cancels the launch, and that failure
// surfaces from ShellExecuteExW. That is the enforcement point: the constraint is
// checked against the shell's own resolved target, and a violation stops the launch
// before any process exists.
//
// IHandlerInfo is also a service provider: QueryService(SID_CtxQueryAssociations) hands
// back the association object for the *specific* handler being invoked, so per-handler
// registration (LocalOnly, EditFlags, MinimumAllowedUrlZone) can be read at decision
// time rather than looked up separately.

// What the site observed and decided. Kept separate from the site so it outlives the
// launch call and can be inspected afterwards. Defined below, after ComServerBinary.
struct LaunchSiteObservations;

// How a COM handler's CLSID is hosted, which determines what a path policy can even
// mean for it.
enum class ComServerHosting
{
    None,
    LocalServer,        // LocalServer32 - its own .exe
    InProcServer,       // InProcServer32 - a .dll, loaded into someone else's process
    Surrogate,          // InProcServer32 + AppID/DllSurrogate - a .dll in a surrogate host
    PackagedExe,        // PackagedCom - an .exe server inside an MSIX package
    PackagedInProc,     // PackagedCom - a .dll server inside an MSIX package
};

struct ComServerBinary
{
    ComServerHosting hosting{ComServerHosting::None};
    std::wstring binaryPath;        // the .exe or .dll registered for the class
    std::wstring surrogatePath;     // the host .exe when hosting == Surrogate
    std::wstring appId;             // the class's AppID, when it has one
    std::wstring packageFullName;   // the declaring package, for the packaged cases

    bool IsPackaged() const noexcept
    {
        return (hosting == ComServerHosting::PackagedExe) || (hosting == ComServerHosting::PackagedInProc);
    }

    // The process a path policy should be judged against. An in-proc server has no
    // process of its own, so there is nothing to pin - that case is reported empty and
    // must be refused rather than guessed at.
    std::wstring const& PathToEnforce() const noexcept
    {
        static const std::wstring empty;
        switch (hosting)
        {
        case ComServerHosting::LocalServer:
        case ComServerHosting::PackagedExe:  return binaryPath;
        case ComServerHosting::Surrogate:    return surrogatePath;
        case ComServerHosting::PackagedInProc:
            return surrogatePath.empty() ? empty : surrogatePath;
        default:                             return empty;
        }
    }
};

// What the site observed and decided. Kept separate from the site so it outlives the
// launch call and can be inspected afterwards.
struct LaunchSiteObservations
{
    bool sawCreateProcess{};
    bool sawCoCreateInstance{};
    std::wstring applicationPath;   // fully expanded, as the shell resolved it
    std::wstring commandLine;
    CLSID handlerClsid{};
    ComServerBinary comServer;      // how that CLSID is hosted, when it is a COM handler
    bool handlerIsLocalOnly{};
    std::wstring handlerPackageFamilyName;  // from IHandlerInfo2::GetApplicationId, when packaged
    bool probeCancelled{};          // a probe launch was stopped before it committed
    HRESULT decision{S_OK};         // the failure returned to the shell, or S_OK
};

namespace details
{
    // Registered server paths are command lines and may be REG_EXPAND_SZ, so the value
    // is expanded and then argv[0] is taken.
    //
    // The unquoted form is genuinely ambiguous: "C:\Program Files\App\a.exe /Automation"
    // has a space inside the path *and* a space before its argument. Splitting at the
    // first space truncates to "C:\Program", which would silently produce a wrong path
    // for a security decision. So each space is tried as a candidate break, longest
    // first, and the first prefix that names an existing file wins. Falling back to the
    // whole string (rather than the first token) keeps a failure visibly wrong instead
    // of plausibly wrong.
    inline std::wstring ExtractExecutableFromCommand(std::wstring_view command)
    {
        while (!command.empty() && (command.front() == L' '))
        {
            command.remove_prefix(1);
        }

        if (!command.empty() && (command.front() == L'"'))
        {
            const auto closing = command.find(L'"', 1);
            return std::wstring(
                (closing == std::wstring_view::npos) ? command.substr(1) : command.substr(1, closing - 1));
        }

        // No arguments at all is the common case and needs no probing.
        if (command.find(L' ') == std::wstring_view::npos)
        {
            return std::wstring(command);
        }

        for (auto space = command.find_last_of(L' '); space != std::wstring_view::npos;
             space = (space == 0) ? std::wstring_view::npos : command.find_last_of(L' ', space - 1))
        {
            const auto candidate = std::wstring(command.substr(0, space));
            if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
            {
                return candidate;
            }
        }

        return std::wstring(command);
    }

    inline std::optional<std::wstring> TryReadClassRegistryString(
        PCWSTR clsidText, PCWSTR subKeyLeaf, PCWSTR valueName) noexcept try
    {
        std::wstring subKey = L"CLSID\\";
        subKey += clsidText;
        if (subKeyLeaf)
        {
            subKey += L'\\';
            subKey += subKeyLeaf;
        }

        // try_get_value_expanded_string expands REG_EXPAND_SZ and reports a missing key
        // or value as an empty optional rather than as an error - which is the common
        // case here, since most classes have no LocalServer32 and no AppID.
        auto stored = wil::reg::try_get_value_expanded_string(HKEY_CLASSES_ROOT, subKey.c_str(), valueName);
        if (!stored || stored->empty())
        {
            return std::nullopt;
        }
        return stored;
    }
    catch (...)
    {
        return std::nullopt;
    }

    // AppID\{id} -> DllSurrogate. An empty value means the system surrogate
    // (dllhost.exe); a non-empty value names a custom surrogate executable.
    inline std::optional<std::wstring> TryResolveDllSurrogate(PCWSTR appId) noexcept try
    {
        std::wstring subKey = L"AppID\\";
        subKey += appId;

        // Present-but-empty is meaningful here (it selects the system surrogate), so the
        // value's existence and its emptiness are two different questions.
        auto stored = wil::reg::try_get_value_expanded_string(HKEY_CLASSES_ROOT, subKey.c_str(), L"DllSurrogate");
        if (!stored)
        {
            return std::nullopt;
        }

        std::wstring surrogatePath = ExtractExecutableFromCommand(stored->c_str());
        if (surrogatePath.empty())
        {
            // The default system surrogate. Resolved to a full path so it is subject to
            // the same whole-path comparison as any other target.
            wchar_t systemDirectory[MAX_PATH]{};
            if (GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory)) == 0)
            {
                return std::nullopt;
            }
            surrogatePath = std::wstring(systemDirectory) + L"\\dllhost.exe";
        }
        return surrogatePath;
    }
    catch (...)
    {
        return std::nullopt;
    }

    inline HRESULT GetPackagedComServerForPackage(
        PCWSTR packageFullName, PCWSTR clsidText, _Out_ ComServerBinary& server) noexcept;

    // Packaged COM is not registered under HKCR\CLSID at all - MSIX servers live in a
    // separate PackagedCom hive, keyed by package:
    //
    //   HKCR\PackagedCom\ClassIndex\{clsid}\<packageFullName>
    //   HKCR\PackagedCom\Package\<packageFullName>\Class\{clsid}   -> ServerId, DllPath
    //   HKCR\PackagedCom\Package\<packageFullName>\Server\<id>     -> Executable | DllPath
    //
    // The Executable value is *package relative*, so it is combined with the package's
    // installed location to produce the absolute path a policy is expressed in.
    inline HRESULT GetPackagedComServer(PCWSTR clsidText, _Out_ ComServerBinary& server) noexcept try
    {
        server = {};

        // ClassIndex maps the class to the package(s) that declare it.
        std::wstring indexKey = L"PackagedCom\\ClassIndex\\";
        indexKey += clsidText;

        wil::unique_hkey index;
        RETURN_IF_FAILED(wil::reg::open_unique_key_nothrow(
            HKEY_CLASSES_ROOT, indexKey.c_str(), index, wil::reg::key_access::read));

        // A class is commonly indexed under several package *versions*, only one of
        // which is actually installed - side-by-side registrations linger. Enumeration
        // order must not decide a security-relevant path, so every candidate is tried
        // and the one that resolves to a real installed location wins.
        for (const auto& keyData : wil::make_range(
                 wil::reg::key_iterator{index.get()}, wil::reg::key_iterator{}))
        {
            ComServerBinary candidate;
            if (SUCCEEDED(GetPackagedComServerForPackage(keyData.name.c_str(), clsidText, candidate)))
            {
                server = std::move(candidate);
                return S_OK;
            }
        }
        RETURN_HR(HRESULT_FROM_WIN32(ERROR_NOT_FOUND));
    }
    CATCH_RETURN();

    // Resolve the class within one specific package.
    inline HRESULT GetPackagedComServerForPackage(
        PCWSTR packageFullName, PCWSTR clsidText, _Out_ ComServerBinary& server) noexcept try
    {
        server = {};
        server.packageFullName = packageFullName;

        const std::wstring packageKey = std::wstring(L"PackagedCom\\Package\\") + packageFullName;

        // The class entry names the server that hosts it, and for an in-proc class it
        // also carries the dll. Read both: which one applies depends on the hosting.
        std::wstring classKey = packageKey + L"\\Class\\" + clsidText;
        const auto serverId = wil::reg::try_get_value<DWORD>(
            HKEY_CLASSES_ROOT, classKey.c_str(), L"ServerId");
        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), !serverId);

        const auto classDll = wil::reg::try_get_value_expanded_string(
            HKEY_CLASSES_ROOT, classKey.c_str(), L"DllPath");
        const bool haveClassDll = classDll.has_value();

        // The server entry carries the binary for an out-of-process server (Executable),
        // and identity/surrogate configuration. An in-proc class has neither an
        // Executable nor a DllPath here - its dll is the one on the Class key above.
        std::wstring serverKey = packageKey + L"\\Server\\" + std::to_wstring(*serverId);

        const auto executable = wil::reg::try_get_value_expanded_string(
            HKEY_CLASSES_ROOT, serverKey.c_str(), L"Executable");
        const auto dllPath = wil::reg::try_get_value_expanded_string(
            HKEY_CLASSES_ROOT, serverKey.c_str(), L"DllPath");
        const bool isExe = executable.has_value();
        std::wstring relative = isExe ? *executable : (dllPath ? *dllPath : L"");
        if (!isExe)
        {
            if (relative.empty())
            {
                RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_NOT_FOUND), !haveClassDll);
                relative = *classDll;
            }
        }

        // A packaged in-proc class can still be hosted out-of-process, in which case the
        // server entry names the identity the surrogate runs as. The host is the system
        // surrogate, so that is what a path policy would be judged against.
        std::wstring surrogateAppId;
        if (!isExe)
        {
            if (const auto appIdValue = wil::reg::try_get_value<std::wstring>(
                    HKEY_CLASSES_ROOT, serverKey.c_str(), L"SurrogateAppId"))
            {
                surrogateAppId = *appIdValue;
            }
        }

        // Package relative -> absolute, via the package's installed location.
        UINT32 pathChars = 0;
        std::wstring installLocation;
        const LONG sizeResult = GetPackagePathByFullName(packageFullName, &pathChars, nullptr);
        if (sizeResult == ERROR_INSUFFICIENT_BUFFER)
        {
            installLocation.resize(pathChars);
            RETURN_IF_WIN32_ERROR(GetPackagePathByFullName(packageFullName, &pathChars, installLocation.data()));
            installLocation.resize(pathChars ? pathChars - 1 : 0); // drop the terminator
        }
        else
        {
            RETURN_WIN32(sizeResult);
        }

        server.binaryPath = installLocation;
        server.binaryPath += L'\\';
        server.binaryPath += ExtractExecutableFromCommand(relative.c_str());
        server.hosting = isExe ? ComServerHosting::PackagedExe : ComServerHosting::PackagedInProc;

        if (!surrogateAppId.empty())
        {
            server.appId = surrogateAppId;
            wchar_t systemDirectory[MAX_PATH]{};
            if (GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory)) != 0)
            {
                server.surrogatePath = std::wstring(systemDirectory) + L"\\dllhost.exe";
            }
        }
        return S_OK;
    }
    CATCH_RETURN();
}

// Resolve a COM handler's CLSID to the binary that hosts it. This is the COM-handler
// counterpart of "uri scheme -> handler .exe": BeforeCoCreateInstance hands over a CLSID
// and nothing else, so the class registration is what turns it into a path a policy can
// be applied to.
//
// There is no COM API that answers this ("give me the server path for a CLSID"), so it
// is read from the registrations COM itself uses. Two hives, because packaged COM does
// not register under HKCR\CLSID:
//
//   classic - HKCR\CLSID\{clsid}\LocalServer32 | InProcServer32 (+ AppID\DllSurrogate)
//   packaged - HKCR\PackagedCom\... , keyed by package, with package-relative paths
//
// Classic is looked up first because a class registered in both places is served by the
// classic registration.
//
// LocalServer32 / PackagedExe are the cases that matter - an out-of-process handler has
// its own .exe, which is exactly what the path policies describe. In-proc servers are
// reported for completeness but yield no enforceable path unless a surrogate hosts them.
//
// An unresolvable CLSID is an ordinary answer, not an error - most CLSIDs on a machine
// are not what a caller is looking for, and a sweep across the registry (see the tests)
// makes that the common case rather than the exception. So this is a Try, like the
// uri-scheme resolver above, rather than an HRESULT a caller would have to check.
inline std::optional<ComServerBinary> TryGetComServerBinaryFromClsid(REFCLSID clsid) noexcept try
{
    ComServerBinary server;

    wchar_t clsidText[64]{};
    if (StringFromGUID2(clsid, clsidText, ARRAYSIZE(clsidText)) == 0)
    {
        return std::nullopt;
    }

    // The class's AppID, when present, is what carries surrogate and identity config.
    if (const auto value = details::TryReadClassRegistryString(clsidText, nullptr, L"AppID"))
    {
        server.appId = *value;
    }

    if (const auto registered = details::TryReadClassRegistryString(clsidText, L"LocalServer32", nullptr))
    {
        server.hosting = ComServerHosting::LocalServer;
        server.binaryPath = details::ExtractExecutableFromCommand(*registered);
        return server;
    }

    if (const auto registered = details::TryReadClassRegistryString(clsidText, L"InProcServer32", nullptr))
    {
        server.hosting = ComServerHosting::InProcServer;
        server.binaryPath = details::ExtractExecutableFromCommand(*registered);

        // A surrogate turns an in-proc server back into an out-of-process one, which
        // restores an enforceable host path.
        if (!server.appId.empty())
        {
            if (const auto surrogate = details::TryResolveDllSurrogate(server.appId.c_str()))
            {
                server.surrogatePath = *surrogate;
                server.hosting = ComServerHosting::Surrogate;
            }
        }
        return server;
    }

    // Not classic - try packaged. The packaged lookup sets its own AppID when the class
    // is surrogate-hosted, so the classic value is only restored if it found none.
    const std::wstring savedAppId = server.appId;
    if (SUCCEEDED(details::GetPackagedComServer(clsidText, server)))
    {
        if (server.appId.empty())
        {
            server.appId = savedAppId;
        }
        return server;
    }

    return std::nullopt;
}
catch (...)
{
    return std::nullopt;
}

// Read the LocalOnly marker off the handler that is about to be invoked. IHandlerInfo's
// association object describes *that* handler, so this answers the per-handler question
// the README raises - the same scheme handled by two apps can differ.
inline bool IsHandlerLocalOnly(_In_opt_ IHandlerInfo* handlerInfo) noexcept
{
    if (auto serviceProvider = wil::try_com_query_nothrow<IServiceProvider>(handlerInfo))
    {
        wil::com_ptr<IQueryAssociations> queryAssoc;
        if (SUCCEEDED(serviceProvider->QueryService(SID_CtxQueryAssociations, IID_PPV_ARGS(&queryAssoc))))
        {
            return SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_VALUE, L"LocalOnly", nullptr, nullptr));
        }
    }
    return false;
}

// A packaged verb's own registration carries an AppUserModelID (see any
// HKCR\AppX.../shell/<verb> key) - IHandlerInfo2::GetApplicationId hands back that same
// AUMID for the specific handler the shell is about to invoke, cheaper and more direct
// than re-deriving it from a resolved path. The family name is the AUMID's prefix, up to
// (not including) the '!'; the suffix names one app within the package and is not part
// of the family identity.
inline std::optional<std::wstring> TryGetHandlerPackageFamilyName(_In_opt_ IHandlerInfo* handlerInfo) noexcept try
{
    auto handlerInfo2 = wil::try_com_query_nothrow<IHandlerInfo2>(handlerInfo);
    if (!handlerInfo2)
    {
        return std::nullopt;
    }

    wil::unique_cotaskmem_string applicationId;
    if (FAILED(handlerInfo2->GetApplicationId(&applicationId)) || !applicationId)
    {
        return std::nullopt;
    }

    const std::wstring_view aumid{applicationId.get()};
    const auto bang = aumid.find(L'!');
    if (bang == std::wstring_view::npos)
    {
        // No '!' means this isn't an AUMID shape at all - not a packaged handler.
        return std::nullopt;
    }
    return std::wstring{aumid.substr(0, bang)};
}
catch (...)
{
    return std::nullopt;
}

// The site handed to ShellExecuteExW. Every callback validates the shell's own resolved
// target against the policy and fails the call to cancel.
//
// The same site serves two modes. In Enforce mode a violation cancels and everything
// else proceeds. In Probe mode *every* launch is cancelled after the target has been
// recorded - a deliberate fake launch, run only to harvest what the shell resolved.
enum class LaunchSiteMode
{
    Enforce,
    Probe,
};

class TargetedLaunchSite : public winrt::implements<TargetedLaunchSite,
    IServiceProvider, IHandlerActivationHost, ICreatingProcess>
{
public:
    TargetedLaunchSite(LaunchTargetPolicy policy, LaunchSiteObservations* observations,
                       LaunchSiteMode mode = LaunchSiteMode::Enforce) :
        m_policy(std::move(policy)), m_observations(observations), m_mode(mode)
    {
    }

    IFACEMETHODIMP QueryService(REFGUID serviceId, REFIID riid, _COM_Outptr_ void** ppv) noexcept override
    {
        *ppv = nullptr;
        return ((serviceId == SID_SHandlerActivationHost) ||
                (serviceId == SID_ExecuteCreatingProcess))
            ? QueryInterface(riid, ppv) : E_NOTIMPL;
    }

    // The COM handler case. The CLSID is resolved to its hosting executable so the same
    // path policy applies whether the scheme dispatches to a process or to a handler.
    IFACEMETHODIMP BeforeCoCreateInstance(REFCLSID clsidHandler, _In_opt_ IShellItemArray*,
                                          _In_opt_ IHandlerInfo* handlerInfo) noexcept override
    {
        m_observations->sawCoCreateInstance = true;
        m_observations->handlerClsid = clsidHandler;
        m_observations->handlerIsLocalOnly = IsHandlerLocalOnly(handlerInfo);

        auto server = TryGetComServerBinaryFromClsid(clsidHandler);
        m_observations->comServer = server.value_or(ComServerBinary{});

        ResolvedLaunchTarget target;
        target.executablePath = server ? server->PathToEnforce() : std::wstring{};
        m_observations->applicationPath = target.executablePath;
        if (auto packageFamilyName = TryGetHandlerPackageFamilyName(handlerInfo))
        {
            target.packageFamilyName = std::move(*packageFamilyName);
            m_observations->handlerPackageFamilyName = target.packageFamilyName;
        }

        if (m_mode == LaunchSiteMode::Probe)
        {
            return Cancelled();
        }
        if (m_policy.match == LaunchTargetMatch::PackageFamilyName)
        {
            // The AUMID names the family directly - no need for the .exe path at all,
            // and this is the only site hook that can see a purely in-proc handler.
            return Record(m_policy.Validate(target));
        }
        if (target.executablePath.empty())
        {
            // An in-proc handler has no process of its own, so a path policy cannot be
            // satisfied - refuse rather than let it through unchecked.
            return Record(m_policy.match == LaunchTargetMatch::None ? S_OK : E_ACCESSDENIED);
        }
        return (m_policy.match == LaunchTargetMatch::ProcessIdAndSequence)
            ? S_OK
            : Record(m_policy.Validate(target));
    }

    // The command line case. applicationPath is fully expanded - this is the value the
    // path policies are meant to be judged against.
    IFACEMETHODIMP BeforeCreateProcess(PCWSTR applicationPath, PCWSTR commandLine,
                                       _In_opt_ IHandlerInfo* handlerInfo) noexcept override
    {
        m_observations->sawCreateProcess = true;
        m_observations->applicationPath = applicationPath ? applicationPath : L"";
        m_observations->commandLine = commandLine ? commandLine : L"";
        m_observations->handlerIsLocalOnly = IsHandlerLocalOnly(handlerInfo);

        ResolvedLaunchTarget target;
        target.executablePath = m_observations->applicationPath;
        if (auto packageFamilyName = TryGetHandlerPackageFamilyName(handlerInfo))
        {
            target.packageFamilyName = std::move(*packageFamilyName);
            m_observations->handlerPackageFamilyName = target.packageFamilyName;
        }

        if (m_mode == LaunchSiteMode::Probe)
        {
            return Cancelled();
        }

        if (m_policy.match == LaunchTargetMatch::ProcessIdAndSequence)
        {
            return S_OK;
        }

        return Record(m_policy.Validate(target));
    }

    // Last stop before CreateProcess. Also where the launch is tagged as coming from an
    // untrusted source, which the target can read from its STARTUPINFOW.
    IFACEMETHODIMP OnCreating(_In_ ICreateProcessInputs* inputs) noexcept override
    {
        if ((m_policy.match == LaunchTargetMatch::ProcessIdAndSequence) ||
            (m_policy.match == LaunchTargetMatch::ProcessIdOrExecutablePath))
        {
            RETURN_IF_FAILED(inputs->AddCreateFlags(CREATE_SUSPENDED));
        }
        if (m_untrustedSource)
        {
            RETURN_IF_FAILED(inputs->AddStartupFlags(STARTF_UNTRUSTEDSOURCE));
        }
        // A backstop: if the earlier hooks were somehow not reached, a probe still must
        // not start anything.
        return (m_mode == LaunchSiteMode::Probe) ? Cancelled() : S_OK;
    }

    void SetUntrustedSource(bool untrusted) noexcept
    {
        m_untrustedSource = untrusted;
    }

    IUnknown* GetAsSite() noexcept
    {
        return static_cast<IServiceProvider*>(this);
    }

private:
    HRESULT Cancelled() noexcept
    {
        m_observations->probeCancelled = true;
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }

    HRESULT Record(HRESULT hr) noexcept
    {
        if (FAILED(hr))
        {
            m_observations->decision = hr;
        }
        return hr;
    }

    LaunchTargetPolicy m_policy;
    LaunchSiteObservations* m_observations;
    LaunchSiteMode m_mode;
    bool m_untrustedSource{};
};

// Launch a uri with the policy enforced from inside ShellExecuteExW. Unlike
// LaunchUriWithTarget, the constraint is checked against the shell's own resolved
// target. SEE_MASK_NOASYNC keeps the callbacks on this thread and makes the cancellation
// observable before this returns. The result is a status, not a thrown HRESULT: a
// refusal, a vanished handler selection, or an OS-level launch failure are all ordinary
// registration- or environment-driven outcomes - exactly what a caller must be able to
// check without a try/catch, since the whole point of this mitigation is defending
// against a bad or hostile app registration, not treating one as a programming error.
// 'observations->decision' carries the underlying HRESULT for a caller that wants the
// detail (which callback cancelled it, or the raw Win32 launch failure).
//
// 'handlerSelection' asks ShellExecuteExW to resolve a specific registered app instead
// of the scheme's default, via SEE_MASK_CLASSNAME/lpClass - the same mechanism the
// shell's own "Open with" picker uses to force a non-default choice. It is resolved to a
// ProgId independently here, immediately before the call: that keeps this function's only
// job as "drive ShellExecuteExW", and the resolution is authoritative anyway, since the
// site chain below still judges whatever the shell actually does with it.
inline LaunchTargetStatus LaunchUriWithSiteEnforcedTarget(
    PCWSTR uri,
    LaunchTargetPolicy const& policy,
    _Out_opt_ LaunchSiteObservations* observations = nullptr,
    bool untrustedSource = false,
    UriHandlerSelection const& handlerSelection)
{
    LaunchSiteObservations local;
    auto& sink = observations ? *observations : local;
    sink = {};

    auto site = winrt::make_self<TargetedLaunchSite>(policy, &sink);
    site->SetUntrustedSource(untrustedSource);

    SHELLEXECUTEINFOW info{sizeof(info)};
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_FLAG_HINST_IS_SITE;
    info.lpFile = uri;
    info.nShow = SW_NORMAL;
    info.hInstApp = reinterpret_cast<HINSTANCE>(site->GetAsSite());

    std::optional<ResolvedUriHandler> selectedHandler;
    if (!handlerSelection.IsDefault())
    {
        const std::wstring_view uriView{uri};
        const auto colon = uriView.find(L':');
        if (colon != std::wstring_view::npos)
        {
            const std::wstring scheme(uriView.substr(0, colon));
            selectedHandler = TryFindUriSchemeHandler(scheme.c_str(), handlerSelection);
        }
        // Not found here is not a fresh failure - ResolveTargetedUriLaunch already
        // rejected an unresolvable selection with NoHandler before this was ever called.
        // Falling through to the default here would silently launch the wrong app, so a
        // vanished selection instead fails the same way an unregistered scheme does: a
        // status, since the registration changing underneath the caller is an ordinary
        // race, not a bug in the caller's own code.
        if (!selectedHandler || selectedHandler->progId.empty())
        {
            sink.decision = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            return LaunchTargetStatus::NoHandler;
        }
        info.fMask |= SEE_MASK_CLASSNAME;
        info.lpClass = selectedHandler->progId.c_str();
    }

    if (!ShellExecuteExW(&info))
    {
        // A cancellation is reported as our own decision, not as a generic shell error,
        // so callers can tell "policy refused this" from "the launch failed". Either way
        // this is an environmental outcome - a missing file, a half-uninstalled handler,
        // or the mitigation firing - not a programming error, so it is a status rather
        // than an exception.
        if (FAILED(sink.decision))
        {
            return LaunchTargetStatus::Refused;
        }
        sink.decision = HRESULT_FROM_WIN32(GetLastError());
        return LaunchTargetStatus::LaunchFailed;
    }

    // The shell can report success even though a callback failed; treat the recorded
    // decision as authoritative so a refusal is never reported as a successful launch.
    if (FAILED(sink.decision))
    {
        return LaunchTargetStatus::Refused;
    }
    return LaunchTargetStatus::Allowed;
}

// Probe: run a *fake* launch purely to discover what the shell would do.
//
// The site is put in Probe mode, so the target is recorded and then every callback
// cancels - nothing is ever created. This is a pre-resolution check that, unlike
// AssocQueryString, uses the shell's own resolution path: the same handler selection,
// the same fully expanded application path, the same command line, including the COM
// handler (DelegateExecute) case that an association string query cannot express.
//
// Use it to decide *before* committing: harvest the target, apply arbitrary caller logic
// to it, and only then launch. The launch itself should still carry an enforcing site -
// the probe's answer is a separate resolution and can go stale between the two calls
// (the same TOCTOU gap that makes the enforcing site the authoritative check).
//
// An unregistered scheme is an ordinary probe answer, not a failure: 'probeCancelled'
// tells the caller whether the shell reached a handler decision at all, so this returns
// the observations unconditionally rather than throwing for "nothing to report".
inline LaunchSiteObservations ProbeUriLaunchTarget(PCWSTR uri)
{
    LaunchSiteObservations observations;

    auto site = winrt::make_self<TargetedLaunchSite>(
        LaunchTargetPolicy::Unconstrained(), &observations, LaunchSiteMode::Probe);

    SHELLEXECUTEINFOW info{sizeof(info)};
    // SEE_MASK_NOASYNC keeps the callbacks on this thread, so the observations are
    // complete by the time ShellExecuteExW returns.
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_FLAG_HINST_IS_SITE;
    info.lpFile = uri;
    info.nShow = SW_NORMAL;
    info.hInstApp = reinterpret_cast<HINSTANCE>(site->GetAsSite());

    ShellExecuteExW(&info);

    return observations;
}

// The probe answer expressed as a target, so it can be fed to a policy directly.
// std::nullopt when the probe never reached a handler decision (an unregistered scheme)
// - an ordinary answer, not something to propagate as an exception.
inline std::optional<ResolvedLaunchTarget> ProbeResolvedLaunchTarget(PCWSTR uri)
{
    const auto observations = ProbeUriLaunchTarget(uri);
    if (!observations.probeCancelled || observations.applicationPath.empty())
    {
        return std::nullopt;
    }

    ResolvedLaunchTarget resolved;
    resolved.executablePath = observations.applicationPath;
    resolved.packageFamilyName = observations.handlerPackageFamilyName;
    return resolved;
}

} // namespace TargetedLaunch
