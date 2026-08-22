#include "pch.h"
#include "TargetedLaunch.h"

#include <atomic>
#include <thread>

#include <winrt/Windows.Foundation.h>

namespace cpp_unit = Microsoft::VisualStudio::CppUnitTestFramework;

using namespace TargetedLaunch;

namespace UriLaunchingSafetey
{

namespace
{
    // A malformed uri is the only failure left that throws (from ResolveTargetedUriLaunch) -
    // it is the caller's own usage error, not something the machine reported. Everything
    // else (a refusal, a missing handler, an OS-level launch failure) is reported through
    // LaunchTargetStatus / std::optional instead, since those are ordinary
    // registration-driven outcomes a defensive caller must be able to check without a
    // try/catch.
    template <typename Func>
    void AssertThrowsHr(HRESULT expected, Func&& func, PCWSTR message = nullptr)
    {
        try
        {
            func();
            cpp_unit::Assert::Fail(message ? message : L"expected an exception, none was thrown");
        }
        catch (wil::ResultException const& e)
        {
            cpp_unit::Assert::AreEqual(expected, e.GetErrorCode(), message);
        }
    }

    LRESULT CALLBACK TestWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) noexcept
    {
        return DefWindowProcW(window, message, wParam, lParam);
    }

    struct ScopedTestWindow
    {
        ATOM windowClass{};
        HWND window{};

        ScopedTestWindow()
        {
            static constexpr wchar_t className[] = L"TargetedLaunchTestWindow";
            WNDCLASSW windowClassData{};
            windowClassData.lpfnWndProc = TestWindowProc;
            windowClassData.hInstance = GetModuleHandleW(nullptr);
            windowClassData.lpszClassName = className;
            windowClass = RegisterClassW(&windowClassData);
            THROW_LAST_ERROR_IF_NULL(reinterpret_cast<void*>(windowClass));

            window = CreateWindowExW(
                0, className, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr,
                windowClassData.hInstance, nullptr);
            THROW_LAST_ERROR_IF_NULL(window);
        }

        ~ScopedTestWindow()
        {
            if (window)
            {
                DestroyWindow(window);
            }
            if (windowClass)
            {
                UnregisterClassW(L"TargetedLaunchTestWindow", GetModuleHandleW(nullptr));
            }
        }
    };

    // A stand-in "peer" process. Long-lived enough to be opened and identified, and
    // killed by the RAII wrapper so no test leaks a process.
    struct ScopedChildProcess
    {
        wil::unique_handle process;
        DWORD processId{};

        ScopedChildProcess() = default;
        ScopedChildProcess(ScopedChildProcess&&) = default;
        ScopedChildProcess& operator=(ScopedChildProcess&&) = default;

        static ScopedChildProcess Spawn()
        {
            wchar_t systemDirectory[MAX_PATH]{};
            THROW_IF_FAILED(SHGetFolderPathW(nullptr, CSIDL_SYSTEM, nullptr, 0, systemDirectory));
            std::wstring commandLine = std::wstring(systemDirectory) + L"\\cmd.exe /c pause";

            STARTUPINFOW startupInfo{sizeof(startupInfo)};
            PROCESS_INFORMATION processInfo{};
            THROW_IF_WIN32_BOOL_FALSE(CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr,
                FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, &processInfo));

            ScopedChildProcess child;
            child.process.reset(processInfo.hProcess);
            child.processId = processInfo.dwProcessId;
            CloseHandle(processInfo.hThread);
            return child;
        }

        ~ScopedChildProcess()
        {
            if (process)
            {
                TerminateProcess(process.get(), 0);
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Case 1: request/response - pin the response to the requesting process instance.
// ---------------------------------------------------------------------------
//
// This is the LaunchUriForResults shape assembled from two one-way uri launches. The
// requester records its own identity in the request; the responder pins the response
// launch to that identity so the reply can only be delivered to the process that asked
// for it.
TEST_CLASS(TargetedLaunchProcessInstance)
{
public:
    // The response reaches the requester when, and only when, the *same instance* is on
    // the other end.
    TEST_METHOD(ResponseIsDeliveredToTheRequestingInstance)
    {
        const auto requester = GetCurrentProcessIdentity();
        cpp_unit::Assert::IsTrue(requester.IsValid());

        // Carried in the request; the responder pins the reply to it.
        const auto policy = LaunchTargetPolicy::PinToProcess(requester);

        const auto decision =
            ResolveTargetedUriLaunch(L"local+app-response:result", policy, requester);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
        const auto& resolved = decision.target;
        cpp_unit::Assert::IsTrue(resolved.runningProcess.has_value());
        cpp_unit::Assert::AreEqual(requester.processId, resolved.runningProcess->processId);
    }

    // The hijack this exists to stop: some *other* live process tries to collect a
    // response addressed to the requester.
    TEST_METHOD(ResponseIsRefusedForADifferentProcess)
    {
        const auto requester = GetCurrentProcessIdentity();
        auto imposter = ScopedChildProcess::Spawn();

        const auto imposterIdentity = TryGetProcessIdentity(imposter.processId);
        cpp_unit::Assert::IsTrue(imposterIdentity.has_value());

        const auto policy = LaunchTargetPolicy::PinToProcess(requester);

        const auto decision =
            ResolveTargetedUriLaunch(L"local+app-response:result", policy, imposterIdentity);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Refused);
    }

    // The reason a pid is not an identity: after a pid is recycled, the pid still
    // matches but the instance does not. Simulated by keeping a real pid and pairing it
    // with a different sequence number, which is exactly what recycling produces.
    TEST_METHOD(ResponseIsRefusedWhenThePidWasRecycled)
    {
        const auto requester = GetCurrentProcessIdentity();

        cpp_unit::Assert::IsTrue(requester.sequenceNumber != 0,
            L"no process sequence number available - the pid-only match would be unsafe");

        ProcessIdentity recycled = requester;   // same pid...
        if (recycled.sequenceNumber != 0)
        {
            recycled.sequenceNumber += 1;       // ...different instance
        }
        const auto policy = LaunchTargetPolicy::PinToProcess(requester);

        const auto decision =
            ResolveTargetedUriLaunch(L"local+app-response:result", policy, recycled);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Refused);
    }

    // A pinned policy with no peer supplied is an error, not a silent pass - a missing
    // target must never be read as "no constraint".
    TEST_METHOD(PinnedPolicyWithoutATargetIsRejected)
    {
        const auto policy = LaunchTargetPolicy::PinToProcess(GetCurrentProcessIdentity());

        const auto decision =
            ResolveTargetedUriLaunch(L"local+app-response:result", policy, std::nullopt);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::NoLiveTarget);
    }
};

TEST_CLASS(TargetedLaunchDirectLaunch)
{
public:
    TEST_METHOD(RegisteredTargetWindowResolvesToItsProcessIdentity)
    {
        ScopedTestWindow targetWindow;
        const auto identity = TryGetProcessIdentity(targetWindow.window);

        cpp_unit::Assert::IsTrue(identity.has_value());
        cpp_unit::Assert::AreEqual(GetCurrentProcessId(), identity->processId);
        cpp_unit::Assert::IsTrue(identity->sequenceNumber != 0);
    }

    TEST_METHOD(ExplicitProcessPathFallbackAcceptsDifferentProcessInstance)
    {
        const auto handlerPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(handlerPath.has_value());

        auto other = ScopedChildProcess::Spawn();
        const auto otherIdentity = TryGetProcessIdentity(other.processId);
        cpp_unit::Assert::IsTrue(otherIdentity.has_value());

        const auto policy = LaunchTargetPolicy::PinToProcessOrExecutablePath(
            GetCurrentProcessIdentity(), *handlerPath);
        const auto decision = ResolveTargetedUriLaunch(
            L"http://example.com", policy, otherIdentity);

        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
    }

    TEST_METHOD(PackageFamilyPolicyRequiresAnObservablePackageTarget)
    {
        LaunchTargetPolicy policy =
            LaunchTargetPolicy::RequirePackageFamilyName(L"Contoso.Sample_12345");

        ResolvedLaunchTarget target;
        target.packageFamilyName = L"Contoso.Sample_12345";
        cpp_unit::Assert::IsTrue(policy.IsSatisfiedBy(target));

        target.packageFamilyName.clear();
        cpp_unit::Assert::IsFalse(policy.IsSatisfiedBy(target));
        cpp_unit::Assert::IsTrue(
            ResolveTargetedUriLaunch(L"http://example.com", policy).status ==
            LaunchTargetStatus::Unverifiable);
    }
};

// ---------------------------------------------------------------------------
// Packaging modes - two independent compile-time questions.
// ---------------------------------------------------------------------------
//
// CallerPackagingMode describes the process hosting this code; TargetPackagingMode
// describes the peer. They are separate template parameters because knowing one says
// nothing about the other, and they are separate *types* so neither can be passed where
// the other was meant.
//
// The test host is an unpackaged classic binary, so it is a valid NeverPackaged caller
// and target. The fail-fast side of a violated assertion terminates the process by design
// (FAIL_FAST_HR_IF_MSG) and is not something a unit test can trigger and catch in-proc -
// that path is verified by inspection of ApplyPackagingAssumption instead.
TEST_CLASS(TargetedLaunchPackagingMode)
{
public:
    // RuntimeDetected (the default) must keep behaving exactly as before: it captures an
    // identity without asserting anything about the peer's packaging.
    TEST_METHOD(RuntimeDetectedMatchesTheUnparameterizedOverload)
    {
        const auto defaulted = TryGetProcessIdentity(GetCurrentProcess());
        const auto explicitRuntimeDetected =
            TryGetProcessIdentity<TargetPackagingMode::RuntimeDetected>(GetCurrentProcess());

        cpp_unit::Assert::IsTrue(defaulted.has_value());
        cpp_unit::Assert::IsTrue(explicitRuntimeDetected.has_value());
        cpp_unit::Assert::AreEqual(defaulted->processId, explicitRuntimeDetected->processId);
        cpp_unit::Assert::AreEqual(defaulted->sequenceNumber, explicitRuntimeDetected->sequenceNumber);
        cpp_unit::Assert::AreEqual(defaulted->packageFamilyName, explicitRuntimeDetected->packageFamilyName);
    }

    // Target mode: NeverPackaged against a peer that really is unpackaged. The assertion
    // holds, so capture succeeds as RuntimeDetected would, without populating a family.
    TEST_METHOD(TargetNeverPackagedAcceptsAGenuinelyUnpackagedPeer)
    {
        auto child = ScopedChildProcess::Spawn();   // cmd.exe: classic, never packaged

        const auto identity =
            TryGetProcessIdentity<TargetPackagingMode::NeverPackaged>(child.processId);

        cpp_unit::Assert::IsTrue(identity.has_value());
        cpp_unit::Assert::IsTrue(identity->packageFamilyName.empty());
    }

    // Caller mode: the same three answers, asked about *this* process instead. The test
    // host is a classic binary, so NeverPackaged is the assertion that holds here.
    TEST_METHOD(CallerNeverPackagedAcceptsThisUnpackagedHost)
    {
        const auto neutral = GetCurrentProcessIdentity();
        if (!neutral.packageFamilyName.empty())
        {
            cpp_unit::Logger::WriteMessage(L"skipped - test host process is packaged");
            return;
        }

        const auto asserted = GetCurrentProcessIdentity<CallerPackagingMode::NeverPackaged>();

        cpp_unit::Assert::AreEqual(neutral.processId, asserted.processId);
        cpp_unit::Assert::AreEqual(neutral.sequenceNumber, asserted.sequenceNumber);
        cpp_unit::Assert::IsTrue(asserted.packageFamilyName.empty());
    }

    // The two modes are independent: an unpackaged caller identifying a peer, each side
    // stating its own answer, with no coupling between them.
    TEST_METHOD(CallerAndTargetModesAreStatedIndependently)
    {
        auto child = ScopedChildProcess::Spawn();

        const auto self = GetCurrentProcessIdentity<CallerPackagingMode::NeverPackaged>();
        const auto peer = TryGetProcessIdentity<TargetPackagingMode::NeverPackaged>(child.processId);

        cpp_unit::Assert::IsTrue(peer.has_value());
        cpp_unit::Assert::AreNotEqual(self.processId, peer->processId);
    }
};

// ---------------------------------------------------------------------------
// Case 2: anti-hijack - pin the launch to a specific handler binary.
// ---------------------------------------------------------------------------
//
// The target here comes from the association system: the launch is validated against
// the .exe that ShellExecute would actually hand the uri to.
TEST_CLASS(TargetedLaunchExecutablePath)
{
public:
    TEST_METHOD(SchemeResolvesToItsRegisteredHandlerExecutable)
    {
        const auto handlerPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(handlerPath.has_value(), L"no default handler registered for 'http'");
        cpp_unit::Assert::IsFalse(handlerPath->empty());
        cpp_unit::LogMessage(L"http -> %ls", handlerPath->c_str());
    }

    // Pinning to the path the association system already resolves to must succeed...
    TEST_METHOD(FullPathPolicyAcceptsTheRegisteredHandler)
    {
        const auto handlerPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(handlerPath.has_value());

        const auto policy = LaunchTargetPolicy::RequireExecutablePath(*handlerPath);

        const auto decision =
            ResolveTargetedUriLaunch(L"http://example.com", policy, std::nullopt);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
    }

    // ...and pinning to anything else must fail, which is what a hijacked association
    // looks like from the caller's side.
    TEST_METHOD(FullPathPolicyRejectsAnUnexpectedHandler)
    {
        const auto policy = LaunchTargetPolicy::RequireExecutablePath(LR"(C:\not-the-registered-handler.exe)");

        const auto decision =
            ResolveTargetedUriLaunch(L"http://example.com", policy, std::nullopt);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Refused);
    }

    // "Only ever launch explorer.exe this way" - the looser, file-name-only rule.
    TEST_METHOD(FileNamePolicyMatchesOnTheFileNameComponent)
    {
        ResolvedLaunchTarget target;
        target.executablePath = LR"(C:\Windows\explorer.exe)";

        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequireExecutableFileName(L"explorer.exe").Validate(target));

        // Case-insensitive, like every other path comparison on Windows.
        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequireExecutableFileName(L"EXPLORER.EXE").Validate(target));

        // A different binary that merely *ends with* the required name must not match,
        // which is why the comparison is on the file name component, not a suffix.
        ResolvedLaunchTarget lookalike;
        lookalike.executablePath = LR"(C:\evil\notexplorer.exe)";
        cpp_unit::Assert::AreEqual(E_ACCESSDENIED,
            LaunchTargetPolicy::RequireExecutableFileName(L"explorer.exe").Validate(lookalike));

        // Same name, different directory: accepted by the file-name rule. This is the
        // documented weakness of the loose form - prefer a full path where possible.
        ResolvedLaunchTarget elsewhere;
        elsewhere.executablePath = LR"(C:\staging\explorer.exe)";
        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequireExecutableFileName(L"explorer.exe").Validate(elsewhere));
        cpp_unit::Assert::AreEqual(E_ACCESSDENIED,
            LaunchTargetPolicy::RequireExecutablePath(LR"(C:\Windows\explorer.exe)").Validate(elsewhere));
    }

    // The status quo for comparison: with no policy, any handler is accepted. This is
    // the behaviour TargetedLaunch exists to replace.
    TEST_METHOD(UnconstrainedPolicyAcceptsAnything)
    {
        ResolvedLaunchTarget anything;
        anything.executablePath = LR"(C:\evil\hijacker.exe)";
        cpp_unit::Assert::AreEqual(S_OK, LaunchTargetPolicy::Unconstrained().Validate(anything));
    }

    // A scheme-less uri is the caller's own bad argument, not something the machine
    // reported, so it is a usage error rather than a LaunchTargetStatus. Keeping it out of
    // the status set is what stops a caller bug from reading as a security outcome.
    TEST_METHOD(MalformedUriIsAUsageErrorRatherThanAStatus)
    {
        cpp_unit::Assert::ExpectException<wil::ResultException>([]
        {
            ResolveTargetedUriLaunch(L"no-scheme-here", LaunchTargetPolicy::Unconstrained());
        });

        // The throwing entry point states the same thing as E_INVALIDARG.
        AssertThrowsHr(E_INVALIDARG, []
        {
            LaunchUriWithTarget(L"no-scheme-here", LaunchTargetPolicy::Unconstrained(), std::nullopt, true);
        });
    }
};

// Selecting a *non-default* handler - the case AssocQueryString and
// TryGetUriSchemeHandlerExecutablePath can never answer, because they only ever report
// the default. This is the classic-desktop equivalent of Launcher.LaunchUriAsync's
// PreferredApplicationId/PackageFamilyName.
TEST_CLASS(TargetedLaunchHandlerSelection)
{
public:
    // The default handler must itself appear in the "every registered app" enumeration -
    // selecting *by* its own identity is the simplest thing that could work.
    TEST_METHOD(SelectingTheDefaultHandlerByItsOwnPathFindsIt)
    {
        const auto defaultPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(defaultPath.has_value(), L"no default handler registered for 'http'");

        const auto selected =
            TryFindUriSchemeHandler(L"http", UriHandlerSelection::ByExecutablePath(*defaultPath));
        cpp_unit::Assert::IsTrue(selected.has_value(), L"the default handler did not appear in the enumeration");
        cpp_unit::Assert::IsTrue(EqualsIgnoreCase(*defaultPath, selected->executablePath));
        cpp_unit::LogMessage(L"http selected via path -> progId=%ls", selected->progId.c_str());
    }

    // The looser, file-name-only form of the same selector.
    TEST_METHOD(SelectingByFileNameMatchesRegardlessOfDirectory)
    {
        const auto defaultPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(defaultPath.has_value());
        const auto fileName = std::wstring(GetFileNamePart(*defaultPath));

        const auto selected =
            TryFindUriSchemeHandler(L"http", UriHandlerSelection::ByExecutableFileName(fileName));
        cpp_unit::Assert::IsTrue(selected.has_value());
    }

    // A selector naming nothing registered is an ordinary "not found" - the caller asked
    // for an app that is not installed, which is not a machine error.
    TEST_METHOD(SelectingAnUnregisteredExecutableFindsNothing)
    {
        const auto selected = TryFindUriSchemeHandler(
            L"http", UriHandlerSelection::ByExecutablePath(LR"(C:\not-a-registered-handler.exe)"));
        cpp_unit::Assert::IsFalse(selected.has_value());
    }

    TEST_METHOD(SelectingAnUnregisteredAppUserModelIdFindsNothing)
    {
        const auto selected = TryFindUriSchemeHandler(
            L"http", UriHandlerSelection::ByAppUserModelId(L"Not.A.Real.Package_1234!App"));
        cpp_unit::Assert::IsFalse(selected.has_value());
    }

    // The default selector is a no-op by design - callers that don't want to pick a
    // specific app should never see the enumeration path at all.
    TEST_METHOD(DefaultSelectionDoesNotEnumerate)
    {
        cpp_unit::Assert::IsFalse(TryFindUriSchemeHandler(L"http", UriHandlerSelection::Default()).has_value());
    }

    // ResolveTargetedUriLaunch integration: a selection that resolves stands in for the
    // default association lookup, and is then judged by the policy like any other target.
    TEST_METHOD(ResolvedSelectionIsValidatedAgainstThePolicy)
    {
        const auto defaultPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(defaultPath.has_value());

        const auto policy = LaunchTargetPolicy::RequireExecutablePath(*defaultPath);
        const auto selection = UriHandlerSelection::ByExecutablePath(*defaultPath);

        const auto decision = ResolveTargetedUriLaunch(
            L"http://example.com", policy, std::nullopt, selection);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
        cpp_unit::Assert::IsTrue(EqualsIgnoreCase(*defaultPath, decision.target.executablePath));
    }

    // A selection that names a real registered path but a *different* one than the
    // policy requires is Refused, not Allowed - selecting an app does not bypass the
    // policy, it only changes which target the policy is evaluated against.
    TEST_METHOD(ResolvedSelectionCanStillBeRefused)
    {
        const auto defaultPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        cpp_unit::Assert::IsTrue(defaultPath.has_value());

        const auto policy = LaunchTargetPolicy::RequireExecutablePath(LR"(C:\some-other-required-handler.exe)");
        const auto selection = UriHandlerSelection::ByExecutablePath(*defaultPath);

        const auto decision = ResolveTargetedUriLaunch(
            L"http://example.com", policy, std::nullopt, selection);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Refused);
    }

    // A selection naming an app that is not registered at all is NoHandler - the caller
    // asked for a specific app, so "fall back to the default" would be the wrong answer.
    TEST_METHOD(UnresolvableSelectionIsNoHandlerRegardlessOfPolicy)
    {
        const auto selection = UriHandlerSelection::ByExecutablePath(LR"(C:\not-a-registered-handler.exe)");

        const auto decision = ResolveTargetedUriLaunch(
            L"http://example.com", LaunchTargetPolicy::Unconstrained(), std::nullopt, selection);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::NoHandler);
    }

    // End to end, against whatever is really installed, without ever launching anything.
    // The tests above prove the mechanism against the *default* handler, which every
    // machine has exactly one of - that alone cannot prove the non-default case works,
    // because selecting the default proves nothing about picking one *among several*.
    // This instead looks for a scheme with genuine contention (more than one application
    // registered - commonly http/https, with more than one browser installed, or mailto,
    // with a browser and a mail client both registered) and selects an alternative to
    // the default. Both ResolveTargetedUriLaunch and LaunchUriWithTarget's dry run stop
    // before ShellExecuteExW is ever reached, so this proves the selection resolves to
    // the *other* app without spawning either one.
    TEST_METHOD(SelectingARealNonDefaultHandlerResolvesWithoutLaunching)
    {
        static constexpr PCWSTR candidateSchemes[] = { L"http", L"https", L"mailto" };

        for (auto scheme : candidateSchemes)
        {
            const auto defaultPath = TryGetUriSchemeHandlerExecutablePath(scheme);
            if (!defaultPath)
            {
                continue;
            }
            const auto defaultFileName = std::wstring(GetFileNamePart(*defaultPath));

            wil::com_ptr<IEnumAssocHandlers> enumHandlers;
            if (FAILED(SHAssocEnumHandlersForProtocolByApplication(scheme, IID_PPV_ARGS(&enumHandlers))))
            {
                continue;
            }

            wil::com_ptr<IAssocHandler> handler;
            ULONG fetched = 0;
            while ((enumHandlers->Next(1, handler.put(), &fetched) == S_OK) && (fetched == 1))
            {
                auto current = std::move(handler);
                handler = nullptr;

                wil::unique_cotaskmem_string name;
                if (FAILED(current->GetName(&name)))
                {
                    continue;
                }
                const std::wstring_view nameView{name.get()};

                // A packaged handler's GetName() is an AUMID ("PackageFamilyName!AppId"),
                // which always contains '!'; this is test-only discovery of *which kind*
                // of identifier was enumerated, not the production matching logic above
                // (which never needs to guess, because the selector already says).
                const bool isAumid = nameView.find(L'!') != std::wstring_view::npos;

                // Skip the default itself - the point is to find a genuine *alternative*.
                if (!isAumid && EqualsIgnoreCase(GetFileNamePart(nameView), defaultFileName))
                {
                    continue;
                }

                const auto selection = isAumid
                    ? UriHandlerSelection::ByAppUserModelId(std::wstring(nameView))
                    : UriHandlerSelection::ByExecutablePath(std::wstring(nameView));
                const std::wstring uri = std::wstring(scheme) + L"://ignored";

                const auto decision = ResolveTargetedUriLaunch(
                    uri.c_str(), LaunchTargetPolicy::Unconstrained(), std::nullopt, selection);
                cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed,
                    L"a real, registered non-default handler failed to resolve");

                if (isAumid)
                {
                    cpp_unit::Assert::IsFalse(decision.target.packageFamilyName.empty());
                }
                else
                {
                    cpp_unit::Assert::IsTrue(EqualsIgnoreCase(decision.target.executablePath, nameView));
                    cpp_unit::Assert::IsFalse(
                        EqualsIgnoreCase(GetFileNamePart(decision.target.executablePath), defaultFileName),
                        L"the resolved target should differ from the scheme's default handler");
                }

                // Same selection through the dry-run entry point: 'dryRun' returns
                // before ShellExecuteExW is ever called, so this is still launch-nothing.
                const auto dryRunStatus = LaunchUriWithTarget(
                    uri.c_str(), LaunchTargetPolicy::Unconstrained(), std::nullopt,
                    /* dryRun */ true, selection);
                cpp_unit::Assert::IsTrue(dryRunStatus == LaunchTargetStatus::Allowed);

                cpp_unit::LogMessage(L"%ls: selected non-default handler %.*ls (default was %ls)",
                    scheme, static_cast<int>(nameView.size()), nameView.data(), defaultFileName.c_str());
                return;   // one confirmed case across all candidate schemes is enough
            }
        }

        cpp_unit::Logger::WriteMessage(
            L"skipped - none of http/https/mailto had more than one registered handler on this machine");
    }
};

// ---------------------------------------------------------------------------
// Case 3: the target comes from the incoming COM call.
// ---------------------------------------------------------------------------
//
// A COM server that launches on a caller's behalf must target the *caller*, and must
// learn who that is from the call context rather than from a parameter the caller
// controls.
namespace
{
    // A minimal IDispatch object published in the Running Object Table so a *separate
    // process* can bind to it and make a real call. The cross-process hop matters: COM
    // short-circuits same-process cross-apartment calls, so those never reach LRPC and
    // carry no call context. Only a genuine cross-process call exercises the identity
    // path a COM server would rely on.
    struct CallerCapturingDispatch : winrt::implements<CallerCapturingDispatch, IDispatch>
    {
        static constexpr DISPID PingDispId = 1;

        std::atomic<bool> captureCompleted{};
        std::atomic<bool> captureSucceeded{};
        std::atomic<DWORD> callerProcessId{};
        std::atomic<bool> rpcCaptureSucceeded{};
        std::atomic<DWORD> rpcCallerProcessId{};

        IFACEMETHODIMP GetTypeInfoCount(UINT* count) noexcept override
        {
            *count = 0;
            return S_OK;
        }

        IFACEMETHODIMP GetTypeInfo(UINT, LCID, ITypeInfo** typeInfo) noexcept override
        {
            *typeInfo = nullptr;
            return E_NOTIMPL;
        }

        IFACEMETHODIMP GetIDsOfNames(REFIID, LPOLESTR* names, UINT count, LCID, DISPID* dispIds) noexcept override
        {
            HRESULT hr = S_OK;
            for (UINT i = 0; i < count; ++i)
            {
                if ((i == 0) && (CompareStringOrdinal(names[i], -1, L"Ping", -1, TRUE) == CSTR_EQUAL))
                {
                    dispIds[i] = PingDispId;
                }
                else
                {
                    dispIds[i] = DISPID_UNKNOWN;
                    hr = DISP_E_UNKNOWNNAME;
                }
            }
            return hr;
        }

        IFACEMETHODIMP Invoke(DISPID dispId, REFIID, LCID, WORD, DISPPARAMS*, VARIANT* result,
                              EXCEPINFO*, UINT*) noexcept override
        {
            if (dispId != PingDispId)
            {
                return DISP_E_MEMBERNOTFOUND;
            }

            // Servicing an incoming call: ask who is calling. Both forms are captured so
            // the test can prove the public route and the private one agree: "for caller
            // of object" scoped to this object, and the ambient "for calling process" via
            // the public RPC query. Neither reads a caller-supplied parameter.
            const auto identity = TryGetComCallerIdentityForObject(static_cast<IDispatch*>(this));
            captureSucceeded = identity.has_value();
            callerProcessId = identity ? identity->processId : 0;

            const auto rpcIdentity = TryGetComCallerIdentity<
                TargetPackagingMode::RuntimeDetected, ComCallerSource::Rpc>();
            rpcCaptureSucceeded = rpcIdentity.has_value();
            rpcCallerProcessId = rpcIdentity ? rpcIdentity->processId : 0;
            captureCompleted = true;

            if (result)
            {
                result->vt = VT_I4;
                result->lVal = static_cast<LONG>(identity ? identity->processId : 0);
            }
            return S_OK;
        }
    };

    // Publish an object in the ROT under a unique item moniker and revoke on scope exit.
    struct ScopedRunningObject
    {
        wil::com_ptr<IRunningObjectTable> rot;
        DWORD registration{};

        ~ScopedRunningObject()
        {
            if (rot && registration)
            {
                rot->Revoke(registration);
            }
        }
    };

    inline void PumpUntil(std::atomic<bool> const& done, DWORD timeoutMs)
    {
        const DWORD deadline = GetTickCount() + timeoutMs;
        while (!done.load() && (GetTickCount() < deadline))
        {
            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            Sleep(10);
        }
    }
}

TEST_CLASS(TargetedLaunchComCaller)
{
public:
    // Outside a COM call there is no caller to speak of. The API must fail rather than
    // return something a policy could act on - "no caller" must never resolve to a
    // target.
    TEST_METHOD(NoCallerOutsideOfAComCall)
    {
        cpp_unit::Assert::IsFalse(TryGetComCallerIdentity().has_value());
    }

    // Same-process cross-apartment calls are optimized by COM and never reach LRPC, so
    // they carry no call context. Documented as a test because it defines where the COM
    // caller source can and cannot be used - an in-process call must not be mistaken for
    // "no caller" and silently treated as unconstrained.
    TEST_METHOD(InProcessCallCarriesNoCallContext)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);
        auto server = winrt::make_self<CallerCapturingDispatch>();

        wil::com_ptr<IStream> marshaled;
        THROW_IF_FAILED(CoMarshalInterThreadInterfaceInStream(
            IID_IDispatch, server.as<IDispatch>().get(), marshaled.put()));

        std::thread caller([&]
        {
            auto callerApartment = wil::CoInitializeEx(COINIT_MULTITHREADED);
            wil::com_ptr<IDispatch> proxy;
            if (SUCCEEDED(CoGetInterfaceAndReleaseStream(marshaled.detach(), IID_PPV_ARGS(&proxy))))
            {
                DISPPARAMS noArgs{};
                proxy->Invoke(CallerCapturingDispatch::PingDispId, IID_NULL, LOCALE_USER_DEFAULT,
                              DISPATCH_METHOD, &noArgs, nullptr, nullptr, nullptr);
            }
        });

        PumpUntil(server->captureCompleted, 20'000);
        caller.join();

        cpp_unit::Assert::IsTrue(server->captureCompleted.load(), L"the call was never dispatched");
        cpp_unit::Assert::IsFalse(server->captureSucceeded.load(),
            L"an in-process call is expected to carry no RPC call context");
    }

    // The real case: a separate process binds to this object through the ROT and calls
    // it. The callee recovers the caller's process id from the call context and it is
    // the helper's pid - not this process, and not anything the caller supplied.
    TEST_METHOD(CrossProcessCallerIdentityComesFromTheCallContext)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);
        auto server = winrt::make_self<CallerCapturingDispatch>();

        // A unique moniker name so concurrent test runs never collide.
        GUID unique{};
        THROW_IF_FAILED(CoCreateGuid(&unique));
        wchar_t monikerName[64]{};
        StringFromGUID2(unique, monikerName, ARRAYSIZE(monikerName));

        ScopedRunningObject published;
        THROW_IF_FAILED(GetRunningObjectTable(0, published.rot.put()));

        wil::com_ptr<IMoniker> moniker;
        THROW_IF_FAILED(CreateItemMoniker(L"!", monikerName, moniker.put()));
        THROW_IF_FAILED(published.rot->Register(ROTFLAGS_REGISTRATIONKEEPSALIVE,
            server.as<IUnknown>().get(), moniker.get(), &published.registration));

        // The helper process. It finds the object by *enumerating* the ROT rather than by
        // parsing a display name: BindToMoniker runs MkParseDisplayName, which has no
        // syntax for a bare item moniker and fails with MK_E_SYNTAX before COM is ever
        // reached. Enumeration is also closer to how the ROT is really used.
        //
        // The script goes to a file rather than -Command: it contains quotes, braces and
        // newlines, and threading those through a command line intact is its own bug farm.
        wchar_t tempDirectory[MAX_PATH]{};
        THROW_LAST_ERROR_IF(GetTempPathW(ARRAYSIZE(tempDirectory), tempDirectory) == 0);
        std::wstring scriptPath = std::wstring(tempDirectory) + L"TargetedLaunchRotHelper" + monikerName + L".ps1";
        auto removeScript = wil::scope_exit([&] { DeleteFileW(scriptPath.c_str()); });

        {
            std::string script =
                "Add-Type -Language CSharp -TypeDefinition @'\n"
                "using System;using System.Runtime.InteropServices;using System.Runtime.InteropServices.ComTypes;\n"
                "public static class RotFind{\n"
                " [DllImport(\"ole32.dll\")] static extern int GetRunningObjectTable(int r,out IRunningObjectTable p);\n"
                " [DllImport(\"ole32.dll\")] static extern int CreateBindCtx(int r,out IBindCtx p);\n"
                " public static object Get(string want){\n"
                "  IRunningObjectTable rot;GetRunningObjectTable(0,out rot);\n"
                "  IBindCtx ctx;CreateBindCtx(0,out ctx);\n"
                "  IEnumMoniker e;rot.EnumRunning(out e);IMoniker[] m=new IMoniker[1];\n"
                "  while(e.Next(1,m,IntPtr.Zero)==0){\n"
                "   string n;m[0].GetDisplayName(ctx,null,out n);\n"
                "   if(n!=null&&n.IndexOf(want,StringComparison.OrdinalIgnoreCase)>=0){\n"
                "    object o;rot.GetObject(m[0],out o);return o;}}\n"
                "  return null;}}\n"
                "'@\n"
                "$o=[RotFind]::Get('";
            // The moniker name is a stringified GUID, so it is ASCII by construction -
            // narrowed explicitly rather than through a wide-to-narrow iterator copy.
            for (PCWSTR p = monikerName; *p; ++p)
            {
                script += static_cast<char>(*p);
            }
            script += "')\n"
                "if($o -ne $null){ $null=$o.Ping() }\n";

            wil::unique_hfile scriptFile(CreateFileW(scriptPath.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
            THROW_LAST_ERROR_IF(!scriptFile);
            DWORD written{};
            THROW_IF_WIN32_BOOL_FALSE(WriteFile(scriptFile.get(), script.data(),
                static_cast<DWORD>(script.size()), &written, nullptr));
        }

        std::wstring commandLine =
            L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath + L"\"";

        STARTUPINFOW startupInfo{sizeof(startupInfo)};
        PROCESS_INFORMATION processInfo{};
        THROW_IF_WIN32_BOOL_FALSE(CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr,
            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, &processInfo));
        wil::unique_handle helperProcess(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
        const DWORD helperProcessId = processInfo.dwProcessId;

        // The STA has to pump so the incoming cross-process call can be dispatched here.
        PumpUntil(server->captureCompleted, 60'000);
        WaitForSingleObject(helperProcess.get(), 10'000);

        cpp_unit::Assert::IsTrue(server->captureCompleted.load(), L"the helper never called in");
        cpp_unit::Assert::IsTrue(server->captureSucceeded.load(), L"the call context did not yield a client pid");

        const DWORD caller = server->callerProcessId.load();
        cpp_unit::LogMessage(L"COM caller pid=%u (helper pid=%u, self=%u)",
            caller, helperProcessId, GetCurrentProcessId());
        cpp_unit::Assert::AreEqual(helperProcessId, caller, L"the call context named the wrong process");
        cpp_unit::Assert::AreNotEqual(GetCurrentProcessId(), caller);

        // Both routes must agree. The public RPC query and the private per-object call
        // context are different mechanisms answering the same question, so a divergence
        // here would mean one of them is naming the wrong process.
        cpp_unit::Assert::IsTrue(server->rpcCaptureSucceeded.load(),
            L"the public RPC query did not yield a client pid");
        cpp_unit::Assert::AreEqual(helperProcessId, server->rpcCallerProcessId.load(),
            L"the public RPC query named a different process than the call context");

        // And that identity is what a server would pin its launch to.
        const auto callerIdentity = TryGetProcessIdentity(caller);
        cpp_unit::Assert::IsTrue(callerIdentity.has_value());
        const auto policy = LaunchTargetPolicy::PinToProcess(*callerIdentity);
        const auto decision = ResolveTargetedUriLaunch(
            L"local+app-response:result", policy, callerIdentity);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
    }

    // How a COM server uses it: the caller's identity from the call context becomes the
    // pinned target of the launch it performs on that caller's behalf.
    TEST_METHOD(ComCallerBecomesTheLaunchTarget)
    {
        // Stands in for the identity a server would recover via GetComCallerIdentity()
        // while servicing the call.
        const auto caller = GetCurrentProcessIdentity();

        const auto policy = LaunchTargetPolicy::PinToProcess(caller);

        const auto decision =
            ResolveTargetedUriLaunch(L"local+app-response:result", policy, caller);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);

        // A caller that names some other process as the target gets nothing: the policy
        // is built from the call context, so a claimed pid cannot override it.
        auto claimed = ScopedChildProcess::Spawn();
        const auto claimedIdentity = TryGetProcessIdentity(claimed.processId);
        cpp_unit::Assert::IsTrue(claimedIdentity.has_value());
        const auto refused = ResolveTargetedUriLaunch(
            L"local+app-response:result", policy, claimedIdentity);
        cpp_unit::Assert::IsTrue(refused.status == LaunchTargetStatus::Refused);
    }
};

// ---------------------------------------------------------------------------
// Case 4: the target is an ancestor process.
// ---------------------------------------------------------------------------
//
// A launched helper replies to whoever launched it, which it finds by walking up the
// parentage chain.
TEST_CLASS(TargetedLaunchParentProcess)
{
public:
    TEST_METHOD(ParentIdentityResolvesAndIsAPlausibleAncestor)
    {
        const auto self = GetCurrentProcessIdentity();

        const auto parent = TryGetParentProcessIdentity(GetCurrentProcessId());
        cpp_unit::Assert::IsTrue(parent.has_value(), L"could not resolve the parent process");

        cpp_unit::LogMessage(L"parent: pid=%u seq=%llu %ls",
            parent->processId, parent->sequenceNumber, parent->executablePath.c_str());

        cpp_unit::Assert::AreNotEqual(GetCurrentProcessId(), parent->processId);
        cpp_unit::Assert::IsTrue(IsPlausibleAncestor(*parent, self),
            L"the reported parent started after this process - a recycled pid");
    }

    // A child launched by this process reports this process as its parent, so the
    // reply from a helper lands back here.
    TEST_METHOD(ChildResolvesThisProcessAsItsParent)
    {
        auto child = ScopedChildProcess::Spawn();

        const auto parentOfChild = TryGetParentProcessIdentity(child.processId);
        cpp_unit::Assert::IsTrue(parentOfChild.has_value());
        cpp_unit::Assert::AreEqual(GetCurrentProcessId(), parentOfChild->processId);

        // The helper pins its reply to the parent it just resolved.
        const auto policy = LaunchTargetPolicy::PinToProcess(*parentOfChild);

        const auto decision = ResolveTargetedUriLaunch(
            L"local+app-response:result", policy, GetCurrentProcessIdentity());
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed);
    }

    // The stale-parent hazard: a pid from the parentage chain is only a claim. A
    // "parent" created after its child is a recycled pid and must be rejected before
    // it is used as a launch target.
    TEST_METHOD(AncestorCreatedAfterTheChildIsRejected)
    {
        auto self = GetCurrentProcessIdentity();

        ProcessIdentity staleParent = self;
        staleParent.processId = self.processId + 1;     // a different process...
        staleParent.sequenceNumber = self.sequenceNumber + 1; // ...that started later

        cpp_unit::Assert::IsFalse(IsPlausibleAncestor(staleParent, self));
    }
};

// ---------------------------------------------------------------------------
// Case 5: end to end - a full request/response exchange over one-way launches.
// ---------------------------------------------------------------------------
TEST_CLASS(TargetedLaunchRequestResponse)
{
public:
    // What travels in the request uri: enough to name the requesting instance so the
    // response can be pinned to it.
    struct RequestToken
    {
        DWORD processId{};
        ULONGLONG sequenceNumber{};

        static RequestToken FromIdentity(ProcessIdentity const& identity)
        {
            return {identity.processId, identity.sequenceNumber};
        }

        ProcessIdentity ToPolicyIdentity() const
        {
            ProcessIdentity identity;
            identity.processId = processId;
            identity.sequenceNumber = sequenceNumber;
            return identity;
        }
    };

    TEST_METHOD(ResponseOnlyReachesTheOriginalRequester)
    {
        // Requester: capture identity, put it in the request, launch.
        const auto requester = GetCurrentProcessIdentity();
        const auto token = RequestToken::FromIdentity(requester);

        // Responder: rebuild the target from the token and pin the response to it. The
        // token is untrusted input, so it is only ever used to *constrain* the launch -
        // it can name a process, never widen what is permitted.
        const auto policy = LaunchTargetPolicy::PinToProcess(token.ToPolicyIdentity());

        const auto decision = ResolveTargetedUriLaunch(
            L"local+app-response:result?id=42", policy, requester);
        cpp_unit::Assert::IsTrue(decision.status == LaunchTargetStatus::Allowed,
            L"response to the requester");

        // A third party racing to collect the response is refused.
        auto interloper = ScopedChildProcess::Spawn();
        const auto interloperIdentity = TryGetProcessIdentity(interloper.processId);
        cpp_unit::Assert::IsTrue(interloperIdentity.has_value());
        const auto refused = ResolveTargetedUriLaunch(
            L"local+app-response:result?id=42", policy, interloperIdentity);
        cpp_unit::Assert::IsTrue(refused.status == LaunchTargetStatus::Refused,
            L"response to an interloper");
    }

    // Validation happens before anything is spawned: a refused launch must never have
    // started a process.
    TEST_METHOD(RefusedLaunchNeverStartsAProcess)
    {
        auto other = ScopedChildProcess::Spawn();
        const auto otherIdentity = TryGetProcessIdentity(other.processId);
        cpp_unit::Assert::IsTrue(otherIdentity.has_value());

        const auto policy = LaunchTargetPolicy::PinToProcess(GetCurrentProcessIdentity());

        // Not a dry run: the call is refused by the policy, so ShellExecuteExW is never
        // reached. Refusal is a status, not an exception - the mitigation firing is an
        // ordinary outcome to check for, not a caller bug.
        cpp_unit::Assert::IsTrue(
            LaunchUriWithTarget(L"local+app-response:result", policy, otherIdentity, /* dryRun */ false)
                == LaunchTargetStatus::Refused);
    }
};

// ---------------------------------------------------------------------------
// Case 6: enforcement inside ShellExecuteExW, via the site chain.
// ---------------------------------------------------------------------------
//
// The pre-resolution check answers "what would ShellExecute pick?" with a separate
// association lookup. The site chain instead judges the shell's *own* resolved target,
// at the point of decision, and cancels by failing the callback.
TEST_CLASS(TargetedLaunchSiteEnforcement)
{
public:
    // The probe: a launch that is always cancelled, run only to harvest what the shell
    // resolved. Nothing is created.
    TEST_METHOD(ProbeReportsTheShellResolvedTarget)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        const auto observations = ProbeUriLaunchTarget(L"http://example.com");

        cpp_unit::Assert::IsTrue(observations.probeCancelled, L"a probe must always cancel");

        cpp_unit::LogMessage(L"probe: createProcess=%d coCreate=%d",
            observations.sawCreateProcess ? 1 : 0, observations.sawCoCreateInstance ? 1 : 0);
        cpp_unit::LogMessage(L"probe: app=%ls", observations.applicationPath.c_str());
        cpp_unit::LogMessage(L"probe: cmd=%ls", observations.commandLine.c_str());

        cpp_unit::Assert::IsFalse(observations.applicationPath.empty(),
            L"the probe yielded no application path");
    }

    // The value of the probe over the association query: it is the shell's own
    // resolution, and the path it reports is fully expanded.
    TEST_METHOD(ProbePathIsExpandedAndAgreesWithTheAssociationQuery)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        const auto probed = ProbeResolvedLaunchTarget(L"http://example.com");
        cpp_unit::Assert::IsTrue(probed.has_value(), L"the probe never reached a handler decision");

        // Fully expanded: a real, rooted path with no unexpanded environment variable.
        cpp_unit::Assert::AreEqual(std::wstring::npos, probed->executablePath.find(L'%'),
            L"the probed path still contains an unexpanded variable");
        cpp_unit::Assert::AreNotEqual(std::wstring::npos, probed->executablePath.find(L':'),
            L"the probed path is not rooted");

        const auto associationPath = TryGetUriSchemeHandlerExecutablePath(L"http");
        if (associationPath)
        {
            cpp_unit::LogMessage(L"probe:       %ls", probed->executablePath.c_str());
            cpp_unit::LogMessage(L"association: %ls", associationPath->c_str());

            // Both should name the same binary. The file name is compared rather than
            // the full path: the two resolutions can legitimately differ in casing or
            // in which registered path form they report.
            cpp_unit::Assert::IsTrue(
                EqualsIgnoreCase(GetFileNamePart(probed->executablePath), GetFileNamePart(*associationPath)),
                L"the probe and the association query named different binaries");
        }
    }

    // Probe, then decide. This is the pre-resolution check rebuilt on the shell's own
    // answer instead of a parallel association lookup.
    TEST_METHOD(ProbeFeedsThePolicyDecision)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        const auto probed = ProbeResolvedLaunchTarget(L"http://example.com");
        cpp_unit::Assert::IsTrue(probed.has_value(), L"the probe never reached a handler decision");

        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequireExecutablePath(probed->executablePath).Validate(*probed));
        cpp_unit::Assert::AreEqual(E_ACCESSDENIED,
            LaunchTargetPolicy::RequireExecutablePath(LR"(C:\somewhere-else.exe)").Validate(*probed));
    }

    // A violated constraint cancels the launch from inside ShellExecuteExW, and the
    // refusal is reported as such rather than as a generic shell failure.
    TEST_METHOD(SiteCancelsTheLaunchWhenTheTargetIsNotPermitted)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        LaunchSiteObservations observations;
        const auto policy = LaunchTargetPolicy::RequireExecutablePath(LR"(C:\not-the-registered-handler.exe)");

        const auto status = LaunchUriWithSiteEnforcedTarget(L"http://example.com", policy, &observations);

        cpp_unit::Assert::IsTrue(status == LaunchTargetStatus::Refused,
            L"the launch was not cancelled by the policy");
        cpp_unit::Assert::AreEqual(E_ACCESSDENIED, observations.decision);
        cpp_unit::LogMessage(L"refused: %ls", observations.applicationPath.c_str());
    }

    // The file-name rule, enforced against the shell's resolved path: pinning to some
    // other name is cancelled.
    TEST_METHOD(SiteEnforcesTheFileNameRuleAgainstTheResolvedPath)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        const auto probed = ProbeResolvedLaunchTarget(L"http://example.com");
        cpp_unit::Assert::IsTrue(probed.has_value(), L"the probe never reached a handler decision");
        const std::wstring resolvedFileName(GetFileNamePart(probed->executablePath));

        LaunchSiteObservations observations;
        const auto status = LaunchUriWithSiteEnforcedTarget(L"http://example.com",
            LaunchTargetPolicy::RequireExecutableFileName(L"a-different-handler.exe"), &observations);
        cpp_unit::Assert::IsTrue(status == LaunchTargetStatus::Refused,
            L"a launch pinned to a different file name should have been cancelled");

        // The permitted case is only asserted as a policy decision - actually letting it
        // through would open a browser window during the test run.
        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequireExecutableFileName(resolvedFileName).Validate(*probed));
    }

    // A packaged verb's own registration (HKCR\AppX.../shell/<verb>) carries an
    // AppUserModelID; the site chain reads that AUMID directly off the handler via
    // IHandlerInfo2, so a package-family policy can be enforced without ever touching a
    // process handle or an on-disk path.
    TEST_METHOD(PackageFamilyPolicyEnforcedFromTheSiteChain)
    {
        auto apartment = wil::CoInitializeEx(COINIT_APARTMENTTHREADED);

        const auto probed = ProbeResolvedLaunchTarget(L"ms-settings:");
        if (!probed || probed->packageFamilyName.empty())
        {
            cpp_unit::Logger::WriteMessage(L"skipped - ms-settings did not probe to a packaged handler");
            return;
        }

        cpp_unit::LogMessage(L"probed package family: %ls", probed->packageFamilyName.c_str());

        LaunchSiteObservations observations;
        const auto status = LaunchUriWithSiteEnforcedTarget(L"ms-settings:",
            LaunchTargetPolicy::RequirePackageFamilyName(L"Not.The.Right.Family_12345"), &observations);
        cpp_unit::Assert::IsTrue(status == LaunchTargetStatus::Refused,
            L"a launch pinned to the wrong package family should have been cancelled");

        // The permitted case is asserted as a policy decision only, to avoid actually
        // opening the Settings app during the test run.
        cpp_unit::Assert::AreEqual(S_OK,
            LaunchTargetPolicy::RequirePackageFamilyName(probed->packageFamilyName).Validate(*probed));
    }
};

namespace
{
}

// The after-create hook (ICreatedProcess/ICreateProcessOutputs) was removed rather than
// left unused. A created process can never be the peer a response is owed to - it was not
// running when the request was made, so it is not the requester - and for a single-instance
// app it forwards to the already-running instance and exits, leaving a transient stub. The
// path it exposes is already available earlier, from BeforeCreateProcess, where a veto still
// prevents creation. Exact-instance policies are answered from the live peer instead, which
// is what TargetedLaunchResponseRouting covers.

// ---------------------------------------------------------------------------
// Case 7: CLSID -> hosting binary, for COM handlers.
// ---------------------------------------------------------------------------
//
// BeforeCoCreateInstance hands over a CLSID and nothing else, so a path policy can only
// be applied to a COM handler once that CLSID is resolved to the binary hosting it.
// There is no COM API for this, so the registrations COM itself uses are read - and
// packaged COM lives in a different hive than classic COM.
TEST_CLASS(TargetedLaunchComServerResolution)
{
public:
        static PCWSTR HostingName(ComServerHosting hosting)
        {
            switch (hosting)
            {
            case ComServerHosting::LocalServer:    return L"LocalServer32";
            case ComServerHosting::InProcServer:   return L"InProcServer32";
            case ComServerHosting::Surrogate:      return L"Surrogate";
            case ComServerHosting::PackagedExe:    return L"PackagedCom(exe)";
            case ComServerHosting::PackagedInProc: return L"PackagedCom(dll)";
            default:                               return L"None";
            }
        }

        // A classic in-proc class (the shell link) resolves to its .dll. It has no process
        // of its own, so it yields no enforceable path - which the policy must treat as a
        // refusal, not as an absence of constraint.
        TEST_METHOD(InProcServerResolvesToADllAndYieldsNoEnforceablePath)
        {
            const auto resolved = TryGetComServerBinaryFromClsid(CLSID_ShellLink);
            cpp_unit::Assert::IsTrue(resolved.has_value());
            const auto& server = *resolved;

            cpp_unit::LogMessage(L"CLSID_ShellLink -> %ls  %ls", HostingName(server.hosting), server.binaryPath.c_str());

            cpp_unit::Assert::IsTrue(server.hosting == ComServerHosting::InProcServer ||
                                     server.hosting == ComServerHosting::Surrogate);
            cpp_unit::Assert::IsFalse(server.binaryPath.empty());
            cpp_unit::Assert::IsTrue(EqualsIgnoreCase(
                GetFileNamePart(server.binaryPath).substr(GetFileNamePart(server.binaryPath).size() - 4), L".dll"));

            if (server.hosting == ComServerHosting::InProcServer)
            {
                cpp_unit::Assert::IsTrue(server.PathToEnforce().empty(),
                    L"an in-proc server must not offer a path to pin");
            }
        }

        // An unregistered class must fail cleanly. A lookup that cannot answer must never
        // produce an empty-but-successful result that a policy would then compare against.
        TEST_METHOD(UnregisteredClsidFails)
        {
            GUID unregistered{};
            THROW_IF_FAILED(CoCreateGuid(&unregistered));

            cpp_unit::Assert::IsFalse(TryGetComServerBinaryFromClsid(unregistered).has_value());
        }

        // Classic COM: find a real LocalServer32 class on this machine and confirm it
        // resolves to an absolute .exe that a path policy can be built from.
        TEST_METHOD(LocalServerResolvesToAnAbsoluteExecutable)
        {
            wil::unique_hkey clsidRoot;
            THROW_IF_WIN32_ERROR(RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &clsidRoot));

            bool found = false;
            wchar_t name[64]{};
            for (DWORD i = 0; !found; ++i)
            {
                DWORD nameLength = ARRAYSIZE(name);
                if (RegEnumKeyExW(clsidRoot.get(), i, name, &nameLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                {
                    break;
                }

                CLSID clsid{};
                if (FAILED(CLSIDFromString(name, &clsid)))
                {
                    continue;
                }

                const auto resolved = TryGetComServerBinaryFromClsid(clsid);
                if (!resolved || (resolved->hosting != ComServerHosting::LocalServer))
                {
                    continue;
                }
                const auto& server = *resolved;

                found = true;
                cpp_unit::LogMessage(L"%ls -> %ls  %ls", name, HostingName(server.hosting), server.binaryPath.c_str());

                // Absolute and expanded: the registered value is a command line and may be
                // REG_EXPAND_SZ, so both the arguments and any variables must be gone.
                cpp_unit::Assert::AreEqual(std::wstring::npos, server.binaryPath.find(L'%'),
                    L"the resolved path still contains an unexpanded variable");
                cpp_unit::Assert::AreEqual(std::wstring::npos, server.binaryPath.find(L'"'),
                    L"the resolved path still contains quoting from the command line");
                cpp_unit::Assert::AreEqual(server.binaryPath, server.PathToEnforce());

                // And it is directly usable as a policy.
                ResolvedLaunchTarget target;
                target.executablePath = server.binaryPath;
                cpp_unit::Assert::AreEqual(S_OK,
                    LaunchTargetPolicy::RequireExecutablePath(server.binaryPath).Validate(target));
            }

            cpp_unit::Assert::IsTrue(found, L"no LocalServer32 class found to exercise");
        }

        // Packaged COM: MSIX servers are not under HKCR\CLSID at all, so a registry lookup
        // that only knows the classic hive reports them as unregistered. This walks the
        // PackagedCom hive to find a real packaged .exe server and confirms it resolves to
        // an absolute path inside the package's install location.
        TEST_METHOD(PackagedComServerResolvesToAnAbsolutePathInThePackage)
        {
            wil::unique_hkey classIndex;
            const LONG openResult = RegOpenKeyExW(HKEY_CLASSES_ROOT, L"PackagedCom\\ClassIndex", 0, KEY_READ, &classIndex);
            if (openResult != ERROR_SUCCESS)
            {
                cpp_unit::LogMessage(L"no PackagedCom registrations on this machine - skipped");
                return;
            }

            bool foundPackaged = false, foundExe = false;
            wchar_t name[64]{};
            for (DWORD i = 0; !foundExe; ++i)
            {
                DWORD nameLength = ARRAYSIZE(name);
                if (RegEnumKeyExW(classIndex.get(), i, name, &nameLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                {
                    break;
                }

                // ClassIndex is keyed with braces, the form CLSIDFromString expects.
                CLSID clsid{};
                if (FAILED(CLSIDFromString(name, &clsid)))
                {
                    continue;
                }

                const auto resolved = TryGetComServerBinaryFromClsid(clsid);
                if (!resolved)
                {
                    if (i < 3)
                    {
                        cpp_unit::LogMessage(L"%ls not resolved", name);
                    }
                    continue;
                }
                const auto& server = *resolved;
                if (!server.IsPackaged())
                {
                    continue;   // also skips classes that a classic registration answered first
                }

                foundPackaged = true;
                cpp_unit::Assert::IsFalse(server.packageFullName.empty(), L"a packaged server must name its package");

                if (server.hosting != ComServerHosting::PackagedExe)
                {
                    continue;   // an in-proc packaged server offers no path to pin
                }

                foundExe = true;
                cpp_unit::LogMessage(L"%ls -> %ls  package=%ls", name,
                    HostingName(server.hosting), server.packageFullName.c_str());
                cpp_unit::LogMessage(L"    %ls", server.binaryPath.c_str());

                // The registered Executable is package *relative*; the resolved path must be
                // absolute, or it could not be compared against a real process image path.
                cpp_unit::Assert::AreNotEqual(std::wstring::npos, server.binaryPath.find(L':'),
                    L"the packaged server path is not absolute");
                cpp_unit::Assert::AreEqual(server.binaryPath, server.PathToEnforce());
            }

            if (!foundPackaged)
            {
                cpp_unit::LogMessage(L"no resolvable packaged COM classes found - skipped");
                return;
            }
            cpp_unit::Assert::IsTrue(foundExe, L"no packaged out-of-process COM server found to exercise");
        }
};

// Sweep every COM registration on the machine through the resolver. The hand-picked
// tests above prove the resolver works on known-good classes; this proves it survives
// the real registry - decades of accumulated registrations, malformed values, servers
// pointing at files that were uninstalled years ago, and every quoting style anyone
// ever wrote into a command line.
//
// Nothing here asserts a *specific* path, because the machine's contents are not the
// test's to control. It asserts the invariants a security decision depends on:
//
//   * failure is clean      - a failed lookup leaves nothing a policy could act on
//   * success is absolute   - a path to enforce is comparable to a process image path
//   * success is answerable - a resolved path names a file that exists
//   * results are stable    - the same CLSID resolves the same way every time
//
// The last invariant is the interesting one. Enumeration order must never decide a
// security-relevant answer; that bug was real here (a class registered by several
// package versions resolved to whichever the registry happened to list first).
TEST_CLASS(TargetedLaunchComServerResolutionSweep)
{
public:
    struct SweepTally
    {
        int examined{}, resolved{}, failed{};
        int localServer{}, inProc{}, surrogate{}, packagedExe{}, packagedInProc{};
        int enforceable{}, missingFile{};
        std::vector<std::wstring> missingFileExamples;
    };

    // Run one CLSID through the resolver and check every invariant against the result.
    static void CheckOne(PCWSTR clsidText, SweepTally& tally)
    {
        CLSID clsid{};
        if (FAILED(CLSIDFromString(clsidText, &clsid)))
        {
            return;     // not a class key - HKCR\CLSID has non-GUID children
        }
        ++tally.examined;

        const auto resolved = TryGetComServerBinaryFromClsid(clsid);

        if (!resolved)
        {
            // A lookup that cannot answer must say so and leave nothing behind - there is
            // no leftover result to inspect, which is the whole point of returning
            // std::optional rather than an out-param a caller could half-fill.
            ++tally.failed;
            return;
        }
        const auto& server = *resolved;

        ++tally.resolved;
        switch (server.hosting)
        {
        case ComServerHosting::LocalServer:    ++tally.localServer;    break;
        case ComServerHosting::InProcServer:   ++tally.inProc;         break;
        case ComServerHosting::Surrogate:      ++tally.surrogate;      break;
        case ComServerHosting::PackagedExe:    ++tally.packagedExe;    break;
        case ComServerHosting::PackagedInProc: ++tally.packagedInProc; break;
        default:
            cpp_unit::Assert::Fail((std::wstring(L"resolved with no hosting kind: ") + clsidText).c_str());
        }

        cpp_unit::Assert::IsFalse(server.binaryPath.empty(),
            (std::wstring(L"resolved with no binary path: ") + clsidText).c_str());
        cpp_unit::Assert::IsTrue(server.IsPackaged() == !server.packageFullName.empty(),
            (std::wstring(L"packaged flag disagrees with package name: ") + clsidText).c_str());

        const std::wstring enforce = server.PathToEnforce();
        if (enforce.empty())
        {
            return;     // in-proc: no process of its own, nothing to pin. Legitimate.
        }
        ++tally.enforceable;

        // A relative path cannot be compared against a real process image path, so a
        // policy built from one would silently never match - or worse, match loosely.
        cpp_unit::Assert::AreNotEqual(std::wstring::npos, enforce.find(L':'),
            (std::wstring(L"path to enforce is not absolute: ") + clsidText + L" -> " + enforce).c_str());
        cpp_unit::Assert::AreEqual(std::wstring::npos, enforce.find(L'%'),
            (std::wstring(L"path to enforce still holds an unexpanded variable: ") + clsidText + L" -> " + enforce).c_str());
        cpp_unit::Assert::IsFalse(GetFileNamePart(enforce).empty(),
            (std::wstring(L"path to enforce has no file name component: ") + clsidText).c_str());

        // Whether the file exists is a property of the machine, not of the resolver, so
        // it is counted and reported rather than asserted. It still earns its place: a
        // resolver that mangled paths would show up here as a wall of misses even while
        // every assert above passed.
        //
        // Package paths are deliberately not probed. WindowsApps is ACL'd, and stub /
        // on-demand packages are registered and healthy while their payload has not been
        // streamed in yet - so a filesystem answer there says nothing about the resolver.
        // The package-relative join is already validated by the absolute-path assert.
        if (!server.IsPackaged() && (GetFileAttributesW(enforce.c_str()) == INVALID_FILE_ATTRIBUTES))
        {
            ++tally.missingFile;
            if (tally.missingFileExamples.size() < 10)
            {
                tally.missingFileExamples.push_back(std::wstring(clsidText) + L" -> " + enforce);
            }
        }

        // Determinism: the same class must resolve the same way every time. Enumeration
        // order, registry view, or a first-match-wins scan must not leak into the answer.
        const auto again = TryGetComServerBinaryFromClsid(clsid);
        cpp_unit::Assert::IsTrue(again.has_value(),
            (std::wstring(L"second lookup failed: ") + clsidText).c_str());
        cpp_unit::Assert::IsTrue(again->hosting == server.hosting,
            (std::wstring(L"unstable hosting kind: ") + clsidText).c_str());
        cpp_unit::Assert::AreEqual(enforce, again->PathToEnforce(),
            (std::wstring(L"unstable path to enforce: ") + clsidText).c_str());
    }

    static void ReportTally(PCWSTR label, SweepTally const& tally)
    {
        cpp_unit::LogMessage(L"%ls: examined=%d resolved=%d failed=%d", label,
            tally.examined, tally.resolved, tally.failed);
        cpp_unit::LogMessage(L"    localServer=%d inProc=%d surrogate=%d packagedExe=%d packagedInProc=%d",
            tally.localServer, tally.inProc, tally.surrogate, tally.packagedExe, tally.packagedInProc);
        cpp_unit::LogMessage(L"    enforceable=%d (of those, %d name a file that is not present)",
            tally.enforceable, tally.missingFile);
        for (auto const& example : tally.missingFileExamples)
        {
            cpp_unit::LogMessage(L"    missing: %ls", example.c_str());
        }
    }

    // Every classic registration under HKCR\CLSID.
    TEST_METHOD(EveryClassicRegistrationResolvesOrFailsCleanly)
    {
        wil::unique_hkey clsidRoot;
        THROW_IF_WIN32_ERROR(RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &clsidRoot));

        SweepTally tally;
        const ULONGLONG start = GetTickCount64();

        wchar_t name[128]{};
        for (DWORD i = 0;; ++i)
        {
            DWORD nameLength = ARRAYSIZE(name);
            const LONG result = RegEnumKeyExW(clsidRoot.get(), i, name, &nameLength,
                                              nullptr, nullptr, nullptr, nullptr);
            if (result == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (result != ERROR_SUCCESS)
            {
                continue;
            }
            CheckOne(name, tally);
        }

        ReportTally(L"HKCR\\CLSID", tally);
        cpp_unit::LogMessage(L"    elapsed %llu ms", GetTickCount64() - start);

        // Sanity on the sweep itself: a machine with a handful of classes, or one where
        // nothing resolved, means the test proved nothing and must not report success.
        cpp_unit::Assert::IsTrue(tally.examined > 100,
            L"too few classes examined for this to be a meaningful sweep");
        cpp_unit::Assert::IsTrue(tally.localServer > 0, L"no LocalServer32 class resolved");
        cpp_unit::Assert::IsTrue(tally.enforceable > 0, L"nothing resolved to an enforceable path");

        // Most out-of-process servers on a healthy machine are actually installed. A
        // resolver that mangled paths would still pass every assert above while failing
        // this one, which is exactly the regression this sweep exists to catch.
        const int present = tally.enforceable - tally.missingFile;
        cpp_unit::Assert::IsTrue(present * 2 > tally.enforceable,
            L"most enforceable paths do not name a real file - the resolver is mangling paths");
    }

    // Every packaged registration under HKCR\PackagedCom\ClassIndex.
    TEST_METHOD(EveryPackagedRegistrationResolvesOrFailsCleanly)
    {
        wil::unique_hkey classIndex;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"PackagedCom\\ClassIndex", 0, KEY_READ, &classIndex) != ERROR_SUCCESS)
        {
            cpp_unit::LogMessage(L"no PackagedCom registrations on this machine - skipped");
            return;
        }

        SweepTally tally;
        const ULONGLONG start = GetTickCount64();

        wchar_t name[128]{};
        for (DWORD i = 0;; ++i)
        {
            DWORD nameLength = ARRAYSIZE(name);
            const LONG result = RegEnumKeyExW(classIndex.get(), i, name, &nameLength,
                                              nullptr, nullptr, nullptr, nullptr);
            if (result == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (result != ERROR_SUCCESS)
            {
                continue;
            }
            CheckOne(name, tally);
        }

        ReportTally(L"HKCR\\PackagedCom\\ClassIndex", tally);
        cpp_unit::LogMessage(L"    elapsed %llu ms", GetTickCount64() - start);

        if (tally.examined == 0)
        {
            cpp_unit::LogMessage(L"no packaged classes to examine - skipped");
            return;
        }

        // Packaged COM registrations should resolve essentially without exception: they
        // are written by deployment from the manifest, not accumulated by hand. The
        // registration is the source of truth, and the package location comes from
        // GetPackagePathByFullName - so there is nothing to confirm on disk, and a
        // filesystem probe would only report on ACLs and on stub packages whose payload
        // has not been streamed in. The asserts above (absolute, expanded, names a file)
        // fully cover the package-relative join.
        cpp_unit::Assert::IsTrue(tally.resolved * 10 > tally.examined * 9,
            L"packaged COM registrations should resolve nearly always");

        // Every packaged out-of-process server must carry its package identity, which is
        // what makes the resolved path trustworthy without consulting the filesystem.
        cpp_unit::Assert::IsTrue(tally.packagedExe > 0, L"no packaged out-of-process server resolved");
    }
};

}
