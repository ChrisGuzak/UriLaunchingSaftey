#include <windows.h>
#include <appmodel.h>
#include <tlhelp32.h>

#if defined(TARGETEDLAUNCH_USE_INTERNAL_PROCESS_SEQUENCE_NUMBER)
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#endif

#include <shobjidl_core.h>

#include <winrt/Microsoft.Windows.AppLifecycle.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.System.h>
#include <wil/resource.h>
#include <wil/result.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

// Pulling the few types actually used into winrt:: keeps call sites short without
// dragging whole namespaces in, where unrelated names can collide.
namespace winrt
{
    using Microsoft::Windows::AppLifecycle::AppInstance;
    using Microsoft::Windows::AppLifecycle::AppActivationArguments;
    using Microsoft::Windows::AppLifecycle::ExtendedActivationKind;
    using Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs;
    using Windows::ApplicationModel::Activation::LaunchActivatedEventArgs;
    using Windows::ApplicationModel::Activation::ProtocolActivatedEventArgs;
    using Windows::ApplicationModel::Activation::ProtocolForResultsActivatedEventArgs;
    using Windows::ApplicationModel::AppInfo;
    using Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager;
    using Windows::Foundation::Collections::ValueSet;
    using Windows::Foundation::IPropertyValue;
    using Windows::Foundation::PropertyType;
    using Windows::Foundation::Uri;
    using Windows::Storage::StorageFile;
    using Windows::System::Launcher;
    using Windows::System::LauncherOptions;
    using Windows::System::LaunchQuerySupportType;
    using Windows::System::LaunchUriResult;
    using Windows::System::LaunchUriStatus;
}

namespace
{
#if defined(TARGETEDLAUNCH_USE_INTERNAL_PROCESS_SEQUENCE_NUMBER)
constexpr PROCESSINFOCLASS ProcessSequenceNumberClass = static_cast<PROCESSINFOCLASS>(92);
constexpr PCWSTR InstanceKeyName = L"sequence";
#else
constexpr PCWSTR InstanceKeyName = L"creation-time";
#endif

struct Identity
{
    DWORD processId{};
    ULONGLONG instanceKey{};
    std::wstring packageFamilyName;
};

// Stamped into every response and checked by the receiver (see the version comparisons
// where a reply is matched). The response travels as a raw struct through a registry
// value, so a receiver can encounter a record written by a different build of this
// sample - a stale responder still registered, or a half-updated install. Without the
// version the bytes would be reinterpreted under the wrong layout; with it the mismatch
// is rejected as "not my reply" rather than silently misread.
constexpr DWORD ResponseProtocolVersion = 1;

// The scheme this sample's own Responder package answers. Declaring it with
// ReturnResults="always" (see AppxManifest.Responder.xml) makes the sample a real
// for-results provider, so the whole round trip - discover, target, launch, respond,
// redeem - can be demonstrated without depending on any inbox app shipping first.
constexpr PCWSTR SampleForResultsScheme = L"targetedlaunch-forresults";

int RunForResultsResponder(winrt::ProtocolForResultsActivatedEventArgs const& arguments);

struct ResponseRecord
{
    DWORD version{};
    DWORD requesterProcessId{};
    ULONGLONG requesterInstanceKey{};
    DWORD responderProcessId{};
    ULONGLONG responderInstanceKey{};
    DWORD responseCode{};
};

wil::unique_event g_stopEvent;

// Packaged full-trust apps launched via IApplicationActivationManager::ActivateApplication
// get a console window that is easy to lose (it can open behind other windows, or close
// immediately if the shell decides to reuse an existing console). Tee every status line to
// a log file as well, controlled by the TARGETEDLAUNCH_LOG_PATH environment variable, so a
// run started that way still leaves verifiable, capturable proof of what happened.
FILE* g_logFile = nullptr;

void LogPrintf(PCWSTR format, ...)
{
    va_list args;
    va_start(args, format);
    va_list argsForLog;
    va_copy(argsForLog, args);
    std::vfwprintf(stdout, format, args);
    va_end(args);
    std::fflush(stdout);
    if (g_logFile)
    {
        std::vfwprintf(g_logFile, format, argsForLog);
        std::fflush(g_logFile);
    }
    va_end(argsForLog);
}

// Screen-capture demo state. This process both sends the ms-screenclip/ms-screensketch
// request and (for the redirect-uri case) receives the callback activation on its own
// registered protocol scheme, so the pending correlation id and result are tracked here
// rather than threaded through winrt::AppInstance's activation callback signature.
constexpr PCWSTR ScreenClipRedirectScheme = L"targetedlaunch-screenclip-response";
std::wstring g_pendingScreenCaptureCorrelationId;
wil::unique_event g_screenCaptureResponseEvent;
std::wstring g_screenCaptureResponseUri;

ULONGLONG GetProcessInstanceKey(HANDLE process)
{
#if defined(TARGETEDLAUNCH_USE_INTERNAL_PROCESS_SEQUENCE_NUMBER)
    ULONGLONG sequenceNumber{};
    ULONG returnLength{};
    return NT_SUCCESS(NtQueryInformationProcess(process, ProcessSequenceNumberClass,
        &sequenceNumber, sizeof(sequenceNumber), &returnLength))
        ? sequenceNumber
        : 0;
#else
    // The native sequence number is a stronger same-sized discriminator, but it is
    // undocumented. The default uses the documented process creation time.
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    THROW_LAST_ERROR_IF(!GetProcessTimes(
        process, &creationTime, &exitTime, &kernelTime, &userTime));

    ULARGE_INTEGER value{};
    value.LowPart = creationTime.dwLowDateTime;
    value.HighPart = creationTime.dwHighDateTime;
    return value.QuadPart;
#endif
}

std::wstring QueryPackageFamilyName(HANDLE process)
{
    UINT32 length{};
    if (GetPackageFamilyName(process, &length, nullptr) != ERROR_INSUFFICIENT_BUFFER)
    {
        return {};
    }

    std::wstring value(length, L'\0');
    if (GetPackageFamilyName(process, &length, value.data()) != ERROR_SUCCESS)
    {
        return {};
    }
    value.resize(length);
    if (!value.empty() && value.back() == L'\0')
    {
        value.pop_back();
    }
    return value;
}

Identity GetIdentity(DWORD processId)
{
    wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process)
    {
        return {};
    }

    Identity identity;
    identity.processId = processId;
    identity.instanceKey = GetProcessInstanceKey(process.get());
    identity.packageFamilyName = QueryPackageFamilyName(process.get());
    return identity;
}

Identity GetIdentity(HANDLE process, DWORD processId)
{
    Identity identity;
    identity.processId = processId;
    identity.instanceKey = GetProcessInstanceKey(process);
    identity.packageFamilyName = QueryPackageFamilyName(process);
    return identity;
}

DWORD GetParentProcessId(DWORD processId)
{
    // Process32First is the documented API for retrieving a process's parent PID.
    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot || snapshot.get() == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry))
    {
        return 0;
    }

    do
    {
        if (entry.th32ProcessID == processId)
        {
            return entry.th32ParentProcessID;
        }
    } while (Process32NextW(snapshot.get(), &entry));

    return 0;
}

void PrintIdentity(std::wstring_view label, Identity const& identity)
{
    LogPrintf(L"%.*ls pid=%lu %ls=%llu package=%ls\n",
        static_cast<int>(label.size()), label.data(), identity.processId,
        InstanceKeyName, identity.instanceKey,
        identity.packageFamilyName.empty() ? L"<unpackaged>" : identity.packageFamilyName.c_str());
}

void PrintParent(Identity const& self)
{
    const DWORD parentPid = GetParentProcessId(self.processId);
    const Identity parent = parentPid ? GetIdentity(parentPid) : Identity{};
    LogPrintf(L"PARENT pid=%lu %ls=%llu plausible=%ls\n", parent.processId,
        InstanceKeyName, parent.instanceKey,
        parent.instanceKey != 0 && parent.instanceKey < self.instanceKey
            ? L"true"
            : L"false");
}

std::wstring GetActivationDescription(winrt::AppActivationArguments const& arguments)
{
    if (arguments.Kind() == winrt::ExtendedActivationKind::Protocol)
    {
        const auto protocol = arguments.Data().as<winrt::ProtocolActivatedEventArgs>();
        return protocol.Uri().RawUri().c_str();
    }

    if (arguments.Kind() == winrt::ExtendedActivationKind::Launch)
    {
        const auto launch = arguments.Data().as<winrt::LaunchActivatedEventArgs>();
        return launch.Arguments().c_str();
    }

    return L"<non-protocol activation>";
}

// Minimal '?key=value&key=value' query parser. Snipping Tool response values (reason,
// file-access-token) are the only ones that can contain percent-encoding; this sample
// only branches on 'code' and 'x-request-correlation-id', which are always plain ASCII,
// so no percent-decoding is implemented here.
std::wstring GetQueryParameter(std::wstring_view uri, std::wstring_view name)
{
    const auto queryStart = uri.find(L'?');
    if (queryStart == std::wstring_view::npos)
    {
        return {};
    }

    std::wstring_view query = uri.substr(queryStart + 1);
    while (!query.empty())
    {
        const auto ampersand = query.find(L'&');
        const std::wstring_view pair = query.substr(0, ampersand);
        const auto equals = pair.find(L'=');
        const std::wstring_view key = pair.substr(0, equals);
        if (_wcsnicmp(key.data(), name.data(), (std::max)(key.size(), name.size())) == 0 &&
            key.size() == name.size())
        {
            return std::wstring(equals == std::wstring_view::npos ? L"" : pair.substr(equals + 1));
        }

        if (ampersand == std::wstring_view::npos)
        {
            break;
        }
        query = query.substr(ampersand + 1);
    }

    return {};
}

void ProcessActivation(winrt::AppActivationArguments const& arguments)
{
    const std::wstring activation = GetActivationDescription(arguments);
    LogPrintf(L"ACTIVATED kind=%d uri=%ls\n",
        static_cast<int>(arguments.Kind()), activation.c_str());
    std::fflush(stdout);

    if (activation.compare(0, wcslen(ScreenClipRedirectScheme), ScreenClipRedirectScheme) == 0)
    {
        g_screenCaptureResponseUri = activation;
        g_screenCaptureResponseEvent.SetEvent();
        return;
    }

    const bool isStopActivation = activation.size() >= 5 &&
        (activation.compare(activation.size() - 5, 5, L":stop") == 0 ||
            activation.compare(activation.size() - 5, 5, L"--stop") == 0);
    if (isStopActivation)
    {
        g_stopEvent.SetEvent();
    }
}

int RunPackagedSingleInstance(std::wstring_view role)
{

    const Identity self = GetIdentity(GetCurrentProcessId());
    winrt::init_apartment(winrt::apartment_type::single_threaded);
    const auto current = winrt::AppInstance::GetCurrent();
    const auto currentActivation = current.GetActivatedEventArgs();

    // A for-results activation carries an operation object the caller is awaiting right now,
    // so it must be answered by this instance: redirecting it to another one would strand the
    // caller. Answer it and exit before the single-instance registration below.
    if (currentActivation.Kind() == winrt::ExtendedActivationKind::ProtocolForResults)
    {
        return RunForResultsResponder(
            currentActivation.Data().as<winrt::ProtocolForResultsActivatedEventArgs>());
    }

    const std::wstring instanceKey = L"TargetedLaunch.LaunchResponse." + std::wstring(role);
    const auto primary = winrt::AppInstance::FindOrRegisterForKey(instanceKey);
    if (!primary.IsCurrent())
    {
        primary.RedirectActivationToAsync(currentActivation).get();
        LogPrintf(L"REDIRECTED role=%ls pid=%lu target-package=%ls\n",
            role.data(), GetCurrentProcessId(),
            self.packageFamilyName.empty() ? L"<unpackaged>" : self.packageFamilyName.c_str());
        return 0;
    }

    g_stopEvent.create(wil::EventOptions::ManualReset);

    const auto activated = primary.Activated([](winrt::Windows::Foundation::IInspectable const&,
        winrt::AppActivationArguments const& arguments)
    {
        ProcessActivation(arguments);
    });

    PrintIdentity(L"READY", self);
    PrintParent(self);
    ProcessActivation(currentActivation);
    std::fflush(stdout);
    g_stopEvent.wait();

    primary.Activated(activated);
    return 0;
}

std::wstring MakeGuidString()
{
    UUID id{};
    THROW_IF_FAILED(UuidCreate(&id));
    wchar_t text[64]{};
    THROW_HR_IF(E_UNEXPECTED, StringFromGUID2(id, text, ARRAYSIZE(text)) == 0);
    // StringFromGUID2 wraps the value in braces ("{...}"); strip them so it is safe to
    // use directly inside a URI query value.
    std::wstring value(text);
    if (value.size() >= 2 && value.front() == L'{' && value.back() == L'}')
    {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}


// packaged-only, two one-way-launch contract: the caller launches ms-screenclip: with a
// redirect-uri (its own registered protocol scheme) and an x-request-correlation-id, and
// Snipping Tool later activates that redirect-uri with the result appended as query
// parameters. This is exactly the shape TargetedLaunch's core problem addresses: the
// response is a second, independent launch, so nothing but the correlation id proves it
// answers *this* request rather than a stale or unrelated one - the caller must verify it
// before trusting the response, which is what this demo checks.
//
// TODO: verify once the updated screen clipping apps are available. Snipping Tool does not
// yet honor this redirect contract on any shipping build, so this path has never completed
// against a live provider.
int RunScreenClipRedirectDemo(DWORD responseTimeoutSeconds)
{
    const Identity self = GetIdentity(GetCurrentProcessId());
    if (self.packageFamilyName.empty())
    {
        // winrt::AppInstance (WinAppSDK AppLifecycle) requires package identity; calling it from
        // an unpackaged process throws, and Snipping Tool's redirect-uri contract also
        // requires a packaged caller (see the doc link above the demo functions), so an
        // unpackaged run can never complete this demo either way. Fail clearly instead of
        // letting the winrt::AppInstance call below throw uncaught and abort() the process.
        LogPrintf(L"ERROR this demo requires a packaged caller: install the Requester "
            L"package (see Build-Packages.ps1 / README.md) and run --screencapture redirect "
            L"from its installed, package-identity exe - a loose unpackaged exe cannot use "
            L"winrt::AppInstance or Snipping Tool's redirect-uri contract.\n");
        return 2;
    }

    // MTA, not STA: this function blocks with .get() below, and this console app has no
    // message pump. A blocking .get() on an STA thread asserts in debug builds because
    // nothing can service the STA re-entrancy it relies on; an MTA thread has no such
    // requirement (this is the same fix MSTest's own .runsettings applies via
    // ExecutionThreadApartmentState=MTA for tests that block on async work), so blocking
    // here is safe.
    winrt::init_apartment(winrt::apartment_type::multi_threaded);

    // This demo is only reachable with package identity (see the guard above), but every
    // WinRT/COM call below can still fail for reasons outside our control (activation
    // broker hiccups, Snipping Tool not installed/updated, redirect-uri registration
    // issues). Catch broadly and log clearly rather than letting an uncaught exception
    // call terminate()/abort() and surface as an opaque Debug Error dialog - a demo should
    // fail with a readable diagnostic, never crash.
    try
    {
        const auto current = winrt::AppInstance::GetCurrent();
        const auto currentActivation = current.GetActivatedEventArgs();
        const auto primary = winrt::AppInstance::FindOrRegisterForKey(L"TargetedLaunch.ScreenClipRedirect");
        if (!primary.IsCurrent())
        {
            // This activation is the redirect-uri callback landing on a *new* process
            // instance; forward it to the resident instance that is waiting for it.
            primary.RedirectActivationToAsync(currentActivation).get();
            return 0;
        }

        g_screenCaptureResponseEvent.create(wil::EventOptions::ManualReset);
        const auto activated = primary.Activated([](winrt::Windows::Foundation::IInspectable const&,
            winrt::AppActivationArguments const& arguments)
        {
            ProcessActivation(arguments);
        });
        const auto revokeActivated = wil::scope_exit([&] { primary.Activated(activated); });

        PrintIdentity(L"REQUESTER", self);
        g_pendingScreenCaptureCorrelationId = MakeGuidString();
        const std::wstring uri = L"ms-screenclip://capture/image?rectangle"
            L"&user-agent=TargetedLaunchSample"
            L"&redirect-uri=" + std::wstring(ScreenClipRedirectScheme) + L":capture"
            L"&x-request-correlation-id=" + g_pendingScreenCaptureCorrelationId;
        LogPrintf(L"REQUEST SENT uri=%ls timeout-seconds=%lu\n", uri.c_str(), responseTimeoutSeconds);
        std::fflush(stdout);

        winrt::Launcher::LaunchUriAsync(winrt::Windows::Foundation::Uri(uri)).get();

        if (!g_screenCaptureResponseEvent.wait(responseTimeoutSeconds * 1000))
        {
            LogPrintf(L"RESPONSE TIMEOUT timeout-seconds=%lu\n", responseTimeoutSeconds);
            return 1;
        }

        const std::wstring correlationId = GetQueryParameter(g_screenCaptureResponseUri,
            L"x-request-correlation-id");
        const std::wstring code = GetQueryParameter(g_screenCaptureResponseUri, L"code");
        const bool correlationMatches = !correlationId.empty() &&
            correlationId == g_pendingScreenCaptureCorrelationId;
        LogPrintf(L"RESPONSE %ls code=%ls correlation-id=%ls\n",
            correlationMatches ? L"ACCEPTED" : L"REFUSED", code.c_str(), correlationId.c_str());
        return correlationMatches && code == L"200" ? 0 : 1;
    }
    catch (winrt::hresult_error const& error)
    {
        LogPrintf(L"RESPONSE ERROR hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
        return 1;
    }
    catch (std::exception const& error)
    {
        LogPrintf(L"RESPONSE ERROR exception=%hs\n", error.what());
        return 1;
    }
}

// LaunchUriForResultsAsync is the safest shape: the OS itself correlates the request and
// its response and hands the result back on the same async call, so there is no second
// launch for a caller to (mis)validate and no redirect-uri registration to get wrong.
//
// Two APIs do the security work here, and they are the point of this demo:
//
//   1. winrt::Launcher::FindUriSchemeHandlersAsync(scheme, winrt::LaunchQuerySupportType::UriForResults)
//      enumerates only those installed apps whose manifest declares ReturnResults for the
//      scheme. A handler that cannot answer is never a candidate, so the caller does not
//      launch-and-hope and then have to interpret a failure it could have avoided.
//   2. winrt::LauncherOptions::TargetApplicationPackageFamilyName pins the launch to exactly one
//      of those discovered packages. Combined with (1) this is a directed launch: the
//      request reaches a named package that is known to implement the contract, rather
//      than whatever happens to own the scheme's default association at the time.
//
// See https://learn.microsoft.com/windows/uwp/launch-resume/how-to-launch-an-app-for-results.

// Waits for a WinRT async operation while pumping messages. LaunchUriForResultsAsync must be
// associated with a caller window and completes back on the originating apartment, so a plain
// blocking .get() on the STA that owns that window deadlocks. Returns false on timeout.
template<typename TAsync>
bool WaitWithMessagePump(TAsync const& async, DWORD timeoutMilliseconds)
{
    auto completed = std::make_shared<wil::unique_event>(wil::EventOptions::ManualReset);
    async.Completed([completed](auto&&, auto&&) { completed->SetEvent(); });

    HANDLE waitHandle = completed->get();
    const ULONGLONG deadline = GetTickCount64() + timeoutMilliseconds;
    for (;;)
    {
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
        const DWORD waitResult =
            MsgWaitForMultipleObjects(1, &waitHandle, FALSE, remaining, QS_ALLINPUT);
        if (waitResult == WAIT_OBJECT_0)
        {
            return true;
        }
        if (waitResult == WAIT_TIMEOUT)
        {
            return false;
        }
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

// LaunchUriForResultsAsync requires a caller window to associate the request with; a console
// app has no natural one, so create a real (if tiny) top-level window to own the launch.
wil::unique_hwnd CreateCallerWindow()
{
    static const ATOM windowClass = [] {
        WNDCLASSEXW windowClassInfo{ sizeof(windowClassInfo) };
        windowClassInfo.lpfnWndProc = DefWindowProcW;
        windowClassInfo.hInstance = GetModuleHandleW(nullptr);
        windowClassInfo.lpszClassName = L"TargetedLaunchSampleCaller";
        return RegisterClassExW(&windowClassInfo);
    }();

    wil::unique_hwnd window(CreateWindowExW(0, reinterpret_cast<PCWSTR>(windowClass),
        L"TargetedLaunch sample caller", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        420, 140, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr));
    if (window)
    {
        ShowWindow(window.get(), SW_SHOWNORMAL);
        SetForegroundWindow(window.get());
    }
    return window;
}

std::wstring ValueSetString(winrt::ValueSet const& values, PCWSTR key)
{
    if (const auto value = values.TryLookup(key))
    {
        if (const auto text = value.try_as<winrt::hstring>())
        {
            return std::wstring(text->c_str());
        }
    }
    return {};
}

std::wstring NewCorrelationId()
{
    GUID correlationGuid{};
    THROW_IF_FAILED(CoCreateGuid(&correlationGuid));
    wchar_t buffer[64]{};
    THROW_HR_IF(E_UNEXPECTED, StringFromGUID2(correlationGuid, buffer, ARRAYSIZE(buffer)) == 0);
    return buffer;
}

// Enumerates the installed apps that declare ReturnResults for this scheme. This is the check
// that makes a for-results launch predictable: an app missing from this list cannot answer,
// so it is never launched and there is no failure to interpret afterwards.
std::vector<winrt::AppInfo> DiscoverForResultsHandlers(std::wstring_view scheme)
{
    std::vector<winrt::AppInfo> handlers;
    const auto async = winrt::Launcher::FindUriSchemeHandlersAsync(
        scheme, winrt::LaunchQuerySupportType::UriForResults);
    if (!WaitWithMessagePump(async, 30 * 1000))
    {
        LogPrintf(L"DISCOVER TIMEOUT scheme=%ls\n", std::wstring(scheme).c_str());
        return handlers;
    }
    for (const winrt::AppInfo& handler : async.GetResults())
    {
        handlers.push_back(handler);
    }
    return handlers;
}

int RunScreenClipDiscoverDemo(std::wstring_view scheme)
{
    winrt::init_apartment(winrt::apartment_type::single_threaded);

    // Contrast the two capability queries against the same scheme. The Uri list is who can be
    // launched at all; the UriForResults list is who can also answer. A caller that wants a
    // response must use the second list - the difference between them is exactly the set of
    // apps that would accept a for-results launch and never reply.
    const auto describe = [&](winrt::LaunchQuerySupportType support, PCWSTR label) {
        LogPrintf(L"DISCOVER scheme=%ls support=%ls\n", std::wstring(scheme).c_str(), label);
        std::vector<winrt::AppInfo> handlers;
        const auto async = winrt::Launcher::FindUriSchemeHandlersAsync(scheme, support);
        if (!WaitWithMessagePump(async, 30 * 1000))
        {
            LogPrintf(L"  TIMEOUT\n");
            return handlers;
        }
        for (const winrt::AppInfo& handler : async.GetResults())
        {
            handlers.push_back(handler);
            LogPrintf(L"  HANDLER package-family=%ls aumid=%ls display-name=%ls\n",
                handler.PackageFamilyName().c_str(), handler.AppUserModelId().c_str(),
                handler.DisplayInfo().DisplayName().c_str());
        }
        LogPrintf(L"  COUNT %zu\n", handlers.size());
        return handlers;
    };

    const std::vector<winrt::AppInfo> launchable = describe(winrt::LaunchQuerySupportType::Uri, L"Uri");
    const std::vector<winrt::AppInfo> answerable =
        describe(winrt::LaunchQuerySupportType::UriForResults, L"UriForResults");

    // The two lists are independent, not nested. A manifest's ReturnResults value decides
    // which list a handler lands in: "optional" appears in both (it can be launched either
    // way), while "always" appears only under UriForResults - such a handler cannot be
    // launched without a result contract at all. So a handler present under UriForResults
    // and absent under Uri is normal, not a discovery error.
    if (answerable.empty())
    {
        LogPrintf(L"DISCOVER RESULT no installed app declares ReturnResults for %ls.\n"
            L"  %zu app(s) can be launched with this scheme but none can answer, so a\n"
            L"  for-results launch has nothing to respond to it and is not attempted.\n",
            std::wstring(scheme).c_str(), launchable.size());
        return 1;
    }

    LogPrintf(L"DISCOVER RESULT launchable=%zu answerable=%zu\n",
        launchable.size(), answerable.size());
    return 0;
}

// Renders one winrt::ValueSet entry for the trace. The response is an out-of-process app's payload,
// so the demo shows what actually arrived rather than assuming the contract was honored.
std::wstring DescribeValue(winrt::Windows::Foundation::IInspectable const& value)
{
    if (!value)
    {
        return L"<null>";
    }
    if (const auto text = value.try_as<winrt::hstring>())
    {
        return L"\"" + std::wstring(text->c_str()) + L"\"";
    }
    if (const auto property = value.try_as<winrt::IPropertyValue>())
    {
        switch (property.Type())
        {
        case winrt::PropertyType::Int32:
            return std::to_wstring(property.GetInt32());
        case winrt::PropertyType::UInt32:
            return std::to_wstring(property.GetUInt32());
        case winrt::PropertyType::Boolean:
            return property.GetBoolean() ? L"true" : L"false";
        default:
            return L"<" + std::to_wstring(static_cast<int>(property.Type())) + L">";
        }
    }
    return L"<object>";
}

// The request URI. Each provider defines its own request shape; the launch machinery around
// it is identical, which is the point of showing three different providers against it.
std::wstring BuildForResultsUri(std::wstring_view scheme, std::wstring const& correlationId)
{
    if (scheme == SampleForResultsScheme)
    {
        return std::wstring(SampleForResultsScheme) +
            L":capture?x-request-correlation-id=" + correlationId;
    }
    if (scheme == L"ms-screenclip")
    {
        // TODO: verify once the updated screen clipping apps are available. No installed app
        // declares ReturnResults for ms-screenclip yet, so discovery correctly refuses to
        // launch and this URI has never been exercised against a live provider. It is kept
        // because it is the real request shape the shipping Snipping Tool will accept.
        return L"ms-screenclip://capture/image?rectangle"
            L"&api-version=1.2"
            L"&enabledModes=SnippingAllModes"
            L"&user-agent=TargetedLaunchSample"
            L"&x-request-correlation-id=" + correlationId;
    }
    return std::wstring(scheme) + L":";
}

// Some for-results contracts run the file the other way around: the caller shares a file it
// owns and the provider writes the result into it. That is the mirror image of ms-screenclip,
// where the provider mints the file and shares a token back. Both directions go through
// winrt::SharedStorageAccessManager, so neither side ever hands over a raw path - only a token
// scoped to this one exchange.
winrt::ValueSet BuildForResultsInput(std::wstring_view scheme, std::wstring_view mediaType,
    std::wstring const& correlationId, std::wstring& sharedFilePath)
{
    if (scheme == SampleForResultsScheme)
    {
        // Input data travels with the launch itself rather than in the URI, which is how a
        // caller passes a request that is too structured (or too large) to encode as a query.
        winrt::ValueSet input;
        input.Insert(L"x-request-correlation-id",
            winrt::box_value(winrt::hstring(correlationId)));
        return input;
    }

    if (scheme != L"microsoft.windows.camera.picker")
    {
        return nullptr;
    }

    const bool video = mediaType == L"video";
    wchar_t tempPath[MAX_PATH]{};
    THROW_LAST_ERROR_IF(GetTempPathW(ARRAYSIZE(tempPath), tempPath) == 0);
    std::wstring path = std::wstring(tempPath) + L"TargetedLaunchSample-capture." +
        (video ? L"mp4" : L"jpg");

    // The provider needs a file that already exists to write into.
    wil::unique_hfile placeholder(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    THROW_LAST_ERROR_IF(!placeholder);
    placeholder.reset();

    const auto open = winrt::StorageFile::GetFileFromPathAsync(path);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), !WaitWithMessagePump(open, 30 * 1000));
    const winrt::hstring token = winrt::SharedStorageAccessManager::AddFile(open.GetResults());

    winrt::ValueSet input;
    input.Insert(L"MediaType", winrt::box_value(winrt::hstring(video ? L"video" : L"photo")));
    input.Insert(video ? L"VideoFileToken" : L"PhotoFileToken", winrt::box_value(token));
    sharedFilePath = path;
    LogPrintf(L"REQUEST INPUT shared-file=%ls media-type=%ls (provider writes into this file)\n",
        path.c_str(), video ? L"video" : L"photo");
    return input;
}

// Redeems a token a provider shared back and reports the file it names. This is the
// provider-mints-the-file direction, and it is the same call the ms-screenclip contract
// needs for its "file-access-token", so exercising it against any real provider validates
// that half of the pipeline even while ms-screenclip has no handler yet.
bool TryRedeemAndReport(std::wstring const& token)
{
    try
    {
        const auto redeem =
            winrt::SharedStorageAccessManager::RedeemTokenForFileAsync(winrt::hstring(token));
        if (!WaitWithMessagePump(redeem, 30 * 1000))
        {
            LogPrintf(L"  REDEEM TIMEOUT token=%ls\n", token.c_str());
            return false;
        }
        const winrt::StorageFile file = redeem.GetResults();
        LogPrintf(L"  REDEEM OK file=%ls\n", file.Path().c_str());
        return true;
    }
    catch (winrt::hresult_error const& error)
    {
        LogPrintf(L"  REDEEM FAILED hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
        return false;
    }
}

// The provider half of the for-results contract, modeled on what Snipping Tool does for
// ms-screenclip: read the caller's request, produce a file, and hand back a single-use token
// for it instead of a path. Implementing both halves here makes the round trip verifiable on
// any machine, without waiting for an inbox app to ship its side.
//
// Note what this contract gives the caller for free, and which the redirect contract above
// cannot: the response is delivered on the very operation the caller is awaiting, so there is
// no separate inbound launch that a stale or hostile reply could impersonate. The correlation
// id is echoed back only so the caller can assert that property rather than assume it.
int RunForResultsResponder(winrt::ProtocolForResultsActivatedEventArgs const& arguments)
{
    // Log entry before touching anything that can throw, so a failure in the accessors below
    // is still attributable to this path rather than looking like a silent startup crash.
    LogPrintf(L"PROVIDER ACTIVATED\n");

    std::wstring uri;
    std::wstring correlationId;
    try
    {
        if (const auto requestUri = arguments.Uri())
        {
            uri = requestUri.RawUri().c_str();
        }
        if (const winrt::ValueSet input = arguments.Data())
        {
            correlationId = ValueSetString(input, L"x-request-correlation-id");
            LogPrintf(L"PROVIDER INPUT entries=%u\n", input.Size());
        }
        if (correlationId.empty())
        {
            correlationId = GetQueryParameter(uri, L"x-request-correlation-id");
        }
        LogPrintf(L"PROVIDER REQUEST uri=%ls correlation-id=%ls\n",
            uri.empty() ? L"<none>" : uri.c_str(),
            correlationId.empty() ? L"<none>" : correlationId.c_str());
    }
    catch (winrt::hresult_error const& error)
    {
        LogPrintf(L"PROVIDER REQUEST-READ FAILED hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
    }

    winrt::ValueSet response;
    try
    {
        // Stand in for the captured image. A real provider writes pixels; the demo's subject
        // is the handoff, so the contents just identify the responder that produced them.
        wchar_t tempPath[MAX_PATH]{};
        THROW_LAST_ERROR_IF(GetTempPathW(ARRAYSIZE(tempPath), tempPath) == 0);
        const std::wstring path =
            std::wstring(tempPath) + L"TargetedLaunchSample-provider-result.txt";
        const std::string contents = "TargetedLaunch sample provider result\r\n";
        wil::unique_hfile file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        THROW_LAST_ERROR_IF(!file);
        DWORD written{};
        THROW_IF_WIN32_BOOL_FALSE(WriteFile(file.get(), contents.data(),
            static_cast<DWORD>(contents.size()), &written, nullptr));
        file.reset();

        // The caller is never told this path. It gets a token that grants access to this one
        // file for this one exchange, which is also how a winrt::ValueSet's 100KB cap is sidestepped.
        const auto open = winrt::StorageFile::GetFileFromPathAsync(path);
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), !WaitWithMessagePump(open, 30 * 1000));
        const winrt::hstring token = winrt::SharedStorageAccessManager::AddFile(open.GetResults());

        // Deliberately the same shape as the ms-screenclip response, including 'code' being a
        // string rather than an int, so the caller's parsing is exercised as written.
        response.Insert(L"code", winrt::box_value(winrt::hstring(L"200")));
        response.Insert(L"reason", winrt::box_value(winrt::hstring(L"OK")));
        response.Insert(L"file-access-token", winrt::box_value(token));
        response.Insert(L"x-request-correlation-id",
            winrt::box_value(winrt::hstring(correlationId)));
        LogPrintf(L"PROVIDER RESPONDING code=200 file=%ls\n", path.c_str());
    }
    catch (winrt::hresult_error const& error)
    {
        response.Clear();
        response.Insert(L"code", winrt::box_value(winrt::hstring(L"500")));
        response.Insert(L"reason", winrt::box_value(error.message()));
        response.Insert(L"x-request-correlation-id",
            winrt::box_value(winrt::hstring(correlationId)));
        LogPrintf(L"PROVIDER RESPONDING code=500 hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
    }

    // Until ReportCompleted is called the caller stays blocked, so this must happen on every
    // path out - including the failure path above.
    try
    {
        arguments.ProtocolForResultsOperation().ReportCompleted(response);
        LogPrintf(L"PROVIDER COMPLETED\n");
    }
    catch (winrt::hresult_error const& error)
    {
        LogPrintf(L"PROVIDER REPORT-COMPLETED FAILED hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
        return 1;
    }
    return 0;
}

int RunScreenClipForResultsDemo(
    std::wstring_view scheme, std::wstring_view mediaType, DWORD responseTimeoutSeconds)
{
    // STA: the launch is associated with a caller window and its completion marshals back here.
    winrt::init_apartment(winrt::apartment_type::single_threaded);

    // Step 1: discover. Only apps that declare ReturnResults appear here.
    LogPrintf(L"DISCOVER scheme=%ls support=UriForResults\n", std::wstring(scheme).c_str());
    const std::vector<winrt::AppInfo> handlers = DiscoverForResultsHandlers(scheme);
    if (handlers.empty())
    {
        LogPrintf(L"RESPONSE NO-PROVIDER - no installed app declares ReturnResults for %ls.\n"
            L"  Nothing was launched: discovery replaces launch-and-hope.\n",
            std::wstring(scheme).c_str());
        return 1;
    }
    for (const winrt::AppInfo& handler : handlers)
    {
        LogPrintf(L"DISCOVER HANDLER package-family=%ls aumid=%ls\n",
            handler.PackageFamilyName().c_str(), handler.AppUserModelId().c_str());
    }

    const wil::unique_hwnd callerWindow = CreateCallerWindow();
    if (!callerWindow)
    {
        LogPrintf(L"ERROR could not create the caller window the launch must be tied to.\n");
        return 1;
    }

    const std::wstring correlationId = NewCorrelationId();
    const std::wstring uri = BuildForResultsUri(scheme, correlationId);
    std::wstring sharedFilePath;
    const winrt::ValueSet input =
        BuildForResultsInput(scheme, mediaType, correlationId, sharedFilePath);

    // Two providers here answer with the same token-shaped payload: this sample's own
    // Responder package, and ms-screenclip. Anything else is dumped raw, since the demo can
    // be pointed at whatever for-results provider happens to be installed.
    const bool tokenShapedResponse =
        scheme == SampleForResultsScheme || scheme == L"ms-screenclip";

    // Step 2: launch each discovered provider by package family name until one answers. The
    // target is pinned, so the request cannot be picked up by whatever owns the association.
    for (const winrt::AppInfo& handler : handlers)
    {
        const winrt::hstring provider = handler.PackageFamilyName();
        LogPrintf(L"REQUEST FORRESULTS target-package-family=%ls\n  uri=%ls\n",
            provider.c_str(), uri.c_str());

        try
        {
            winrt::LauncherOptions options;
            options.TargetApplicationPackageFamilyName(provider);
            options.as<::IInitializeWithWindow>()->Initialize(callerWindow.get());

            const auto async = input
                ? winrt::Launcher::LaunchUriForResultsAsync(
                    winrt::Windows::Foundation::Uri(uri), options, input)
                : winrt::Launcher::LaunchUriForResultsAsync(
                    winrt::Windows::Foundation::Uri(uri), options);
            if (!WaitWithMessagePump(async, responseTimeoutSeconds * 1000))
            {
                LogPrintf(L"RESPONSE TIMEOUT after %lu seconds (the provider UI keeps running)\n",
                    responseTimeoutSeconds);
                return 1;
            }

            const winrt::LaunchUriResult result = async.GetResults();
            if (result.Status() != winrt::LaunchUriStatus::Success)
            {
                LogPrintf(L"RESPONSE REFUSED status=%d provider=%ls\n",
                    static_cast<int>(result.Status()), provider.c_str());
                continue;
            }

            const winrt::ValueSet values = result.Result();
            if (!values)
            {
                LogPrintf(L"RESPONSE EMPTY provider=%ls (launch succeeded, no payload)\n",
                    provider.c_str());
                if (sharedFilePath.empty())
                {
                    continue;
                }
            }
            else
            {
                // Show the payload exactly as it arrived before interpreting it.
                LogPrintf(L"RESPONSE PAYLOAD entries=%u\n", values.Size());
                for (const auto& entry : values)
                {
                    LogPrintf(L"  %ls = %ls\n", entry.Key().c_str(),
                        DescribeValue(entry.Value()).c_str());

                    // Any value the provider labels a token is redeemable; redeeming it here
                    // proves the caller can reach the shared file without ever being told a
                    // path. Skipped for the token-shaped contracts below, which redeem their
                    // own named token - these tokens are single-use, so redeeming twice fails.
                    const std::wstring key(entry.Key().c_str());
                    if (!tokenShapedResponse &&
                        (key.find(L"Token") != std::wstring::npos ||
                            key.find(L"token") != std::wstring::npos))
                    {
                        const std::wstring token = ValueSetString(values, entry.Key().c_str());
                        if (!token.empty())
                        {
                            TryRedeemAndReport(token);
                        }
                    }
                }
            }

            // Caller-supplied-file contract: the result is whatever the provider wrote into
            // the file we shared, so the file itself is the evidence the round trip completed.
            if (!sharedFilePath.empty())
            {
                LARGE_INTEGER size{};
                wil::unique_hfile written(CreateFileW(sharedFilePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
                if (written && GetFileSizeEx(written.get(), &size) && size.QuadPart > 0)
                {
                    LogPrintf(L"RESPONSE ACCEPTED provider=%ls file=%ls bytes=%lld\n",
                        provider.c_str(), sharedFilePath.c_str(), size.QuadPart);
                    return 0;
                }
                LogPrintf(L"RESPONSE NO-CONTENT provider=%ls file=%ls (nothing was written,\n"
                    L"  so the user dismissed the provider without producing a result)\n",
                    provider.c_str(), sharedFilePath.c_str());
                return 1;
            }

            if (!tokenShapedResponse)
            {
                // No documented contract to apply for other schemes; the payload above is the
                // result. Reaching here still proves discovery, targeted launch, and response.
                LogPrintf(L"RESPONSE ACCEPTED provider=%ls (payload shown above)\n",
                    provider.c_str());
                return 0;
            }

            // Snipping Tool boxes the result code as an HSTRING, so it must be read as a
            // string and parsed. Reading it as an int makes every response fail to decode.
            const std::wstring code = ValueSetString(values, L"code");
            const std::wstring reason = ValueSetString(values, L"reason");
            const std::wstring fileAccessToken = ValueSetString(values, L"file-access-token");
            LogPrintf(L"RESPONSE code=%ls reason=%ls has-token=%ls\n",
                code.c_str(), reason.c_str(), fileAccessToken.empty() ? L"no" : L"yes");

            // A for-results reply arrives on the operation this caller is awaiting, so it
            // cannot be a stale or injected response the way a redirect-uri activation can.
            // Assert the echoed id anyway: it costs nothing and it is the property the
            // redirect contract has to establish the hard way.
            const std::wstring echoedId = ValueSetString(values, L"x-request-correlation-id");
            if (!echoedId.empty() && echoedId != correlationId)
            {
                LogPrintf(L"RESPONSE MISMATCHED correlation-id expected=%ls actual=%ls\n",
                    correlationId.c_str(), echoedId.c_str());
                return 1;
            }

            if (code == L"499")
            {
                // An explicit user cancel is a final answer, not a provider failure: do not
                // try the next candidate and reopen a capture the user just dismissed.
                LogPrintf(L"RESPONSE CANCELED by user\n");
                return 1;
            }
            if (code != L"200" || fileAccessToken.empty())
            {
                LogPrintf(L"RESPONSE REJECTED provider=%ls - trying the next candidate\n",
                    provider.c_str());
                continue;
            }

            // Step 3: redeem the single-use token. The caller never receives a path directly;
            // it receives a token the provider minted for this response, which grants read
            // access to the provider's file and nothing else.
            const auto redeem = winrt::SharedStorageAccessManager::RedeemTokenForFileAsync(
                winrt::hstring(fileAccessToken));
            if (!WaitWithMessagePump(redeem, 30 * 1000))
            {
                LogPrintf(L"RESPONSE REDEEM-TIMEOUT\n");
                return 1;
            }
            const winrt::StorageFile file = redeem.GetResults();
            LogPrintf(L"RESPONSE ACCEPTED provider=%ls file=%ls\n",
                provider.c_str(), file.Path().c_str());
            return 0;
        }
        catch (winrt::hresult_error const& error)
        {
            LogPrintf(L"RESPONSE ERROR provider=%ls hr=0x%08X message=%ls\n",
                provider.c_str(), static_cast<unsigned int>(error.code()),
                error.message().c_str());
        }
    }

    LogPrintf(L"RESPONSE NONE - every discovered provider failed to return a result.\n");
    return 1;
}

// The legacy ms-screensketch: scheme was deprecated 2025-05-01 in favor of ms-screenclip:
// (see https://learn.microsoft.com/windows/apps/develop/launch/launch-screen-snipping).
// The deprecated documentation never specified a response contract for it at all, so this
// is a bare one-way launch shown only to contrast with ms-screenclip's structured
// request/response and ForResults support above - it is not a security pattern to copy.
int RunScreenSketchLegacyDemo()
{
    // See the MTA comment in RunScreenClipRedirectDemo above.
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    LogPrintf(L"REQUEST SENT uri=ms-screensketch: (legacy, deprecated, no response contract)\n");
    std::fflush(stdout);
    winrt::Launcher::LaunchUriAsync(winrt::Windows::Foundation::Uri(L"ms-screensketch:")).get();
    LogPrintf(L"RESPONSE NONE reason=legacy-scheme-has-no-documented-callback\n");
    return 0;
}

bool TryParseInstanceKey(PCWSTR value, ULONGLONG* instanceKey)
{
    wchar_t* end{};
    const ULONGLONG parsed = _wcstoui64(value, &end, 10);
    if (end == value || *end != L'\0')
    {
        return false;
    }

    *instanceKey = parsed;
    return true;
}

std::wstring GetResponseObjectName(PCWSTR objectType)
{
    UUID requestId{};
    THROW_IF_FAILED(UuidCreate(&requestId));

    wchar_t requestIdText[64]{};
    const int length = StringFromGUID2(requestId, requestIdText, ARRAYSIZE(requestIdText));
    THROW_HR_IF(E_UNEXPECTED, length == 0);
    return L"Local\\TargetedLaunch." + std::wstring(objectType) + L"." + requestIdText;
}

std::wstring GetExecutablePath()
{
    std::wstring path(MAX_PATH, L'\0');
    for (;;)
    {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        THROW_LAST_ERROR_IF(length == 0);
        if (length < path.size() - 1)
        {
            path.resize(length);
            return path;
        }

        path.resize(path.size() * 2);
    }
}

int RunUnpackagedRequester(DWORD responseTimeoutSeconds, DWORD responderDelaySeconds)
{
    const Identity self = GetIdentity(GetCurrentProcessId());
    PrintIdentity(L"REQUESTER", self);
    PrintParent(self);

    const std::wstring mappingName = GetResponseObjectName(L"Response");
    const std::wstring eventName = GetResponseObjectName(L"ResponseReady");
    wil::unique_handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(ResponseRecord), mappingName.c_str()));
    THROW_LAST_ERROR_IF_NULL(mapping.get());
    THROW_LAST_ERROR_IF(GetLastError() == ERROR_ALREADY_EXISTS);

    auto response = static_cast<ResponseRecord*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS,
        0, 0, sizeof(ResponseRecord)));
    THROW_LAST_ERROR_IF_NULL(response);
    const auto unmapResponse = wil::scope_exit([response] { UnmapViewOfFile(response); });
    *response = { ResponseProtocolVersion, self.processId, self.instanceKey };

    wil::unique_handle responseReady(CreateEventW(nullptr, TRUE, FALSE, eventName.c_str()));
    THROW_LAST_ERROR_IF_NULL(responseReady.get());
    THROW_LAST_ERROR_IF(GetLastError() == ERROR_ALREADY_EXISTS);

    const std::wstring command = L"\"" + GetExecutablePath() + L"\" --unpackaged --role responder" +
        L" --requester-pid " + std::to_wstring(self.processId) +
        L" --requester-instance-key " + std::to_wstring(self.instanceKey) +
        L" --response-mapping \"" + mappingName + L"\"" +
        L" --response-event \"" + eventName + L"\"" +
        (responderDelaySeconds == 0 ? L"" :
            L" --response-delay-seconds " + std::to_wstring(responderDelaySeconds));
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo{};
    THROW_LAST_ERROR_IF(!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE, 0,
        nullptr, nullptr, &startupInfo, &processInfo));
    wil::unique_handle responderProcess(processInfo.hProcess);
    wil::unique_handle responderThread(processInfo.hThread);
    const Identity expectedResponder = GetIdentity(responderProcess.get(), processInfo.dwProcessId);

    LogPrintf(L"REQUEST SENT responder-pid=%lu timeout-seconds=%lu\n",
        expectedResponder.processId, responseTimeoutSeconds);
    std::fflush(stdout);

    HANDLE waitHandles[] = { responseReady.get(), responderProcess.get() };
    const DWORD waitResult = WaitForMultipleObjects(ARRAYSIZE(waitHandles), waitHandles, FALSE,
        responseTimeoutSeconds * 1000);
    if (waitResult == WAIT_TIMEOUT)
    {
        LogPrintf(L"RESPONSE TIMEOUT timeout-seconds=%lu\n", responseTimeoutSeconds);
        return 1;
    }
    THROW_LAST_ERROR_IF(waitResult == WAIT_FAILED);

    if (waitResult != WAIT_OBJECT_0)
    {
        LogPrintf(L"RESPONSE REFUSED responder-exited=true\n");
        return 1;
    }

    MemoryBarrier();
    const bool responseMatches = response->version == ResponseProtocolVersion &&
        response->requesterProcessId == self.processId &&
        response->requesterInstanceKey == self.instanceKey &&
        response->responderProcessId == expectedResponder.processId &&
        response->responderInstanceKey == expectedResponder.instanceKey &&
        response->responseCode == 0;
    LogPrintf(L"RESPONSE %ls requester-pid=%lu %ls=%llu responder-pid=%lu\n",
        responseMatches ? L"ACCEPTED" : L"REFUSED", self.processId, InstanceKeyName,
        self.instanceKey, response->responderProcessId);
    return responseMatches ? 0 : 1;
}

int RunUnpackagedResponder(DWORD requesterProcessId, ULONGLONG requesterInstanceKey,
    std::wstring_view mappingName, std::wstring_view eventName, DWORD responseDelaySeconds)
{
    const Identity self = GetIdentity(GetCurrentProcessId());
    PrintIdentity(L"RESPONDER", self);
    PrintParent(self);

    const Identity requester = GetIdentity(requesterProcessId);
    const bool requesterMatches = requester.processId == requesterProcessId &&
        requester.instanceKey != 0 && requester.instanceKey == requesterInstanceKey;
    if (mappingName.empty() || eventName.empty())
    {
        LogPrintf(L"RESPONSE %ls requester-pid=%lu %ls=%llu\n",
            requesterMatches ? L"ACCEPTED" : L"REFUSED", requesterProcessId,
            InstanceKeyName, requesterInstanceKey);
        return requesterMatches ? 0 : 1;
    }

    wil::unique_handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE,
        std::wstring(mappingName).c_str()));
    THROW_LAST_ERROR_IF_NULL(mapping.get());
    auto response = static_cast<ResponseRecord*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS,
        0, 0, sizeof(ResponseRecord)));
    THROW_LAST_ERROR_IF_NULL(response);
    const auto unmapResponse = wil::scope_exit([response] { UnmapViewOfFile(response); });
    wil::unique_handle responseReady(OpenEventW(EVENT_MODIFY_STATE, FALSE,
        std::wstring(eventName).c_str()));
    THROW_LAST_ERROR_IF_NULL(responseReady.get());

    const bool requestMatches = response->version == ResponseProtocolVersion &&
        response->requesterProcessId == requesterProcessId &&
        response->requesterInstanceKey == requesterInstanceKey;
    if (responseDelaySeconds != 0)
    {
        Sleep(responseDelaySeconds * 1000);
    }
    response->responderProcessId = self.processId;
    response->responderInstanceKey = self.instanceKey;
    response->responseCode = requesterMatches && requestMatches ? 0 : 1;
    MemoryBarrier();
    THROW_LAST_ERROR_IF(!SetEvent(responseReady.get()));

    LogPrintf(L"RESPONSE SENT %ls requester-pid=%lu %ls=%llu\n",
        response->responseCode == 0 ? L"ACCEPTED" : L"REFUSED", requesterProcessId,
        InstanceKeyName, requesterInstanceKey);
    return response->responseCode == 0 ? 0 : 1;
}
}

int RunSample(int argc, wchar_t** argv);

int wmain(int argc, wchar_t** argv)
{
    // Packaged/activation-broker-launched runs may have no visible or attachable console, and
    // the broker does not propagate the launching shell's environment block to the new process,
    // so TARGETEDLAUNCH_LOG_PATH cannot be counted on to arrive. Fall back through candidate
    // paths until one actually opens: a packaged app's install directory is read-only, so the
    // location beside the executable works only for unpackaged runs and must not be the only
    // option, or an activated provider ends up with no way to report anything at all.
    wchar_t logPath[MAX_PATH]{};
    const auto tryOpenLog = [&](PCWSTR candidate) {
        if (!candidate || candidate[0] == L'\0' || g_logFile)
        {
            return;
        }
        if (_wfopen_s(&g_logFile, candidate, L"a, ccs=UTF-8") == 0 && g_logFile)
        {
            wcscpy_s(logPath, ARRAYSIZE(logPath), candidate);
        }
        else
        {
            g_logFile = nullptr;
        }
    };

    wchar_t candidate[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"TARGETEDLAUNCH_LOG_PATH", candidate, ARRAYSIZE(candidate)) > 0)
    {
        tryOpenLog(candidate);
    }
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", candidate, ARRAYSIZE(candidate)) > 0)
    {
        wcsncat_s(candidate, ARRAYSIZE(candidate), L"\\LaunchResponseSample.log", _TRUNCATE);
        tryOpenLog(candidate);
    }
    if (GetTempPathW(ARRAYSIZE(candidate), candidate) > 0)
    {
        wcsncat_s(candidate, ARRAYSIZE(candidate), L"LaunchResponseSample.log", _TRUNCATE);
        tryOpenLog(candidate);
    }
    if (GetModuleFileNameW(nullptr, candidate, ARRAYSIZE(candidate)) > 0)
    {
        if (wchar_t* const lastSlash = wcsrchr(candidate, L'\\'))
        {
            lastSlash[1] = L'\0';
            wcsncat_s(candidate, ARRAYSIZE(candidate), L"LaunchResponseSample.log", _TRUNCATE);
            tryOpenLog(candidate);
        }
    }
    const auto closeLogFile = wil::scope_exit([&] { if (g_logFile) { std::fclose(g_logFile); } });
    LogPrintf(L"START pid=%lu log=%ls\n", GetCurrentProcessId(),
        logPath[0] == L'\0' ? L"<none>" : logPath);

    // A packaged activation has no console to print a crash to, and an unhandled exception
    // here aborts the process - which, on the for-results path, strands the caller until its
    // timeout expires with no explanation. Catch everything and leave a record instead.
    try
    {
        return RunSample(argc, argv);
    }
    catch (winrt::hresult_error const& error)
    {
        LogPrintf(L"FATAL hr=0x%08X message=%ls\n",
            static_cast<unsigned int>(error.code()), error.message().c_str());
        return 1;
    }
    catch (std::exception const& error)
    {
        LogPrintf(L"FATAL %hs\n", error.what());
        return 1;
    }
    catch (...)
    {
        LogPrintf(L"FATAL unknown exception\n");
        return 1;
    }
}

int RunSample(int argc, wchar_t** argv)
{
    bool unpackaged = false;
    std::wstring_view role = L"responder";
    DWORD requesterProcessId{};
    ULONGLONG requesterInstanceKey{};
    DWORD responseTimeoutSeconds = 10;
    DWORD responseDelaySeconds{};
    std::wstring_view responseMapping;
    std::wstring_view responseEvent;
    std::wstring_view screenCaptureMode;
    std::wstring_view scheme = L"ms-screenclip";
    std::wstring_view mediaType = L"photo";
    for (int index = 1; index < argc; ++index)
    {
        const std::wstring_view argument = argv[index];
        if (argument == L"--unpackaged")
        {
            unpackaged = true;
        }
        else if (argument == L"--role" && index + 1 < argc)
        {
            role = argv[++index];
        }
        else if (argument == L"--screencapture" && index + 1 < argc)
        {
            screenCaptureMode = argv[++index];
        }
        else if (argument == L"--scheme" && index + 1 < argc)
        {
            scheme = argv[++index];
        }
        else if (argument == L"--media" && index + 1 < argc)
        {
            mediaType = argv[++index];
        }
        else if (argument == L"--requester-pid" && index + 1 < argc)
        {
            requesterProcessId = wcstoul(argv[++index], nullptr, 10);
        }
        else if (argument == L"--requester-instance-key" && index + 1 < argc)
        {
            if (!TryParseInstanceKey(argv[++index], &requesterInstanceKey))
            {
                std::fwprintf(stderr, L"ERROR --requester-instance-key must be an unsigned integer\n");
                return 2;
            }
        }
        else if (argument == L"--response-timeout-seconds" && index + 1 < argc)
        {
            responseTimeoutSeconds = wcstoul(argv[++index], nullptr, 10);
        }
        else if (argument == L"--response-delay-seconds" && index + 1 < argc)
        {
            responseDelaySeconds = wcstoul(argv[++index], nullptr, 10);
        }
        else if (argument == L"--response-mapping" && index + 1 < argc)
        {
            responseMapping = argv[++index];
        }
        else if (argument == L"--response-event" && index + 1 < argc)
        {
            responseEvent = argv[++index];
        }
    }

    if (role != L"requester" && role != L"responder")
    {
        std::fwprintf(stderr, L"ERROR --role must be requester or responder\n");
        return 2;
    }

    if (!screenCaptureMode.empty())
    {
        if (screenCaptureMode == L"redirect")
        {
            return RunScreenClipRedirectDemo(responseTimeoutSeconds);
        }
        if (screenCaptureMode == L"discover")
        {
            return RunScreenClipDiscoverDemo(scheme);
        }
        if (screenCaptureMode == L"forresults")
        {
            return RunScreenClipForResultsDemo(scheme, mediaType, responseTimeoutSeconds);
        }
        if (screenCaptureMode == L"legacy")
        {
            return RunScreenSketchLegacyDemo();
        }
        std::fwprintf(stderr,
            L"ERROR --screencapture must be discover, redirect, forresults, or legacy\n");
        return 2;
    }

    if (unpackaged)
    {
        if (role == L"responder" &&
            (requesterProcessId == 0 || requesterInstanceKey == 0))
        {
            std::fwprintf(stderr,
                L"ERROR responder requires --requester-pid and --requester-instance-key\n");
            return 2;
        }
        return role == L"requester"
            ? RunUnpackagedRequester(responseTimeoutSeconds, responseDelaySeconds)
            : RunUnpackagedResponder(requesterProcessId, requesterInstanceKey,
                responseMapping, responseEvent, responseDelaySeconds);
    }

    return RunPackagedSingleInstance(role);
}
