#include "pch.h"
#include <wil/registry.h>

#include <appmodel.h>
#include <string>
#include <string_view>
#include <vector>
#include <thread>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.ApplicationModel.AppExtensions.h>

// Pulling the few types actually used into winrt:: keeps call sites short without
// dragging whole namespaces in, where unrelated names can collide.
namespace winrt
{
    using Windows::ApplicationModel::AppExtensions::AppExtensionCatalog;
    using Windows::Foundation::Collections::IPropertySet;
}

#pragma comment(lib, "shlwapi.lib") // link to this

// ---------------------------------------------------------------------------
// POC helpers: packaged URI scheme detection + AppExtension LocalOnly detection
// ---------------------------------------------------------------------------

// The shell-owned AppExtension contract that packaged handlers declare to mark a
// URI scheme as "local only" (see README "Packaged Uri Scheme Handlers").
constexpr PCWSTR c_localOnlyUriSchemeContract = L"com.microsoft.windows.urischeme.localonly";

struct UriSchemeHandlerPackage
{
    bool isPackaged{};                 // handler resolved to a real AUMID
    std::wstring appUserModelId;       // raw ASSOCSTR_APPID value (AUMID for packaged, plain name for classic)
    std::wstring packageFamilyName;    // prefix of the AUMID (stable identifier)
    std::wstring packageFullName;      // resolved via GetPackagesByPackageFamily (version-stamped)
};

// Public-API recipe: query the scheme's *default* handler AppUserModelID. If it parses
// as a real AUMID the handler is a packaged app; otherwise it's a classic (unpackaged)
// app or there is no handler. Returns the family/full name when packaged.
inline UriSchemeHandlerPackage GetUriSchemeHandlerPackage(PCWSTR scheme)
{
    UriSchemeHandlerPackage result;

    wchar_t aumid[APPLICATION_USER_MODEL_ID_MAX_LENGTH]{};
    DWORD aumidLen = ARRAYSIZE(aumid);
    // ASSOCF_IS_PROTOCOL: 'scheme' is a URI scheme, not a file extension.
    if (FAILED(AssocQueryStringW(ASSOCF_IS_PROTOCOL, ASSOCSTR_APPID, scheme, nullptr, aumid, &aumidLen)))
    {
        return result; // no handler, or a desktop handler that exposes no AUMID
    }
    result.appUserModelId = aumid;

    // Validate + split AUMID = "<PackageFamilyName>!<PRAID>". Classic handlers return a
    // plain name (e.g. "MSEdge") which fails to parse -> a clean packaged/unpackaged discriminator.
    wchar_t family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1]{};
    UINT32 familyLen = ARRAYSIZE(family);
    wchar_t praid[APPLICATION_USER_MODEL_ID_MAX_LENGTH]{};
    UINT32 praidLen = ARRAYSIZE(praid);
    if (ParseApplicationUserModelId(aumid, &familyLen, family, &praidLen, praid) != ERROR_SUCCESS)
    {
        return result; // not a packaged AUMID -> classic/unpackaged handler
    }

    result.isPackaged = true;
    result.packageFamilyName = family;

    // family -> full name (one package per family per user). Two-call buffer pattern.
    UINT32 count = 0, bufChars = 0;
    if (GetPackagesByPackageFamily(family, &count, nullptr, &bufChars, nullptr) == ERROR_INSUFFICIENT_BUFFER && count)
    {
        std::vector<PWSTR> fullNames(count);
        std::wstring buffer(bufChars, L'\0');
        if (GetPackagesByPackageFamily(family, &count, fullNames.data(), &bufChars, buffer.data()) == ERROR_SUCCESS && count)
        {
            result.packageFullName = fullNames[0];
        }
    }
    return result;
}

struct LocalOnlyAppExtension
{
    std::wstring extensionId;            // AppExtension Id (instance label)
    std::wstring packageFamilyName;     // declaring package
    std::vector<std::wstring> schemes;  // resolved scheme list (from <Scheme> and <Schemes>)
    std::wstring rawProps;              // debug: every top-level property key + leaf text
};

// Reads the inner text of a leaf AppExtension property. A manifest element like
// <Scheme>foo</Scheme> surfaces as props["Scheme"] -> IPropertySet -> ["#text"] -> "foo".
inline std::wstring ReadLeafProperty(
    winrt::IPropertySet const& props, PCWSTR name)
{
    if (props && props.HasKey(name))
    {
        if (auto leaf = props.Lookup(name).try_as<winrt::IPropertySet>())
        {
            if (leaf.HasKey(L"#text"))
            {
                return winrt::unbox_value_or<winrt::hstring>(leaf.Lookup(L"#text"), {}).c_str();
            }
        }
    }
    return {};
}

inline std::vector<std::wstring> SplitDelimited(std::wstring const& value, wchar_t delim)
{
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= value.size())
    {
        auto pos = value.find(delim, start);
        auto token = value.substr(start, pos == std::wstring::npos ? std::wstring::npos : pos - start);
        if (!token.empty())
        {
            parts.push_back(token);
        }
        if (pos == std::wstring::npos)
        {
            break;
        }
        start = pos + 1;
    }
    return parts;
}

// Enumerate every packaged handler that declares the local-only contract and the URI
// scheme(s) it marks. Must run in an MTA (blocks on the async catalog/property calls).
inline std::vector<LocalOnlyAppExtension> CollectLocalOnlyAppExtensionSchemes()
{
    std::vector<LocalOnlyAppExtension> result;
    auto catalog = winrt::AppExtensionCatalog::Open(c_localOnlyUriSchemeContract);
    auto extensions = catalog.FindAllAsync().get();
    for (auto const& ext : extensions)
    {
        LocalOnlyAppExtension info;
        info.extensionId = ext.Id().c_str();
        info.packageFamilyName = ext.AppInfo().PackageFamilyName().c_str();

        auto props = ext.GetExtensionPropertiesAsync().get();
        if (props)
        {
            // Dump every top-level property key so we can see how repeated/container
            // elements actually surface in the IPropertySet.
            for (auto const& kv : props)
            {
                std::wstring text;
                if (auto leaf = kv.Value().try_as<winrt::IPropertySet>())
                {
                    if (leaf.HasKey(L"#text"))
                    {
                        text = winrt::unbox_value_or<winrt::hstring>(leaf.Lookup(L"#text"), {}).c_str();
                    }
                }
                info.rawProps += std::wstring(kv.Key().c_str()) + L"=[" + text + L"] ";
            }

            // Shape A: a (repeated) <Scheme> element.
            if (auto one = ReadLeafProperty(props, L"Scheme"); !one.empty())
            {
                info.schemes.push_back(one);
            }
            // Shape B: a delimited <Schemes> element, e.g. "a;b;c".
            for (auto& scheme : SplitDelimited(ReadLeafProperty(props, L"Schemes"), L';'))
            {
                info.schemes.push_back(scheme);
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

// Run a callable on a dedicated MTA thread so winrt .get() never blocks an STA/UI thread.
template <typename Fn>
auto RunOnMtaThread(Fn&& fn) -> decltype(fn())
{
    decltype(fn()) result{};
    std::exception_ptr error;
    std::thread worker([&]
    {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        try { result = fn(); }
        catch (...) { error = std::current_exception(); }
        winrt::uninit_apartment();
    });
    worker.join();
    if (error) { std::rethrow_exception(error); }
    return result;
}

template <typename HostT>
class ActivationServiceProvider : public winrt::implements<ActivationServiceProvider<HostT>, 
    IServiceProvider, IHandlerActivationHost, ICreatingProcess>
{
public:
    ActivationServiceProvider(HostT* host = nullptr) : m_host(host)
    {
    }

    // IServiceProvider
    IFACEMETHODIMP QueryService(REFGUID serviceId, REFIID riid, __deref_out void** ppv) noexcept override
    {
        *ppv = nullptr;
        return ((serviceId == SID_SHandlerActivationHost) ||
                (serviceId == SID_ExecuteCreatingProcess)) ? QueryInterface(riid, ppv) : E_NOTIMPL;
    }

    // IHandlerActivationHost
    IFACEMETHODIMP BeforeCoCreateInstance(REFCLSID clsidHandler, _In_opt_ IShellItemArray* items, IHandlerInfo* handlerInfo) noexcept override
    {
        m_sawActivation = true;
        m_host->BeforeCoCreateInstance(clsidHandler, items, handlerInfo);
        m_host->ReportHandlerInfo(handlerInfo);
        return m_cancelActivation ? HRESULT_FROM_WIN32(ERROR_CANCELLED) : S_OK;
    }

    IFACEMETHODIMP BeforeCreateProcess(PCWSTR applicationPath, PCWSTR commandLine, IHandlerInfo* handlerInfo) noexcept override
    {
        m_sawActivation = true;
        m_host->BeforeCreateProcess(applicationPath, commandLine, handlerInfo);
        m_host->ReportHandlerInfo(handlerInfo);
        return m_cancelActivation ? HRESULT_FROM_WIN32(ERROR_CANCELLED) : S_OK;
    }

    IFACEMETHODIMP OnCreating(ICreateProcessInputs* inputs) noexcept override
    {
        // Indicate what is being launched is from an untrusted source.
        // Processes can retrieve this via GetStartupInfoW() STARTUPINFOW.dwFlags
        inputs->AddStartupFlags(STARTF_UNTRUSTEDSOURCE);
        // A backstop: if the hooks above were somehow not reached, a cancelling site
        // still must not let anything start.
        return m_cancelActivation ? HRESULT_FROM_WIN32(ERROR_CANCELLED) : S_OK;
    }

    // Observe the resolved handler without committing to the launch.
    void SetCancelActivation(bool cancel) noexcept
    {
        m_cancelActivation = cancel;
    }

    bool SawActivation() const noexcept
    {
        return m_sawActivation;
    }

    IUnknown* GetAsSite()
    {
        return static_cast<IServiceProvider*>(this);
    }

private:
    HostT* m_host;
    bool m_cancelActivation{};
    bool m_sawActivation{};
};

HRESULT ShellExecuteItemWithVerb(
    HWND hwnd, _In_opt_ IUnknown* site, _In_opt_ PCWSTR verb, _In_opt_ PCWSTR classToUse, IShellItem* item, DWORD /* SEE_MASK_XXX */ mask = SEE_MASK_DEFAULT)
{
    // how to activate a shell item, use ShellExecute().
    wil::unique_cotaskmem_ptr<ITEMIDLIST_ABSOLUTE> launchTarget;
    RETURN_IF_FAILED(SHGetIDListFromObject(item, wil::out_param(launchTarget)));
    SHELLEXECUTEINFO ei = {sizeof(ei)};
    ei.fMask = mask | SEE_MASK_IDLIST | (classToUse ? SEE_MASK_CLASSNAME : SEE_MASK_DEFAULT) |
               (site ? SEE_MASK_FLAG_HINST_IS_SITE : SEE_MASK_DEFAULT);
    ei.hwnd = hwnd;
    ei.nShow = SW_NORMAL;
    ei.lpIDList = launchTarget.get();
    ei.lpVerb = verb;
    ei.lpClass = classToUse;
    ei.hInstApp = reinterpret_cast<HINSTANCE>(site);
    RETURN_IF_WIN32_BOOL_FALSE(ShellExecuteExW(&ei));
    return S_OK;
}

namespace cpp_unit = Microsoft::VisualStudio::CppUnitTestFramework;

namespace UriLaunchingSafetey
{

TEST_CLASS(UseCases)
{
public:
    void BeforeCoCreateInstance(REFCLSID clsidHandler, _In_opt_ IShellItemArray* items, IHandlerInfo* handlerInfo)
    {
    }

    void BeforeCreateProcess(PCWSTR applicationPath, PCWSTR commandLine, IHandlerInfo* handlerInfo)
    {
        cpp_unit::LogMessage(L"%ls", applicationPath);
        cpp_unit::LogMessage(L"%ls", commandLine);
    }

    void ReportHandlerInfo(IHandlerInfo * handlerInfo)
    {
        wil::unique_cotaskmem_string appName, appPublisher, appIcon, appId, progId;
        handlerInfo->GetApplicationDisplayName(&appName);
        handlerInfo->GetApplicationPublisher(&appPublisher);
        handlerInfo->GetApplicationIconReference(&appIcon);

        if (auto handlerInfo2 = wil::try_com_query<IHandlerInfo2>(handlerInfo))
        {
            handlerInfo2->GetApplicationId(&appId);
        }

        // For nested ShellExecute case ignore these values if the app is null.
        if (appName)
        {
            cpp_unit::LogMessage(L"AppName: %ls", appName.get());
            cpp_unit::LogMessage(L"Publisher: %ls", appPublisher.get());
            cpp_unit::LogMessage(L"Icon: %ls", appIcon.get());
            cpp_unit::LogMessage(L"AppId: %ls", appId.get());
            cpp_unit::LogMessage(L"ProgId: %ls", progId.get());
        }

        // An obscure way to get to the association object so we can inspect the EditFlags
        // or other configuration from the handler that is about to be invoked.
        if (auto serviceProvider = wil::try_com_query<IServiceProvider>(handlerInfo))
        {
            wil::com_ptr<IQueryAssociations> queryAssoc;
            if (SUCCEEDED(serviceProvider->QueryService(SID_CtxQueryAssociations, IID_PPV_ARGS(&queryAssoc))))
            {
                cpp_unit::LogMessage(L"SID_CtxQueryAssociations %p", queryAssoc.get());
                wchar_t value[128]{};
                DWORD valueLength = ARRAYSIZE(value);
                if (SUCCEEDED(queryAssoc->GetString(ASSOCF_NONE, ASSOCSTR_PROGID, nullptr, value, &valueLength)))
                {
                    cpp_unit::LogMessage(L"ProgId %ls", value);
                }

                DWORD editFlags{}, editFlagsSize = sizeof(editFlags);
                if (SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_EDITFLAGS, nullptr, &editFlags, &editFlagsSize)))
                {
                    cpp_unit::LogMessage(L"EditFlags 0x%04X", editFlags);
                }

                DWORD localOnly{}, localOnlySize = sizeof(localOnly);
                if (SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_VALUE, L"LocalOnly", &localOnly, &localOnlySize)))
                {
                    cpp_unit::LogMessage(L"LocalOnly");
                }

                // MinimumAllowedUrlZone = 1 (Local)
                // Uri Launching Safety
                DWORD minZone{}, minZoneSize = sizeof(minZone);
                if (SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_VALUE, L"MinimumAllowedUrlZone", &minZone, &minZoneSize)))
                {
                    auto zoneOfLaunchInput = URLZONE::URLZONE_INTERNET; // browsers
                    cpp_unit::LogMessage(L"MinimumAllowedUrlZone %d", minZone);
                    if (static_cast<URLZONE>(minZone) < zoneOfLaunchInput) // "less than" test as zone values increase for lower trust
                    {
                        cpp_unit::LogMessage(L"Launch blocked");
                    }
                }
            }
        }
    }

    // Demonstrates the site chain observing a launch, without actually launching. Both
    // activation hooks report what the shell resolved and then return ERROR_CANCELLED, so
    // the test still exercises real handler resolution but never opens a browser. Running
    // a test suite must not have side effects on the desktop.
    TEST_METHOD(LaunchWithShellExecute)
    {
        auto service = winrt::make_self<ActivationServiceProvider<UseCases>>(this);
        service->SetCancelActivation(true);

        PCWSTR uri = L"http://example.com";

        wil::com_ptr<IShellItem> uriItem;
        THROW_IF_FAILED(SHCreateItemFromParsingName(uri, nullptr, IID_PPV_ARGS(&uriItem)));

        const HRESULT hr = ShellExecuteItemWithVerb(nullptr, service->GetAsSite(), nullptr, nullptr, uriItem.get());
        cpp_unit::Assert::AreEqual(HRESULT_FROM_WIN32(ERROR_CANCELLED), hr, L"the launch should have been cancelled");
        cpp_unit::Assert::IsTrue(service->SawActivation(), L"the site chain was never consulted");
    }

    static wil::com_ptr<IQueryAssociations> CreateUriSchemeAssocHandler(PCWSTR uriScheme)
    {
        wil::com_ptr<IQueryAssociations> queryAssoc;
        THROW_IF_FAILED(AssocCreate(CLSID_QueryAssociations, IID_PPV_ARGS(&queryAssoc)));
        THROW_IF_FAILED(queryAssoc->Init(ASSOCF_IS_PROTOCOL, uriScheme, nullptr, nullptr));
        return queryAssoc;
    }

    bool IsLocalOnlyUriScheme(PCWSTR scheme)
    {
        const auto schemeView = std::wstring_view(scheme);
        const auto localPrefix = std::wstring_view(L"local+");

        // In C++ 20 this can be (schemeView.starts_with("local+"))
        if ((schemeView.size() >= localPrefix.size()) && (schemeView.compare(0, localPrefix.size(), localPrefix) == 0))
        {
            return true;
        }
        else
        {
            auto queryAssoc = CreateUriSchemeAssocHandler(scheme);
            if (SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_VALUE, L"LocalOnly", nullptr, nullptr)))
            {
                return true;
            }

            /*
            // TODO: this should only apply to Windows OS Uri handlers, those who's
            // module is protected with WRP (owned by TrusteInstaller)
            DWORD editFlags{}, editFlagsSize = sizeof(editFlags);
            if (SUCCEEDED(queryAssoc->GetData(ASSOCF_NONE, ASSOCDATA_EDITFLAGS, nullptr, &editFlags, &editFlagsSize)) &&
                WI_IsFlagClear(editFlags, FTA_SafeForElevation))
            {
                return true;
            }
            */
            return false;
        }
    }

    // AssocDump /DumpUriSchemesThatAreSafeForElevation
    // AssocDump /DumpUriSchemesWithSystemHandlers
    TEST_METHOD(DetectLocalOnlyUriSchemes)
    {
        cpp_unit::Assert::IsTrue(IsLocalOnlyUriScheme(L"local+some-uri-scheme"));
        cpp_unit::Assert::IsFalse(IsLocalOnlyUriScheme(L"http"));
        cpp_unit::Assert::IsFalse(IsLocalOnlyUriScheme(L"ms-settings"));
        // This should be local only based on the module being a windows component
        // but IsLocalOnlyUriScheme helper does not support that yet.
        // cpp_unit::Assert::IsTrue(IsLocalOnlyUriScheme(L"explorer.zipselection"));

        // Like CreateLocalOnlySchemes.ps1
        auto schemeKey = wil::reg::create_unique_key(HKEY_CURRENT_USER, LR"(Software\Classes\local+uri-scheme)",
            wil::reg::key_access::readwrite);
        wil::reg::set_value(schemeKey.get(), L"URL Protocol", L"");
        wil::reg::set_value(schemeKey.get(), L"LocalOnly", L"");
        cpp_unit::Assert::IsTrue(IsLocalOnlyUriScheme(L"local+uri-scheme"));

        // The crux question: does the assoc query API detect the LocalOnly value
        // when it is registered as REG_NONE? REG_NONE is the recommended type: a
        // presence-only marker that carries no payload, avoiding the odd REG_DWORD=0
        // (which reads like "off" while still being present).
        //
        // REG_DWORD also works (the assoc query API detects the value regardless of
        // its type), but REG_NONE is preferred, so only REG_NONE is tested here.
        schemeKey = wil::reg::create_unique_key(HKEY_CURRENT_USER, LR"(Software\Classes\uri-scheme-local-only-none)", wil::reg::key_access::readwrite);
        wil::reg::set_value(schemeKey.get(), L"URL Protocol", L"");
        wil::reg::set_value_binary(schemeKey.get(), L"LocalOnly", REG_NONE, {});
        cpp_unit::Assert::IsTrue(IsLocalOnlyUriScheme(L"uri-scheme-local-only-none"));
    }
};

// POC: detect whether a URI scheme is handled by a packaged app, and whether a
// packaged handler has declared the scheme "local only" via the AppExtension contract.
TEST_CLASS(PackagedUriSchemeDetection)
{
public:
    static void LogPackageResult(PCWSTR scheme, UriSchemeHandlerPackage const& pkg)
    {
        if (pkg.isPackaged)
        {
            cpp_unit::LogMessage(L"%-20ls PACKAGED   family=%ls  full=%ls  (aumid=%ls)",
                scheme, pkg.packageFamilyName.c_str(),
                pkg.packageFullName.empty() ? L"<unresolved>" : pkg.packageFullName.c_str(),
                pkg.appUserModelId.c_str());
        }
        else if (!pkg.appUserModelId.empty())
        {
            cpp_unit::LogMessage(L"%-20ls unpackaged (classic handler, appId=%ls)", scheme, pkg.appUserModelId.c_str());
        }
        else
        {
            cpp_unit::LogMessage(L"%-20ls no handler / no AppUserModelID", scheme);
        }
    }

    // Enumerate well-known schemes that typically have packaged or unpackaged handlers.
    // Results are machine-dependent (depends on what's installed / set as default), so
    // these are LOGGED for inspection; only stable invariants are asserted.
    TEST_METHOD(DetectPackagedUriSchemes)
    {
        // Schemes commonly served by packaged (MSIX/appx) apps.
        PCWSTR likelyPackaged[] = {
            L"ms-photos",       // Microsoft.Windows.Photos
            L"bingmaps",        // Microsoft.WindowsMaps
            L"ms-drive-to",     // Microsoft.WindowsMaps
            L"ms-store",        // Microsoft.WindowsStore
            L"ms-windows-store",// Microsoft.WindowsStore
            L"ms-clock",        // Microsoft.WindowsAlarms
            L"ms-people",       // Microsoft.People
            L"ms-settings",     // Windows.ImmersiveControlPanel (system, packaged)
            L"ms-search",       // shell search (system)
            L"ms-shellhost",    // ShellHost (system, packaged)
        };

        // Schemes commonly served by classic (unpackaged) handlers.
        PCWSTR likelyUnpackaged[] = {
            L"http",            // default browser (e.g. MSEdge desktop)
            L"https",
            L"mailto",          // default mail client
        };

        cpp_unit::LogMessage(L"--- likely packaged ---");
        for (auto scheme : likelyPackaged)
        {
            LogPackageResult(scheme, GetUriSchemeHandlerPackage(scheme));
        }

        cpp_unit::LogMessage(L"--- likely unpackaged ---");
        for (auto scheme : likelyUnpackaged)
        {
            LogPackageResult(scheme, GetUriSchemeHandlerPackage(scheme));
        }

        // Invariant: a scheme with no handler is never reported as packaged.
        auto none = GetUriSchemeHandlerPackage(L"this-scheme-does-not-exist-zzz");
        cpp_unit::Assert::IsFalse(none.isPackaged);
        cpp_unit::Assert::IsTrue(none.packageFamilyName.empty());

        // Invariant: when a scheme IS reported packaged, the AUMID parsed into a family name.
        for (auto scheme : likelyPackaged)
        {
            auto pkg = GetUriSchemeHandlerPackage(scheme);
            if (pkg.isPackaged)
            {
                cpp_unit::Assert::IsFalse(pkg.packageFamilyName.empty());
                cpp_unit::Assert::AreNotEqual(std::wstring::npos, pkg.appUserModelId.find(L'!'));
            }
        }
    }

    // POC of the AppExtension-based local-only detection. On a typical dev box no package
    // declares the contract yet, so this enumerates (likely empty) and logs whatever is found.
    TEST_METHOD(EnumerateLocalOnlyAppExtensions)
    {
        auto extensions = RunOnMtaThread([] { return CollectLocalOnlyAppExtensionSchemes(); });

        cpp_unit::LogMessage(L"contract '%ls' declared by %zu extension(s)",
            c_localOnlyUriSchemeContract, extensions.size());
        for (auto const& e : extensions)
        {
            cpp_unit::LogMessage(L"  id=%ls  package=%ls", e.extensionId.c_str(), e.packageFamilyName.c_str());
            cpp_unit::LogMessage(L"    raw props: %ls", e.rawProps.c_str());
            cpp_unit::LogMessage(L"    resolved schemes (%zu):", e.schemes.size());
            for (auto const& s : e.schemes)
            {
                cpp_unit::LogMessage(L"      %ls", s.c_str());
            }
        }

        // Demonstrate the resolver shape: "is this packaged scheme local only?"
        auto isLocalOnlyPackagedScheme = [&](std::wstring_view scheme)
        {
            for (auto const& e : extensions)
            {
                for (auto const& s : e.schemes)
                {
                    if (s == scheme)
                    {
                        return true;
                    }
                }
            }
            return false;
        };

        // No assertion on a specific scheme (registration is environment-provided); just
        // confirm the resolver runs against the enumerated set without throwing.
        cpp_unit::LogMessage(L"is 'local+alpha' local-only (packaged)? %d",
            isLocalOnlyPackagedScheme(L"local+alpha") ? 1 : 0);
    }
};

}
