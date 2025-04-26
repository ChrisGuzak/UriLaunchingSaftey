#include "pch.h"

template <typename HostT>
class ActivationServiceProvider : public winrt::implements<ActivationServiceProvider<HostT>, IServiceProvider, IHandlerActivationHost>
{
public:
    ActivationServiceProvider(HostT* host = nullptr) : m_host(host)
    {
    }

    // IServiceProvider
    IFACEMETHODIMP QueryService(REFGUID serviceId, REFIID riid, __deref_out void** ppv) noexcept override
    {
        *ppv = nullptr;
        return (serviceId == SID_SHandlerActivationHost) ? QueryInterface(riid, ppv) : E_NOTIMPL;
    }

    // IHandlerActivationHost
    IFACEMETHODIMP BeforeCoCreateInstance(REFCLSID clsidHandler, _In_opt_ IShellItemArray* items, IHandlerInfo* handlerInfo) noexcept override
    {
        m_host->BeforeCoCreateInstance(clsidHandler, items, handlerInfo);
        m_host->ReportHandlerInfo(handlerInfo);
        return S_OK;
    }

    IFACEMETHODIMP BeforeCreateProcess(PCWSTR applicationPath, PCWSTR commandLine, IHandlerInfo* handlerInfo) noexcept override
    {
        m_host->BeforeCreateProcess(applicationPath, commandLine, handlerInfo);
        m_host->ReportHandlerInfo(handlerInfo);
        return S_OK;
    }

    IUnknown* GetAsSite()
    {
        return static_cast<IServiceProvider*>(this);
    }

private:
    HostT* m_host;
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
                    cpp_unit::LogMessage(L"MinimumZone %d", minZone);
                    if (static_cast<URLZONE>(minZone) < zoneOfLaunchInput) // "less than" test as zone values increase for lower trust
                    {
                        cpp_unit::LogMessage(L"Launch blocked");
                    }
                }
            }
        }
    }

    TEST_METHOD(LaunchWithShellExecute)
    {
        auto service = winrt::make_self<ActivationServiceProvider<UseCases>>(this);

        PCWSTR uri = L"http://www.msn.com";

        wil::com_ptr<IShellItem> uriItem;
        THROW_IF_FAILED(SHCreateItemFromParsingName(uri, nullptr, IID_PPV_ARGS(&uriItem)));

        ShellExecuteItemWithVerb(nullptr, service->GetAsSite(), nullptr, nullptr, uriItem.get());
    }

    TEST_METHOD(DetectLocalOnlyUriSchemes)
    {
    }
};

}
