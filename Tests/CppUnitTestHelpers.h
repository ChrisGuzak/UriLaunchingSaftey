#ifndef CPPUNITTESTHELPERS_H
#define CPPUNITTESTHELPERS_H

#include <CppUnitTest.h>
#include <wil/result.h>
#include <wil/resource.h>

namespace Microsoft::VisualStudio::CppUnitTestFramework
{
template <typename... args_t>
inline void LogMessage(_Printf_format_string_ const wchar_t* format, args_t&&... args)
{
    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(
        wil::str_printf_failfast<wil::unique_cotaskmem_string>(format, wistd::forward<args_t>(args)...).get());
}
}

struct GlobalInit
{
    GlobalInit()
    {
        wil::SetResultMessageCallback([](wil::FailureInfo* /* failure */, PWSTR debugMessage, size_t) noexcept
        {
            Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(debugMessage);
        });
    }
};

inline GlobalInit g_globalInit;

#endif // CPPUNITTESTHELPERS_H

