-- Add the release and debug rules
-- (release will be used by default unless you pass -m)
add_rules("mode.release", "mode.debug")

-- Optional: You can specify platform and arch via command line:
-- `xmake f -p macosx -a arm64 -m release`
target("crypto_speck")
-- Set the target kind to a shared library (.dll on Windows, .dylib on macOS)
set_kind("shared")
-- Set the C and C++ language standards
set_languages("c11", "c++17")
-- Recursively add all C source files from lib and src directories
add_files("src/**.c")
-- Recursively add all header files from lib and src directories
add_headerfiles("src/**.h")

-- Initialize the include directories list with base folders
local includes = { ".", "src", "test" }
-- Dynamically find and add all subdirectories in src to the includes list
for _, dir in ipairs(os.dirs("src/**")) do
    table.insert(includes, dir)
end

-- Apply the collected include directories to the target
add_includedirs(includes)

-- Ensure macOS builds use a stable SDK symlink path so standard headers
-- (e.g. inttypes.h) resolve even if a stale versioned SDK path is cached.
if is_plat("macosx") then
    local sdk_path =
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    if os.isdir(sdk_path) then
        add_cxflags("-isysroot " .. sdk_path, { force = true })
        add_ldflags("-isysroot " .. sdk_path, { force = true })
    end
end

-- Set the C runtime library to multi-threaded (MT) only for Windows
if is_plat("windows") then
    set_runtimes("MT")
end

-- Define a test suite for the security access module
add_tests("crypto_speck_test", {
    -- The test target is a standalone binary
    kind = "binary",
    -- Use C11 for the test code
    languages = "c11",
    -- The main test source file
    files = { "test/test.c" },
    -- Reuse the same include directories as the main target
    includes = includes,
})

-- Optimization and linker flags for release mode
if is_mode("release") then
    if is_plat("windows") then
        -- Enable Level 2 optimizations (/O2)
        add_cxflags("/O2", { force = true })
        -- Disable incremental linking for faster final builds
        add_ldflags("/INCREMENTAL:NO", { force = true })
    else
        -- For macOS/Linux (Clang/GCC)
        set_optimize("fastest")
    end
end

target("test")
set_kind("phony")
