"""The interactive build behind build.py.

    console.py   terminal output and prompts (no platform knowledge)
    core.py      what every platform shares: repository root, build plan, prerequisite checks, helpers
    linux.py     everything specific to Linux   (kernelguard.ko + kgmon, built from linux/)
    windows.py   everything specific to Windows (KernelGuard.sys + KernelGuardMonitor.exe, built from windows/)
    cli.py       options and the platform-neutral flow: ask, check, build, verify

linux.py and windows.py never import each other; cli.py is the only place that knows both exist.
A platform is a module that provides:

    ID, TITLE, PRODUCES     name of the platform, as shown in the menu
    COMPONENTS              (value, label, note) rows for the "Components" question
    CHECKS_REQUIRED         True if the build needs what the prerequisite checks find, so --skip-checks
                            must still run them (silently)
    PLAN                    the core.Plan subclass holding this platform's settings
    unavailable(host_os, host_arch)   why this platform cannot be built on this host, or None
    describe_host(host_arch)          one-line description of a host of this platform
    configure(plan, args, interactive)  platform-specific options and questions, answered into the plan
    plan_rows(plan)         extra (label, value) rows for the "Build plan" summary
    checks(plan, chk)       prerequisite checks, reported through a core.Checks
    build(plan)             run the build
    outputs(plan)           files a successful build must have produced
    report(plan)            what to do next
"""
