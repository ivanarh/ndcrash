# NDCrash fork #

**NDCrash** is a powerful crash reporting library for Android NDK applications. The author was inspired by PLCrashReporter and Google Breakpad. Note that this library is new and has a an experimental status.

Fork from [ivanarh](https://github.com/ivanarh/ndcrash).

## Added features ##

* Added ndcrash_in_dump_backtrace : Dump current backtrace into file using unwinder (only libunwindstack supported).
* Added ndcrash_out_trigger_dump : Triggers a manual dump of thread states.
* Added back Linux/x86 support for libunwindstack (tested on Debian).
