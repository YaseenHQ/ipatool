package machine

// macOS27SharedCacheFunctions maps the external function pointers used by the
// AppleMediaServices image extracted from the macOS 27.3 (26C5035r) arm64e
// shared cache. The extraction has its cache slide applied, so these values are
// stable for this exact build and are replaced with emulator services at load
// time.
var macOS27SharedCacheFunctions = map[uint64]string{
	0x0000000180549604: "___error",
	0x0000000180589ba8: "_pthread_once",
	0x000000018058a6dc: "_pthread_rwlock_unlock",
	0x000000018058a7a4: "_pthread_rwlock_wrlock",
	0x000000018058b2bc: "_pthread_rwlock_init",
	0x00000001805abcc8: "_sysctlbyname",
	0x00000001805acec4: "_gettimeofday",
	0x00000001805b2fb8: "_arc4random",
	0x00000001805b48a4: "___memset_chk",
	0x0000000180621418: "_abort",
	0x0000000181e96ce8: "_malloc",
	0x0000000181e976f0: "_free",
	0x000000018471f540: "_CFStringCreateWithCString",
	0x0000000184724200: "_CFStringGetLength",
	0x00000001847244dc: "_CFStringGetCString",
	0x0000000184727278: "_CFRelease",
	0x00000001847389e8: "_CFDataGetLength",
	0x0000000184ebc4cc: "_IOServiceMatching",
	0x0000000184ebd168: "_IOServiceGetMatchingServices",
	0x0000000184ebd4fc: "_IOIteratorNext",
	0x0000000184ebdb50: "_IOObjectRelease",
	0x0000000185598570: "_dispatch_once",
	0x00000001855dbb40: "_strlen",
}

var macOS27SharedCacheSlots = map[uint64]string{}
