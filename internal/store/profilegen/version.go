package profilegen

// FrameworkUUID and PluginUUID pin the Apple images consumed by the bootstrap.
const FrameworkUUID = "475AB715-9F47-37FC-B7E6-723FE441D5C3"
const PluginUUID = "90000BC8-171B-33D7-AB53-5E9338B18DBC"

// Increment bootstrapRevision whenever generation or the profile format changes.
const bootstrapRevision = "3"

// Version identifies the pinned inputs and bootstrap implementation.
func Version() string {
	return "macos-27-26C5035r-unicorn-" + bootstrapRevision + "-" + digest([]byte(FrameworkUUID + PluginUUID))[:16]
}
