package rules

// Omitted files.
//
// A collector (CollectDir, FetchSnapshot) does not always supply every file in
// a package: some exceed the per-file cap, some fail the text test, and once
// the aggregate cap is reached the remainder are skipped entirely. openssl-1.1
// carries 41 patches totalling 382 KB, so the tail of that list never reaches
// the scanner.
//
// Before this existed, such a file was simply absent, and absent is
// indistinguishable from "not in the repository". Two things went wrong as a
// result. REF-004 reported the scanner's own truncation as a missing source —
// a finding about aurscan dressed up as a finding about the package. And more
// seriously, the auditor prompt asserted that the supplied file list was
// exhaustive, which on such a package is false: a payload in the 41st patch
// would be reviewed by a model that had been told it saw everything.
//
// So a skipped file is now RECORDED rather than dropped. It appears in the file
// set with OmittedContent as its content, which means:
//
//   - reference resolution finds it, so REF-004 stays quiet about a file that
//     is present in the repository;
//   - the pattern rules skip it, since there is nothing to match;
//   - the prompt lists it separately as NOT reviewed, so the model's picture of
//     its own coverage is accurate.
//
// The marker begins with a NUL so it can never collide with real file content:
// every collector rejects non-text input via isTexty before this point.
const OmittedContent = "\x00aurscan:omitted"

// IsOmitted reports whether a file's content is the omission marker rather than
// the file itself.
func IsOmitted(content string) bool { return content == OmittedContent }
