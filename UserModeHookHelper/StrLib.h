#ifndef STRLIB_H
#define STRLIB_H
#include "Common.h"
BOOLEAN SL_EqualWideString(WCHAR* a1, WCHAR* a2, BOOLEAN ignoreCase);
// Concatenate two NUL-terminated wide strings (treat NULL as empty).
// Writes result into caller-provided buffer 'Out' which has capacity 'OutChars'
// characters. On success returns TRUE and Out contains a NUL-terminated
// wide string. On failure (invalid params or insufficient capacity) returns
// FALSE and Out contents are undefined.
BOOLEAN SL_ConcatWideString(_In_opt_ const WCHAR* A, _In_opt_ const WCHAR* B, _Out_writes_(OutChars) PWCHAR Out, SIZE_T OutChars);

BOOLEAN
NTAPI
SL_RtlSuffixUnicodeString(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
);

// Compute 64-bit FNV-1a hash over UTF-16LE byte buffer (NT-style paths).
// Returns 0 on invalid input, otherwise returns computed hash.
ULONGLONG SL_ComputeNtPathHash(_In_reads_bytes_opt_(ByteLen) const PUCHAR Bytes, _In_ SIZE_T ByteLen);

// Compute 64-bit FNV-1a hash over UNICODE_STRING buffer.
// Returns 0 on invalid input, otherwise returns computed hash.
ULONGLONG SL_ComputeNtPathHashUnicode(_In_ PUNICODE_STRING Path);

#endif