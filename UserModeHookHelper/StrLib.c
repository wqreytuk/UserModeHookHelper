#include "StrLib.h"

BOOLEAN SL_EqualWideString(WCHAR* a1, WCHAR* a2, BOOLEAN ignoreCase) {
	// Treat NULL pointers as unequal to any non-NULL string. If both are NULL,
	// consider them equal.
	if (a1 == NULL && a2 == NULL) return TRUE;
	if (a1 == NULL || a2 == NULL) return FALSE;

	UNICODE_STRING uniA1;
	UNICODE_STRING uniA2;
	RtlInitUnicodeString(&uniA1, a1);
	RtlInitUnicodeString(&uniA2, a2);
	return RtlEqualUnicodeString(&uniA1, &uniA2, ignoreCase);
}

BOOLEAN
NTAPI
SL_RtlSuffixUnicodeString(
	_In_ PUNICODE_STRING Suffix,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
)
{
	//
	// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
	//

	return String2->Length >= Suffix->Length &&
		RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - Suffix->Length) / sizeof(WCHAR),
			Suffix->Length / sizeof(WCHAR),
			Suffix->Buffer,
			Suffix->Length / sizeof(WCHAR),
			CaseInSensitive) == 0;

}

BOOLEAN SL_ConcatWideString(_In_opt_ const WCHAR* A, _In_opt_ const WCHAR* B, _Out_writes_(OutChars) PWCHAR Out, SIZE_T OutChars) {
	if (!Out || OutChars == 0) return FALSE;

	SIZE_T lenA = 0;
	SIZE_T lenB = 0;
	if (A) lenA = wcslen(A);
	if (B) lenB = wcslen(B);

	// need space for lenA + lenB + null
	SIZE_T need = lenA + lenB + 1;
	if (need > OutChars) return FALSE;

	// copy A then B
	if (lenA > 0) RtlCopyMemory(Out, A, lenA * sizeof(WCHAR));
	if (lenB > 0) RtlCopyMemory(Out + lenA, B, lenB * sizeof(WCHAR));
	Out[lenA + lenB] = L'\0';
	return TRUE;
}

ULONGLONG SL_ComputeNtPathHash(_In_reads_bytes_opt_(ByteLen) const PUCHAR Bytes, _In_ SIZE_T ByteLen) {
	if (!Bytes || ByteLen == 0) return 0;

	// FNV-1a 64-bit constants
	const ULONGLONG FNV_offset = 14695981039346656037ULL;
	const ULONGLONG FNV_prime = 1099511628211ULL;
	ULONGLONG hash = FNV_offset;

	for (SIZE_T i = 0; i < ByteLen; ++i) {
		hash ^= (ULONGLONG)Bytes[i];
		hash *= FNV_prime;
	}
	return hash;
}

ULONGLONG SL_ComputeNtPathHashUnicode(_In_ PUNICODE_STRING Path) {
	if (!Path || !Path->Buffer || Path->Length == 0) return 0;
	return SL_ComputeNtPathHash((const PUCHAR)Path->Buffer, Path->Length);
}