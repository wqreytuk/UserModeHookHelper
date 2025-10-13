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