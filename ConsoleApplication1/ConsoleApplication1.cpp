#ifndef UNICODE
#define UNICODE
#endif
#ifndef __UNICODE
#define __UNICODE
#endif

#include <stdio.h>
#include <windows.h>
#include <guiddef.h>
#include <stdio.h>

int wmain(int argc, wchar_t *argv[])
{
	// https://learn.microsoft.com/en-us/troubleshoot/windows-server/application-management/0x80004027-remotely-access-com-plus-object
	if (argc != 5) {
		wprintf(L"Invalid arguments\n");
		return 1;
	}
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-comt/7b6d157b-8158-4041-a1b8-186b43a2422c
	const GUID clsid = {
		0xECABB0C4, 0x7F19, 0x11D2,
		{ 0x97, 0x8E, 0x00, 0x00, 0xF8, 0x75, 0x7E, 0x2A}
	};
	const wchar_t* domain = L"WORKGROUP";
	CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	CoInitializeSecurity(0, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	COAUTHINFO ca = { 0 };
	ca.dwAuthnSvc = RPC_C_AUTHN_WINNT;
	ca.dwAuthzSvc = RPC_C_AUTHZ_NONE;
	ca.dwAuthnLevel = _wtoi(argv[4]);// RPC_C_AUTHN_LEVEL_PKT; // RPC_C_AUTHN_LEVEL_DEFAULT;
	ca.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
	COAUTHIDENTITY id = { 0 };
	ca.pAuthIdentityData = &id;
	id.User = (USHORT*)argv[1];
	id.UserLength = wcslen(argv[1]);
	id.Password = (USHORT*)argv[2];
	id.PasswordLength = wcslen(argv[2]);
	id.Domain = (USHORT*)domain;
	id.DomainLength = wcslen(domain);
	id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	COSERVERINFO c = { 0 };
	c.pwszName = argv[3];
	c.pAuthInfo = &ca;
	MULTI_QI res = { 0 };
	res.pIID = &IID_IUnknown;
	HRESULT hr = CoCreateInstanceEx(clsid, 0, CLSCTX_REMOTE_SERVER, &c, 1, &res);
	wprintf(L"hr = 0x%08x\n", hr);
	if (SUCCEEDED(hr)) {
		res.pItf->Release();
	}
	CoUninitialize();
	return 0;
}
