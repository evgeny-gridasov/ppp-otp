#
#

Summary:	PPP OTP authentication support
Name:		ppp-otp
Version:	1.0.2
Release:	1%{?dist}
License:	None
Group:		Applications/Internet
BuildRequires:	ppp-devel, openssl-devel
URL:		https://github.com/evgeny-gridasov/ppp-otp
Source0:	https://github.com/evgeny-gridasov/ppp-otp/archive/1.0.1-2.zip
%global pppver %((%{__awk} '/^#define VERSION/ { print $NF }' /usr/include/pppd/patchlevel.h 2>/dev/null||echo none)|/usr/bin/tr -d '"')
Requires:	ppp = %{pppver}, openssl

%description
OTP tokens authentication support for PPP server

%prep
%setup -q

%build
make

%install
mkdir -p %{buildroot}%{_libdir}/pppd/%{pppver}

install -s -pm 0755 lib/otp.so %{buildroot}%{_libdir}/pppd/%{pppver}/otp.so

%post

%preun

%postun

%files
%{_libdir}/pppd/%{pppver}/otp.so
%attr(0755,root,root) %{_libdir}/pppd/%{pppver}/otp.so

%changelog
* Mon Feb 9 2015 Evgeny Gridasov <evgeny.gridasov@gmail.com> - 1.0.2-1
- Fixed memory corruption 

* Wed Nov 12 2014 Evgeny Gridasov <evgeny.gridasov@gmail.com> - 1.0.1-1
- Added hex support
- Added totp 60 second key support

* Fri Nov 29 2013 Evgeny Gridasov <evgeny.gridasov@gmail.com> - 1.0.0-1
- Added base32 support
- Package up

