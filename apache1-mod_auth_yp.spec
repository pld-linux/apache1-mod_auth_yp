%define		mod_name	auth_yp
%define 	apxs		/usr/sbin/apxs
Summary:	NIS/YP domain authentication module for Apache
Summary(pl):	Modu³ Apache uwierzytelniaj±cy u¿ytkownika w domenie NIS/YP
Name:		apache-mod_%{mod_name}
Version:	1.0
Release:	1
License:	GPL
Group:		Networking/Daemons
Source0:	http://nte.univ-lyon2.fr/~brogniar/articles/mod_%{mod_name}.c
Source1:	%{name}-htaccess
Patch0:		%{name}-authfile.patch
Patch1:		%{name}-shadow.patch
BuildRequires:	apache(EAPI)-devel
Prereq:		%{_sbindir}/apxs
Requires:	apache(EAPI)
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_pkglibdir	%(%{apxs} -q LIBEXECDIR)

%description
Apache module authenticating against a NIS/YP domain.

%description -l pl
Modu³ do apache autoryzuj±cy w domenie NIS/YP.

%prep
%setup -q -T -c -n "mod_%{mod_name}-%{version}"
install %{SOURCE0} .
%patch0
%patch1

%build
%{apxs} \
	-c mod_%{mod_name}.c \
	-o mod_%{mod_name}.so

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT%{_pkglibdir}

install mod_%{mod_name}.so $RPM_BUILD_ROOT%{_pkglibdir}
install %{SOURCE1} ./sample-htaccess

%post
%{apxs} -e -a -n %{mod_name} %{_pkglibdir}/mod_%{mod_name}.so 1>&2
if [ -f /var/lock/subsys/httpd ]; then
	/etc/rc.d/init.d/httpd restart 1>&2
fi

%preun
if [ "$1" = "0" ]; then
	%{apxs} -e -A -n %{mod_name} %{_pkglibdir}/mod_%{mod_name}.so 1>&2
	if [ -f /var/lock/subsys/httpd ]; then
		/etc/rc.d/init.d/httpd restart 1>&2
	fi
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc sample-htaccess
%attr(755,root,root) %{_pkglibdir}/*
