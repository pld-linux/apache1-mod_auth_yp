%define		mod_name	auth_yp
%define 	apxs		/usr/sbin/apxs1
Summary:	NIS/YP domain authentication module for Apache
Summary(pl):	Modu³ Apache'a uwierzytelniaj±cy u¿ytkownika w domenie NIS/YP
Name:		apache1-mod_%{mod_name}
Version:	1.0
Release:	1.3
License:	GPL
Group:		Networking/Daemons
Source0:	http://nte.univ-lyon2.fr/~brogniar/articles/mod_%{mod_name}.c
Source1:	%{name}-htaccess
Patch0:		%{name}-authfile.patch
Patch1:		%{name}-shadow.patch
BuildRequires:	%{apxs}
BuildRequires:	apache1-devel >= 1.3.33-2
Requires(triggerpostun):	%{apxs}
Requires:	apache1 >= 1.3.33-2
Obsoletes:	apache-mod_%{mod_name} <= %{version}
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_pkglibdir	%(%{apxs} -q LIBEXECDIR 2>/dev/null)
%define		_sysconfdir	%(%{apxs} -q SYSCONFDIR 2>/dev/null)

%description
Apache module authenticating against a NIS/YP domain.

%description -l pl
Modu³ do Apache'a autoryzuj±cy w domenie NIS/YP.

%prep
%setup -q -T -c -n "mod_%{mod_name}-%{version}"
install %{SOURCE0} .
%patch0
%patch1

%build
%{apxs} \
	-c mod_%{mod_name}.c \
	-o mod_%{mod_name}.so \
	-l nsl

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_pkglibdir},%{_sysconfdir}/conf.d}

install mod_%{mod_name}.so $RPM_BUILD_ROOT%{_pkglibdir}
install %{SOURCE1} ./sample-htaccess

echo 'LoadModule %{mod_name}_module	modules/mod_%{mod_name}.so' > \
	$RPM_BUILD_ROOT%{_sysconfdir}/conf.d/90_mod_%{mod_name}.conf

%post
if [ -f /var/lock/subsys/apache ]; then
	/etc/rc.d/init.d/apache restart 1>&2
fi

%preun
if [ "$1" = "0" ]; then
	if [ -f /var/lock/subsys/apache ]; then
		/etc/rc.d/init.d/apache restart 1>&2
	fi
fi

%clean
rm -rf $RPM_BUILD_ROOT

%triggerpostun -- apache1-mod_%{mod_name} < 1.0-1.1
# check that they're not using old apache.conf
if grep -q '^Include conf\.d' /etc/apache/apache.conf; then
	%{apxs} -e -A -n %{mod_name} %{_pkglibdir}/mod_%{mod_name}.so 1>&2
fi

%files
%defattr(644,root,root,755)
%doc sample-htaccess
%attr(640,root,root) %config(noreplace) %verify(not size mtime md5) %{_sysconfdir}/conf.d/*_mod_%{mod_name}.conf
%attr(755,root,root) %{_pkglibdir}/*
