Name:           libtlsrpt
Version:        0.5.0 
Release:        1%{?dist}
Summary:        Interface library to implement TLSRPT reporting into an MTA and to generate and submit TLSRPT reports.

License:        GPLv3+
URL:            https://github.com/sys4/tlsrpt
Source0:        libtlsrpt-0.5.0.tar.gz 

%description
Interface library to implement TLSRPT reporting into an MTA and to generate and submit TLSRPT reports.
The libtlsrpt library sends the data to the TLSRPT-receiver daemonn which collects and pre-aggregates the report data.


%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%prep
%autosetup


%build
%configure --disable-static
%make_build


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
#%license add-license-file-here
#%doc add-main-docs-here
%{_libdir}/*.so.*

%files devel
#%doc add-devel-docs-here
%{_includedir}/*
%{_libdir}/*.so


%changelog
* Fri Oct  4 2024 Boris Lohner <bl@sys4.de>
- 
