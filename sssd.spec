%global rhel7_minor %(%{__grep} -o "7.[0-9]*" /etc/redhat-release |%{__sed} -s 's/7.//')

# we don't want to provide private python extension libs
%define __provides_exclude_from %{python_sitearch}/.*\.so$|%{_libdir}/%{name}/modules/libwbclient.so.*$
%define _hardened_build 1

    %global install_pcscd_polkit_rule 1

# Determine the location of the LDB modules directory
%global ldb_modulesdir %(pkg-config --variable=modulesdir ldb)
%global ldb_version 1.1.17


%if (0%{?fedora} || 0%{?rhel} >= 7)
    %global with_cifs_utils_plugin 1
%else
    %global with_cifs_utils_plugin_option --disable-cifs-idmap-plugin
%endif

    %global with_krb5_localauth_plugin 1

%global libwbc_alternatives_version 0.13
%global libwbc_lib_version %{libwbc_alternatives_version}.0
%global libwbc_alternatives_suffix %nil
%if 0%{?__isa_bits} == 64
%global libwbc_alternatives_suffix -64
%endif

%global enable_systemtap 1
%if (0%{?enable_systemtap} == 1)
    %global enable_systemtap_opt --enable-systemtap
%endif

%if (0%{?fedora} >= 23 || 0%{?rhel} >= 7)
    %global with_kcm 1
    %global with_kcm_option --with-kcm
%else
    %global with_kcm_option --without-kcm
%endif

Name: sssd
Version: 1.15.2
Release: 50.el7_4.2.ns7
Group: Applications/System
Summary: System Security Services Daemon
License: GPLv3+
URL: https://pagure.io/SSSD/sssd/
Source0: https://releases.pagure.org/SSSD/sssd/sssd-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

### Patches ###
Patch0001: 0001-MAN-Mention-sssd-secrets-in-SEE-ALSO-section.patch
Patch0002: 0002-split_on_separator-move-to-a-separate-file.patch
Patch0003: 0003-util-move-string_in_list-to-util_ext.patch
Patch0004: 0004-certmap-add-new-library-libsss_certmap.patch
Patch0005: 0005-certmap-add-placeholder-for-OpenSSL-implementation.patch
Patch0006: 0006-sysdb-add-sysdb_attrs_copy.patch
Patch0007: 0007-sdap_get_users_send-new-argument-mapped_attrs.patch
Patch0008: 0008-LDAP-always-store-the-certificate-from-the-request.patch
Patch0009: 0009-sss_cert_derb64_to_ldap_filter-add-sss_certmap-suppo.patch
Patch0010: 0010-sysdb-add-certmap-related-calls.patch
Patch0011: 0011-IPA-add-certmap-support.patch
Patch0012: 0012-nss-idmap-add-sss_nss_getlistbycert.patch
Patch0013: 0013-nss-allow-larger-buffer-for-certificate-based-reques.patch
Patch0014: 0014-IPA-Add-s2n-request-to-string-function.patch
Patch0015: 0015-IPA-Enhance-debug-logging-for-ipa-s2n-operations.patch
Patch0016: 0016-UTIL-iobuf-Make-input-parameter-for-the-readonly-ope.patch
Patch0017: 0017-UTIL-Fix-a-typo-in-the-tcurl-test-tool.patch
Patch0018: 0018-UTIL-Add-SAFEALIGN_COPY_UINT8_CHECK.patch
Patch0019: 0019-UTIL-Add-utility-macro-cli_creds_get_gid.patch
Patch0020: 0020-UTIL-Add-type-specific-getsetters-to-sss_iobuf.patch
Patch0021: 0021-UTIL-krb5-principal-un-marshalling.patch
Patch0022: 0022-KCM-Initial-responder-build-and-packaging.patch
Patch0023: 0023-KCM-request-parsing-and-sending-a-reply.patch
Patch0024: 0024-KCM-Implement-an-internal-ccache-storage-and-retriev.patch
Patch0025: 0025-KCM-Add-a-in-memory-credential-storage.patch
Patch0026: 0026-KCM-Implement-KCM-server-operations.patch
Patch0027: 0027-MAN-Add-a-manual-page-for-sssd-kcm.patch
Patch0028: 0028-TESTS-Add-integration-tests-for-the-KCM-responder.patch
Patch0029: 0029-SECRETS-Create-DB-path-before-the-operation-itself.patch
Patch0030: 0030-SECRETS-Return-a-nicer-error-message-on-request-with.patch
Patch0031: 0031-SECRETS-Store-ccaches-in-secrets-for-the-KCM-respond.patch
Patch0032: 0032-TCURL-Support-HTTP-POST-for-creating-containers.patch
Patch0033: 0033-KCM-Store-ccaches-in-secrets.patch
Patch0034: 0034-KCM-Make-the-secrets-ccache-back-end-configurable-ma.patch
Patch0035: 0035-KCM-Queue-requests-by-the-same-UID.patch
Patch0036: 0036-KCM-Idle-terminate-the-responder-if-the-secrets-back.patch
Patch0037: 0037-CONFIGURE-Fix-fallback-if-pkg-config-for-uuid-is-mis.patch
Patch0038: 0038-intg-fix-configure-failure-with-strict-cflags.patch
Patch0039: 0039-intg-Remove-bashism-from-intgcheck-prepare.patch
Patch0040: 0040-UTIL-Introduce-subdomain_create_conf_path.patch
Patch0041: 0041-SUBDOMAINS-Allow-use_fully_qualified_names-for-subdo.patch
Patch0042: 0042-CACHE_REQ-Descend-into-subdomains-on-lookups.patch
Patch0043: 0043-NSS-TESTS-Fix-subdomains-attribution.patch
Patch0044: 0044-NSS-TESTS-Improve-setup-teardown-for-subdomains-test.patch
Patch0045: 0045-NSS-TESTS-Include-searches-for-non-fqnames-members-o.patch
Patch0046: 0046-SYSDB-Add-methods-to-deal-with-the-domain-s-resoluti.patch
Patch0047: 0047-SYSDB-TESTS-Add-tests-for-the-domain-s-resolution-or.patch
Patch0048: 0048-IPA-Get-ipaDomainsResolutionOrder-from-ipaConfig.patch
Patch0049: 0049-IPA_SUBDOMAINS-Rename-_refresh_view-to-_refresh_view.patch
Patch0050: 0050-IPA-Get-ipaDomainsResolutionOrder-from-IPA-ID-View.patch
Patch0051: 0051-DLINKLIST-Add-DLIST_FOR_EACH_SAFE-macro.patch
Patch0052: 0052-CACHE_REQ-Make-use-of-domainResolutionOrder.patch
Patch0053: 0053-UTIL-Expose-replace_char-as-sss_replace_char.patch
Patch0054: 0054-Add-domain_resolution_order-config-option.patch
Patch0055: 0055-ssh-handle-binary-keys-correctly.patch
Patch0056: 0056-ssh-add-support-for-certificates-from-non-default-vi.patch
Patch0057: 0057-krb5-return-to-responder-that-pkinit-is-not-availabl.patch
Patch0058: 0058-IPA-add-mapped-attributes-to-user-from-trusted-domai.patch
Patch0059: 0059-IPA-lookup-AD-users-by-certificates-on-IPA-clients.patch
Patch0060: 0060-IPA-enable-AD-user-lookup-by-certificate.patch
Patch0061: 0061-CONFDB-Introduce-SSSD-domain-type-to-distinguish-POS.patch
Patch0062: 0062-CONFDB-Allow-configuring-application-sections-as-non.patch
Patch0063: 0063-CACHE_REQ-Domain-type-selection-in-cache_req.patch
Patch0064: 0064-IFP-Search-both-POSIX-and-non-POSIX-domains.patch
Patch0065: 0065-IFP-ListByName-Don-t-crash-when-no-results-are-found.patch
Patch0066: 0066-PAM-Remove-unneeded-memory-context.patch
Patch0067: 0067-PAM-Add-application-services.patch
Patch0068: 0068-SYSDB-Allow-storing-non-POSIX-users.patch
Patch0069: 0069-SYSDB-Only-generate-new-UID-in-local-domain.patch
Patch0070: 0070-LDAP-save-non-POSIX-users-in-application-domains.patch
Patch0071: 0071-LDAP-Relax-search-filters-in-application-domains.patch
Patch0072: 0072-KRB5-Authenticate-users-in-a-non-POSIX-domain-using-.patch
Patch0073: 0073-KCM-Fix-off-by-one-error-in-secrets-key-parsing.patch
Patch0074: 0074-tcurl-add-support-for-ssl-and-raw-output.patch
Patch0075: 0075-tcurl-test-refactor-so-new-options-can-be-added-more.patch
Patch0076: 0076-tcurl-test-add-support-for-raw-output.patch
Patch0077: 0077-tcurl-test-add-support-for-tls-settings.patch
Patch0078: 0078-tcurl-add-support-for-http-basic-auth.patch
Patch0079: 0079-tcurl-test-allow-to-set-custom-headers.patch
Patch0080: 0080-tcurl-test-add-support-for-client-certificate.patch
Patch0081: 0081-ci-do-not-build-secrets-on-rhel6.patch
Patch0082: 0082-build-make-curl-required-by-secrets.patch
Patch0083: 0083-secrets-use-tcurl-in-proxy-provider.patch
Patch0084: 0084-secrets-remove-http-parser-code-in-proxy-provider.patch
Patch0085: 0085-secrets-allow-to-configure-certificate-check.patch
Patch0086: 0086-secrets-support-HTTP-basic-authentication-with-proxy.patch
Patch0087: 0087-secrets-fix-debug-message.patch
Patch0088: 0088-secrets-always-add-Content-Length-header.patch
Patch0089: 0089-sss_iobuf-fix-read-shadows-a-global-declaration.patch
Patch0090: 0090-configure-fix-typo.patch
Patch0091: 0091-pam_test_client-add-service-and-environment-to-PAM-t.patch
Patch0092: 0092-pam_test_client-add-SSSD-getpwnam-lookup.patch
Patch0093: 0093-sss_sifp-update-method-names.patch
Patch0094: 0094-pam_test_client-add-InfoPipe-user-lookup.patch
Patch0095: 0095-sssctl-integrate-pam_test_client-into-sssctl.patch
Patch0096: 0096-i18n-adding-sssctl-files.patch
Patch0097: 0097-responders-do-not-leak-selinux-context-on-clients-de.patch
Patch0098: 0098-ipa_s2n_get_acct_info_send-provide-correct-req_input.patch
Patch0099: 0099-config-check-Message-when-sssd.conf-is-missing.patch
Patch0100: 0100-sbus-check-connection-for-NULL-before-unregister-it.patch
Patch0101: 0101-selinux-Do-not-fail-if-SELinux-is-not-managed.patch
Patch0102: 0102-UTIL-Use-max-15-characters-for-AD-host-UPN.patch
Patch0103: 0103-Move-sized_output_name-and-sized_domain_name-into-re.patch
Patch0104: 0104-IFP-Use-sized_domain_name-to-format-the-groups-the-u.patch
Patch0105: 0105-RESPONDER-Fallback-to-global-domain-resolution-order.patch
Patch0106: 0106-NSS-TESTS-Improve-non-fqnames-tests.patch
Patch0107: 0107-CACHE_REQ-Allow-configurationless-shortname-lookups.patch
Patch0108: 0108-CACHE_REQ_DOMAIN-Add-some-comments-to-cache_req_doma.patch
Patch0109: 0109-RESPONDER_COMMON-Improve-domaiN_resolution_order-deb.patch
Patch0110: 0110-CACHE_REQ_DOMAIN-debug-the-set-domain-resolution-ord.patch
Patch0111: 0111-SECRETS-remove-unused-variable.patch
Patch0112: 0112-IPA-Improve-DEBUG-message-if-a-group-has-no-ipaNTSec.patch
Patch0113: 0113-IPA-Improve-s2n-debug-message-for-missing-ipaNTSecur.patch
Patch0114: 0114-CONFDB-Fix-standalone-application-domains.patch
Patch0115: 0115-utils-add-sss_domain_is_forest_root.patch
Patch0116: 0116-ad-handle-forest-root-not-listed-in-ad_enabled_domai.patch
Patch0117: 0117-SDAP-Fix-handling-of-search-bases.patch
Patch0118: 0118-overrides-add-certificates-to-mapped-attribute.patch
Patch0119: 0119-AD-Make-ad_account_can_shortcut-reusable-by-SSSD-on-.patch
Patch0120: 0120-LDAP-AD-Do-not-fail-in-case-rfc2307bis_nested_groups.patch
Patch0121: 0121-PAM-check-matching-certificates-from-all-domains.patch
Patch0122: 0122-DP-Reduce-Data-Provider-log-level-noise.patch
Patch0123: 0123-NSS-Move-output-name-formatting-to-utils.patch
Patch0124: 0124-CACHE_REQ-Add-a-new-cache_req_ncache_filter_fn-plugi.patch
Patch0125: 0125-CACHE_REQ_RESULT-Introduce-cache_req_create_ldb_resu.patch
Patch0126: 0126-CACHE_REQ-Make-use-of-cache_req_ncache_filter_fn.patch
Patch0127: 0127-SERVER_MODE-Update-sdap-lists-for-each-ad_ctx.patch
Patch0128: 0128-sss_nss_getlistbycert-return-results-from-multiple-d.patch
Patch0129: 0129-CACHE_REQ-Avoid-using-of-uninitialized-value.patch
Patch0130: 0130-CACHE_REQ-Ensure-the-domains-are-updated-for-filter-.patch
Patch0131: 0131-AD-SUBDOMAINS-Fix-search-bases-for-child-domains.patch
Patch0132: 0132-KRB5-Advise-the-user-to-inspect-the-krb5_child.log-i.patch
Patch0133: 0133-cache_req-use-the-right-negative-cache-for-initgroup.patch
Patch0134: 0134-test-make-sure-p11_child-is-build-for-pam-srv-tests.patch
Patch0135: 0135-pam-properly-support-UPN-logon-names.patch
Patch0136: 0136-KCM-Fix-the-per-client-serialization-queue.patch
Patch0137: 0137-TESTS-Add-a-test-for-parallel-execution-of-klist.patch
Patch0138: 0138-ipa-filter-IPA-users-from-extdom-lookups-by-certific.patch
Patch0139: 0139-krb5-accept-changed-principal-if-krb5_canonicalize-T.patch
Patch0140: 0140-IPA-Avoid-using-uninitialized-ret-value-when-skippin.patch
Patch0141: 0141-IPA-Return-from-function-after-marking-a-request-as-.patch
Patch0142: 0142-HBAC-Do-not-rely-on-originalMemberOf-use-the-sysdb-m.patch
Patch0143: 0143-VALIDATORS-Add-subdomain-section.patch
Patch0144: 0144-VALIDATORS-Remove-application-section-domain.patch
Patch0145: 0145-VALIDATORS-Escape-special-regex-chars.patch
Patch0146: 0146-TESTS-Add-unit-tests-for-cfg-validation.patch
Patch0147: 0147-MAN-Fix-typo-in-trusted-domain-section.patch
Patch0148: 0148-VALIDATORS-Change-regex-for-app-domains.patch
Patch0149: 0149-VALIDATORS-Detect-inherit_from-in-normal-domain.patch
Patch0150: 0150-VALIDATOR-prevent-duplicite-report-from-subdomain-se.patch
Patch0151: 0151-test_config_check-Fix-few-issues.patch
Patch0152: 0152-KRB5-Fix-access_provider-krb5.patch
Patch0153: 0153-BUILD-Improve-error-messages-for-optional-dependenci.patch
Patch0154: 0154-RESPONDER_COMMON-update-certmaps-in-responders.patch
Patch0155: 0155-tests-fix-test_pam_preauth_cert_no_logon_name.patch
Patch0156: 0156-pam_sss-add-support-for-SSS_PAM_CERT_INFO_WITH_HINT.patch
Patch0157: 0157-add_pam_cert_response-add-support-for-SSS_PAM_CERT_I.patch
Patch0158: 0158-PAM-send-user-name-hint-response-when-needed.patch
Patch0159: 0159-sysdb-sysdb_get_certmap-allow-empty-certmap.patch
Patch0160: 0160-sssctl-show-user-name-used-for-authentication-in-use.patch
Patch0161: 0161-RESP-Provide-a-reusable-request-to-fully-resolve-inc.patch
Patch0162: 0162-IFP-Only-format-the-output-name-to-the-short-version.patch
Patch0163: 0163-IFP-Resolve-group-names-from-GIDs-if-required.patch
Patch0164: 0164-ldap-handle-certmap-errors-gracefully.patch
Patch0165: 0165-SECRETS-Fix-warning-Wpointer-bool-conversion.patch
Patch0166: 0166-IPA-Fix-the-PAM-error-code-that-auth-code-expects-to.patch
Patch0167: 0167-pam_sss-Fix-checking-of-empty-string-cert_user.patch
Patch0168: 0168-CACHE_REQ-Simplify-_search_ncache_filter.patch
Patch0169: 0169-CACHE_REQ_SEARCH-Check-for-filtered-users-groups-als.patch
Patch0170: 0170-cache_req-Do-not-use-default_domain_suffix-with-netg.patch
Patch0171: 0171-krb5-disable-enterprise-principals-during-password-c.patch
Patch0172: 0172-pam_sss-Fix-leaking-of-memory-in-case-of-failures.patch
Patch0173: 0173-IFP-Add-domain-and-domainname-attributes-to-the-user.patch
Patch0174: 0174-IFP-Fix-error-handling-in-ifp_user_get_attr_handle_r.patch
Patch0175: 0175-SYSDB-Return-ERR_NO_TS-when-there-s-no-timestamp-cac.patch
Patch0176: 0176-SYSDB-Internally-expose-sysdb_search_ts_matches.patch
Patch0177: 0177-SYSDB-Make-the-usage-of-the-filter-more-generic-for-.patch
Patch0178: 0178-SYSDB_OPS-Mark-an-entry-as-expired-also-in-the-times.patch
Patch0179: 0179-SYSDB_OPS-Invalidate-a-cache-entry-also-in-the-ts_ca.patch
Patch0180: 0180-SYSDB-Introduce-_search_-users-groups-_by_timestamp.patch
Patch0181: 0181-LDAP_ID_CLEANUP-Use-sysdb_search_-_by_timestamp.patch
Patch0182: 0182-krb5-use-plain-principal-if-password-is-expired.patch
Patch0183: 0183-RESPONDER-Use-fqnames-as-output-when-needed.patch
Patch0184: 0184-DOMAIN-Add-sss_domain_info_-get-set-_output_fqnames.patch
Patch0185: 0185-GPO-Fix-typo-in-DEBUG-message.patch
Patch0186: 0186-SDAP-Update-parent-sdap_list.patch
Patch0187: 0187-RESPONDERS-Fix-terminating-idle-connections.patch
Patch0188: 0188-TESTS-Integration-test-for-idle-timeout.patch
Patch0189: 0189-MAN-Document-that-client_idle_timeout-can-t-be-short.patch
Patch0190: 0190-ad_account_can_shortcut-shortcut-if-ID-is-unknown.patch

#This patch should not be removed in RHEL-7
Patch999: 0999-NOUPSTREAM-Default-to-root-if-sssd-user-is-not-spec

# Backport patch
# https://pagure.io/SSSD/sssd/issue/3461
# https://bugzilla.redhat.com/show_bug.cgi?id=1462769
Patch1000: 1000-NETHSERVER-bad-samba-auth.patch

### Dependencies ###

Requires: sssd-common = %{version}-%{release}
Requires: sssd-ldap = %{version}-%{release}
Requires: sssd-krb5 = %{version}-%{release}
Requires: sssd-ipa = %{version}-%{release}
Requires: sssd-ad = %{version}-%{release}
Requires: sssd-proxy = %{version}-%{release}
Requires: python-sssdconfig = %{version}-%{release}

%global servicename sssd
%global sssdstatedir %{_localstatedir}/lib/sss
%global dbpath %{sssdstatedir}/db
%global keytabdir %{sssdstatedir}/keytabs
%global pipepath %{sssdstatedir}/pipes
%global mcpath %{sssdstatedir}/mc
%global pubconfpath %{sssdstatedir}/pubconf
%global gpocachepath %{sssdstatedir}/gpo_cache
%global secdbpath %{sssdstatedir}/secrets

### Build Dependencies ###

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: m4
BuildRequires: popt-devel
BuildRequires: libtalloc-devel
BuildRequires: libtevent-devel
BuildRequires: libtdb-devel

# LDB needs a strict version match to build
BuildRequires: libldb-devel >= %{ldb_version}
BuildRequires: libdhash-devel >= 0.4.2
BuildRequires: libcollection-devel
BuildRequires: libini_config-devel >= 1.3.0
BuildRequires: dbus-devel
BuildRequires: dbus-libs
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: nss-devel
BuildRequires: nspr-devel
BuildRequires: pcre-devel
BuildRequires: libxslt
BuildRequires: libxml2
BuildRequires: docbook-style-xsl
BuildRequires: krb5-devel >= 1.12
BuildRequires: c-ares-devel
BuildRequires: python-devel
BuildRequires: check-devel
BuildRequires: doxygen
BuildRequires: libselinux-devel
BuildRequires: libsemanage-devel
BuildRequires: bind-utils
BuildRequires: keyutils-libs-devel
BuildRequires: gettext-devel
BuildRequires: pkgconfig
BuildRequires: diffstat
BuildRequires: findutils
BuildRequires: glib2-devel
BuildRequires: selinux-policy-targeted
BuildRequires: libnl3-devel
BuildRequires: systemd-devel
%if (0%{?with_cifs_utils_plugin} == 1)
BuildRequires: cifs-utils-devel
%endif
BuildRequires: libnfsidmap-devel
BuildRequires: samba4-devel >= 4.0.0-59beta2
BuildRequires: libsmbclient-devel
BuildRequires: systemtap-sdt-devel
BuildRequires: jansson-devel
BuildRequires: http-parser-devel
BuildRequires: curl-devel
BuildRequires: libuuid-devel

%description
Provides a set of daemons to manage access to remote directories and
authentication mechanisms. It provides an NSS and PAM interface toward
the system and a pluggable backend system to connect to multiple different
account sources. It is also the basis to provide client auditing and policy
services for projects like FreeIPA.

The sssd subpackage is a meta-package that contains the deamon as well as all
the existing back ends.

%package common
Summary: Common files for the SSSD
Group: Applications/System
License: GPLv3+
# Conflicts
Conflicts: selinux-policy < 3.10.0-46
Conflicts: sssd < 1.10.0-8%{?dist}.beta2
# Requires
Requires: sssd-client%{?_isa} = %{version}-%{release}
Requires: libsss_idmap%{?_isa} = %{version}-%{release}
Requires: libsss_sudo%{?_isa}  = %{version}-%{release}
Requires: libsss_autofs%{?_isa} = %{version}-%{release}
Requires(post): systemd-units chkconfig
Requires(preun): systemd-units chkconfig
Requires(postun): systemd-units chkconfig
# sssd-common owns sssd.service file and is restarted in posttrans
# libwbclient alternative might break restarting sssd
# gpo_child -> libsmbclient -> samba-client-libs -> libwbclient
OrderWithRequires: libwbclient
OrderWithRequires: sssd-libwbclient

### Provides ###
Provides: libsss_sudo-devel = %{version}-%{release}
Obsoletes: libsss_sudo-devel <= 1.10.0-7%{?dist}.beta1

%description common
Common files for the SSSD. The common package includes all the files needed
to run a particular back end, however, the back ends are packaged in separate
subpackages such as sssd-ldap.

%package client
Summary: SSSD Client libraries for NSS and PAM
Group: Applications/System
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires(post):  /usr/sbin/alternatives
Requires(preun): /usr/sbin/alternatives

%description client
Provides the libraries needed by the PAM and NSS stacks to connect to the SSSD
service.

%package -n libsss_sudo
Summary: A library to allow communication between SUDO and SSSD
Group: Development/Libraries
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsss_sudo
A utility library to allow communication between SUDO and SSSD

%package -n libsss_autofs
Summary: A library to allow communication between Autofs and SSSD
Group: Development/Libraries
License: LGPLv3+

%description -n libsss_autofs
A utility library to allow communication between Autofs and SSSD

%package tools
Summary: Userspace tools for use with the SSSD
Group: Applications/System
License: GPLv3+
Requires: sssd-common = %{version}-%{release}
Requires: python-sss = %{version}-%{release}
Requires: python-sssdconfig = %{version}-%{release}

%description tools
Provides userspace tools for manipulating users, groups, and nested groups in
SSSD when using id_provider = local in /etc/sssd/sssd.conf.

Also provides several other administrative tools:
    * sss_debuglevel to change the debug level on the fly
    * sss_seed which pre-creates a user entry for use in kickstarts
    * sss_obfuscate for generating an obfuscated LDAP password
    * sssctl -- an sssd status and control utility

%package -n python-sssdconfig
Summary: SSSD and IPA configuration file manipulation classes and functions
Group: Applications/System
License: GPLv3+
BuildArch: noarch

%description -n python-sssdconfig
Provides python2 files for manipulation SSSD and IPA configuration files.

%package -n python-sss
Summary: Python2 bindings for sssd
Group: Development/Libraries
License: LGPLv3+
Requires: sssd-common = %{version}-%{release}

%description -n python-sss
Provides python2 module for manipulating users, groups, and nested groups in
SSSD when using id_provider = local in /etc/sssd/sssd.conf.

Also provides several other useful python2 bindings:
    * function for retrieving list of groups user belongs to.
    * class for obfuscation of passwords

%package -n python-sss-murmur
Summary: Python2 bindings for murmur hash function
Group: Development/Libraries
License: LGPLv3+

%description -n python-sss-murmur
Provides python2 module for calculating the murmur hash version 3

%package ldap
Summary: The LDAP back end of the SSSD
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: sssd-common = %{version}-%{release}
Requires: sssd-krb5-common = %{version}-%{release}

%description ldap
Provides the LDAP back end that the SSSD can utilize to fetch identity data
from and authenticate against an LDAP server.

%package krb5-common
Summary: SSSD helpers needed for Kerberos and GSSAPI authentication
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: cyrus-sasl-gssapi%{?_isa}
Requires: sssd-common = %{version}-%{release}

%description krb5-common
Provides helper processes that the LDAP and Kerberos back ends can use for
Kerberos user or host authentication.

%package krb5
Summary: The Kerberos authentication back end for the SSSD
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: sssd-common = %{version}-%{release}
Requires: sssd-krb5-common = %{version}-%{release}

%description krb5
Provides the Kerberos back end that the SSSD can utilize authenticate
against a Kerberos server.

%package common-pac
Summary: Common files needed for supporting PAC processing
Group: Applications/System
License: GPLv3+
Requires: sssd-common = %{version}-%{release}

%description common-pac
Provides common files needed by SSSD providers such as IPA and Active Directory
for handling Kerberos PACs.

%package ipa
Summary: The IPA back end of the SSSD
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: sssd-common = %{version}-%{release}
Requires: sssd-krb5-common = %{version}-%{release}
Requires: libipa_hbac%{?_isa} = %{version}-%{release}
Requires: bind-utils
Requires: sssd-common-pac = %{version}-%{release}
Requires(pre): shadow-utils

%description ipa
Provides the IPA back end that the SSSD can utilize to fetch identity data
from and authenticate against an IPA server.

%package ad
Summary: The AD back end of the SSSD
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: sssd-common = %{version}-%{release}
Requires: sssd-krb5-common = %{version}-%{release}
Requires: bind-utils
Requires: sssd-common-pac = %{version}-%{release}

%description ad
Provides the Active Directory back end that the SSSD can utilize to fetch
identity data from and authenticate against an Active Directory server.

%package proxy
Summary: The proxy back end of the SSSD
Group: Applications/System
License: GPLv3+
Conflicts: sssd < 1.10.0-8.beta2
Requires: sssd-common = %{version}-%{release}

%description proxy
Provides the proxy back end which can be used to wrap an existing NSS and/or
PAM modules to leverage SSSD caching.

%package -n libsss_idmap
Summary: FreeIPA Idmap library
Group: Development/Libraries
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsss_idmap
Utility library to convert SIDs to Unix uids and gids

%package -n libsss_idmap-devel
Summary: FreeIPA Idmap library
Group: Development/Libraries
License: LGPLv3+
Requires: libsss_idmap = %{version}-%{release}

%description -n libsss_idmap-devel
Utility library to SIDs to Unix uids and gids

%package -n libipa_hbac
Summary: FreeIPA HBAC Evaluator library
Group: Development/Libraries
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libipa_hbac
Utility library to validate FreeIPA HBAC rules for authorization requests

%package -n libipa_hbac-devel
Summary: FreeIPA HBAC Evaluator library
Group: Development/Libraries
License: LGPLv3+
Requires: libipa_hbac = %{version}-%{release}

%description -n libipa_hbac-devel
Utility library to validate FreeIPA HBAC rules for authorization requests

%package -n python-libipa_hbac
Summary: Python2 bindings for the FreeIPA HBAC Evaluator library
Group: Development/Libraries
License: LGPLv3+
Requires: libipa_hbac = %{version}-%{release}
Provides: libipa_hbac-python = %{version}-%{release}
Obsoletes: libipa_hbac-python < 1.12.90

%description -n python-libipa_hbac
The python-libipa_hbac contains the bindings so that libipa_hbac can be
used by Python applications.

%package -n libsss_nss_idmap
Summary: Library for SID and certificate based lookups
Group: Development/Libraries
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsss_nss_idmap
Utility library for SID and certificate based lookups

%package -n libsss_nss_idmap-devel
Summary: Library for SID and certificate based lookups
Group: Development/Libraries
License: LGPLv3+
Requires: libsss_nss_idmap = %{version}-%{release}

%description -n libsss_nss_idmap-devel
Utility library for SID and certificate based lookups

%package -n python-libsss_nss_idmap
Summary: Python2 bindings for libsss_nss_idmap
Group: Development/Libraries
License: LGPLv3+
Requires: libsss_nss_idmap = %{version}-%{release}
Provides: libsss_nss_idmap-python = %{version}-%{release}
Obsoletes: libsss_nss_idmap-python < 1.12.90

%description -n python-libsss_nss_idmap
The python-libsss_nss_idmap contains the bindings so that libsss_nss_idmap can
be used by Python applications.

%package dbus
Summary: The D-Bus responder of the SSSD
Group: Applications/System
License: GPLv3+
Requires: sssd-common = %{version}-%{release}

%description dbus
Provides the D-Bus responder of the SSSD, called the InfoPipe, that allows
the information from the SSSD to be transmitted over the system bus.

%if (0%{?install_pcscd_polkit_rule} == 1)
%package polkit-rules
Summary: Rules for polkit integration for SSSD
Group: Applications/System
License: GPLv3+
Requires: polkit >= 0.106
Requires: sssd-common = %{version}-%{release}

%description polkit-rules
Provides rules for polkit integration with SSSD. This is required
for smartcard support.
%endif

%package -n libsss_simpleifp
Summary: The SSSD D-Bus responder helper library
Group: Development/Libraries
License: GPLv3+
Requires: sssd-dbus = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsss_simpleifp
Provides library that simplifies D-Bus API for the SSSD InfoPipe responder.

%package -n libsss_simpleifp-devel
Summary: The SSSD D-Bus responder helper library
Group: Development/Libraries
License: GPLv3+
Requires: dbus-devel
Requires: libsss_simpleifp = %{version}-%{release}

%description -n libsss_simpleifp-devel
Provides library that simplifies D-Bus API for the SSSD InfoPipe responder.

%package libwbclient
Summary: The SSSD libwbclient implementation
Group: Applications/System
License: GPLv3+ and LGPLv3+
Conflicts: libwbclient < 4.1.12

%description libwbclient
The SSSD libwbclient implementation.

%package libwbclient-devel
Summary: Development libraries for the SSSD libwbclient implementation
Group:  Development/Libraries
License: GPLv3+ and LGPLv3+
Conflicts: libwbclient-devel < 4.1.12

%description libwbclient-devel
Development libraries for the SSSD libwbclient implementation.

%package winbind-idmap
Summary: SSSD's idmap_sss Backend for Winbind
Group:  Applications/System
License: GPLv3+ and LGPLv3+

%description winbind-idmap
The idmap_sss module provides a way for Winbind to call SSSD to map UIDs/GIDs
and SIDs.

%package -n libsss_certmap
Summary: SSSD Certficate Mapping Library
Group: Development/Libraries
License: LGPLv3+
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsss_certmap
Library to map certificates to users based on rules

%package -n libsss_certmap-devel
Summary: SSSD Certficate Mapping Library
Group: Development/Libraries
License: LGPLv3+
Requires: libsss_certmap = %{version}-%{release}

%description -n libsss_certmap-devel
Library to map certificates to users based on rules

%if (0%{?with_kcm} == 1)
%package kcm
Summary: An implementation of a Kerberos KCM server
Group:  Applications/System
License: GPLv3+
Requires: sssd-common = %{version}-%{release}

%description kcm
An implementation of a Kerberos KCM server. Use this package if you want to
use the KCM: Kerberos credentials cache.
%endif

%prep
# Update timestamps on the files touched by a patch, to avoid non-equal
# .pyc/.pyo files across the multilib peers within a build, where "Level"
# is the patch prefix option (e.g. -p1)
# Taken from specfile for python-simplejson
UpdateTimestamps() {
  Level=$1
  PatchFile=$2

  # Locate the affected files:
  for f in $(diffstat $Level -l $PatchFile); do
    # Set the files to have the same timestamp as that of the patch:
    touch -r $PatchFile $f
  done
}

%setup -q

for p in %patches ; do
    %__patch -p1 -i $p
    UpdateTimestamps -p1 $p
done

%build
autoreconf -ivf

%configure \
    --with-test-dir=/dev/shm \
    --with-db-path=%{dbpath} \
    --with-mcache-path=%{mcpath} \
    --with-pipe-path=%{pipepath} \
    --with-pubconf-path=%{pubconfpath} \
    --with-gpo-cache-path=%{gpocachepath} \
    --with-init-dir=%{_initrddir} \
    --with-krb5-rcache-dir=%{_localstatedir}/cache/krb5rcache \
    --enable-nsslibdir=%{_libdir} \
    --enable-pammoddir=%{_libdir}/security \
    --enable-nfsidmaplibdir=%{_libdir}/libnfsidmap \
    --disable-static \
    --disable-rpath \
    --with-sssd-user=sssd \
    --with-initscript=systemd \
    --with-syslog=journald \
    --enable-sss-default-nss-plugin \
    %{?with_cifs_utils_plugin_option} \
    --without-python3-bindings \
    --with-ad-gpo-default=permissive \
    %{?enable_polkit_rules_option} \
    %{?enable_systemtap_opt} \
    %{?with_kcm_option}

make %{?_smp_mflags} all docs

%check
export CK_TIMEOUT_MULTIPLIER=10
make %{?_smp_mflags} check VERBOSE=yes
unset CK_TIMEOUT_MULTIPLIER

%install

make install DESTDIR=$RPM_BUILD_ROOT

if [ ! -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/modules/libwbclient.so.%{libwbc_lib_version} ]
then
    echo "Expected libwbclient version not found, please check if version has changed."
    exit -1
fi

# Prepare language files
/usr/lib/rpm/find-lang.sh $RPM_BUILD_ROOT sssd

# Copy default logrotate file
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d
install -m644 src/examples/logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/sssd

# Make sure SSSD is able to run on read-only root
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/rwtab.d
install -m644 src/examples/rwtab $RPM_BUILD_ROOT%{_sysconfdir}/rwtab.d/sssd

%if (0%{?with_cifs_utils_plugin} == 1)
# Create directory for cifs-idmap alternative
# Otherwise this directory could not be owned by sssd-client
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cifs-utils
%endif

# Remove .la files created by libtool
find $RPM_BUILD_ROOT -name "*.la" -exec rm -f {} \;

# Suppress developer-only documentation
rm -Rf ${RPM_BUILD_ROOT}/%{_docdir}/%{name}

# Older versions of rpmbuild can only handle one -f option
# So we need to append to the sssd*.lang file
for file in `ls $RPM_BUILD_ROOT/%{python_sitelib}/*.egg-info 2> /dev/null`
do
    echo %{python_sitelib}/`basename $file` >> python_sssdconfig.lang
done

touch sssd.lang
for subpackage in sssd_ldap sssd_krb5 sssd_ipa sssd_ad sssd_proxy sssd_tools \
                  sssd_client sssd_dbus sssd_winbind_idmap \
                  libsss_certmap sssd_kcm
do
    touch $subpackage.lang
done

for man in `find $RPM_BUILD_ROOT/%{_mandir}/??/man?/ -type f | sed -e "s#$RPM_BUILD_ROOT/%{_mandir}/##"`
do
    lang=`echo $man | cut -c 1-2`
    case `basename $man` in
        sss_cache*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd.lang
            ;;
        sss_ssh*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd.lang
            ;;
        sss_*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_tools.lang
            ;;
        sssctl*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_tools.lang
            ;;
        sssd_krb5_*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_client.lang
            ;;
        pam_sss*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_client.lang
            ;;
        sssd-ldap*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_ldap.lang
            ;;
        sssd-krb5*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_krb5.lang
            ;;
        sssd-ipa*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_ipa.lang
            ;;
        sssd-ad*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_ad.lang
            ;;
        sssd-proxy*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_proxy.lang
            ;;
        sssd-ifp*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_dbus.lang
            ;;
        sssd-kcm*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_kcm.lang
            ;;
        idmap_sss*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd_winbind_idmap.lang
            ;;
        sss-certmap*)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> libsss_certmap.lang
            ;;
        *)
            echo \%lang\(${lang}\) \%{_mandir}/${man}\* >> sssd.lang
            ;;
    esac
done

# Print these to the rpmbuild log
echo "sssd.lang:"
cat sssd.lang

echo "python_sssdconfig.lang:"
cat python_sssdconfig.lang

for subpackage in sssd_ldap sssd_krb5 sssd_ipa sssd_ad sssd_proxy sssd_tools \
                  sssd_client sssd_dbus sssd_winbind_idmap \
                  libsss_certmap sssd_kcm
do
    echo "$subpackage.lang:"
    cat $subpackage.lang
done

%files
%defattr(-,root,root,-)
%license COPYING

%files common -f sssd.lang
%defattr(-,root,root,-)
%license COPYING
%doc src/examples/sssd-example.conf
%{_sbindir}/sssd
%{_unitdir}/sssd.service
%{_unitdir}/sssd-autofs.socket
%{_unitdir}/sssd-autofs.service
%{_unitdir}/sssd-nss.socket
%{_unitdir}/sssd-nss.service
%{_unitdir}/sssd-pac.socket
%{_unitdir}/sssd-pac.service
%{_unitdir}/sssd-pam.socket
%{_unitdir}/sssd-pam-priv.socket
%{_unitdir}/sssd-pam.service
%{_unitdir}/sssd-ssh.socket
%{_unitdir}/sssd-ssh.service
%{_unitdir}/sssd-sudo.socket
%{_unitdir}/sssd-sudo.service
%{_unitdir}/sssd-secrets.socket
%{_unitdir}/sssd-secrets.service

%dir %{_libexecdir}/%{servicename}
%{_libexecdir}/%{servicename}/sssd_be
%{_libexecdir}/%{servicename}/sssd_nss
%{_libexecdir}/%{servicename}/sssd_pam
%{_libexecdir}/%{servicename}/sssd_autofs
%{_libexecdir}/%{servicename}/sssd_secrets
%{_libexecdir}/%{servicename}/sssd_ssh
%{_libexecdir}/%{servicename}/sssd_sudo
%{_libexecdir}/%{servicename}/p11_child
%{_libexecdir}/%{servicename}/sssd_check_socket_activated_responders

%dir %{_libdir}/%{name}
# The files provider is intentionally packaged in -common
%{_libdir}/%{name}/libsss_files.so
%{_libdir}/%{name}/libsss_simple.so

#Internal shared libraries
%{_libdir}/%{name}/libsss_child.so
%{_libdir}/%{name}/libsss_crypt.so
%{_libdir}/%{name}/libsss_cert.so
%{_libdir}/%{name}/libsss_debug.so
%{_libdir}/%{name}/libsss_krb5_common.so
%{_libdir}/%{name}/libsss_ldap_common.so
%{_libdir}/%{name}/libsss_util.so
%{_libdir}/%{name}/libsss_semanage.so

# 3rd party application libraries
%{_libdir}/libnfsidmap/sss.so

%{ldb_modulesdir}/memberof.so
%{_bindir}/sss_ssh_authorizedkeys
%{_bindir}/sss_ssh_knownhostsproxy
%{_sbindir}/sss_cache
%{_libexecdir}/%{servicename}/sss_signal

%dir %{sssdstatedir}
%dir %{_localstatedir}/cache/krb5rcache
%attr(700,sssd,sssd) %dir %{dbpath}
%attr(755,sssd,sssd) %dir %{mcpath}
%attr(700,root,root) %dir %{secdbpath}
%ghost %attr(0644,sssd,sssd) %verify(not md5 size mtime) %{mcpath}/passwd
%ghost %attr(0644,sssd,sssd) %verify(not md5 size mtime) %{mcpath}/group
%ghost %attr(0644,sssd,sssd) %verify(not md5 size mtime) %{mcpath}/initgroups
%attr(755,sssd,sssd) %dir %{pipepath}
%attr(750,sssd,root) %dir %{pipepath}/private
%attr(755,sssd,sssd) %dir %{pubconfpath}
%attr(755,sssd,sssd) %dir %{gpocachepath}
%attr(750,sssd,sssd) %dir %{_var}/log/%{name}
%attr(711,sssd,sssd) %dir %{_sysconfdir}/sssd
%attr(711,sssd,sssd) %dir %{_sysconfdir}/sssd/conf.d
%ghost %attr(0600,sssd,sssd) %config(noreplace) %{_sysconfdir}/sssd/sssd.conf
%attr(755,root,root) %dir %{_sysconfdir}/systemd/system/sssd.service.d
%config(noreplace) %{_sysconfdir}/systemd/system/sssd.service.d/journal.conf
%dir %{_sysconfdir}/logrotate.d
%config(noreplace) %{_sysconfdir}/logrotate.d/sssd
%dir %{_sysconfdir}/rwtab.d
%config(noreplace) %{_sysconfdir}/rwtab.d/sssd
%dir %{_datadir}/sssd
%{_sysconfdir}/pam.d/sssd-shadowutils
%{_libdir}/%{name}/conf/sssd.conf

%{_datadir}/sssd/cfg_rules.ini
%{_datadir}/sssd/sssd.api.conf
%{_datadir}/sssd/sssd.api.d
%{_mandir}/man1/sss_ssh_authorizedkeys.1*
%{_mandir}/man1/sss_ssh_knownhostsproxy.1*
%{_mandir}/man5/sssd.conf.5*
%{_mandir}/man5/sssd-files.5*
%{_mandir}/man5/sssd-simple.5*
%{_mandir}/man5/sssd-sudo.5*
%{_mandir}/man5/sssd-secrets.5*
%{_mandir}/man5/sss_rpcidmapd.5*
%{_mandir}/man8/sssd.8*
%{_mandir}/man8/sss_cache.8*
%if (0%{?enable_systemtap} == 1)
%dir %{_datadir}/sssd/systemtap
%{_datadir}/sssd/systemtap/id_perf.stp
%{_datadir}/sssd/systemtap/nested_group_perf.stp
%dir %{_datadir}/systemtap
%dir %{_datadir}/systemtap/tapset
%{_datadir}/systemtap/tapset/sssd.stp
%{_datadir}/systemtap/tapset/sssd_functions.stp
%endif

%if (0%{?install_pcscd_polkit_rule} == 1)
%files polkit-rules
%{_datadir}/polkit-1/rules.d/*
%endif

%files ldap -f sssd_ldap.lang
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/libsss_ldap.so
%{_mandir}/man5/sssd-ldap.5*

%files krb5-common
%defattr(-,root,root,-)
%license COPYING
%attr(755,sssd,sssd) %dir %{pubconfpath}/krb5.include.d
%attr(4750,root,sssd) %{_libexecdir}/%{servicename}/ldap_child
%attr(4750,root,sssd) %{_libexecdir}/%{servicename}/krb5_child

%files krb5 -f sssd_krb5.lang
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/libsss_krb5.so
%{_mandir}/man5/sssd-krb5.5*

%files common-pac
%defattr(-,root,root,-)
%license COPYING
%{_libexecdir}/%{servicename}/sssd_pac

%files ipa -f sssd_ipa.lang
%defattr(-,root,root,-)
%license COPYING
%attr(700,sssd,sssd) %dir %{keytabdir}
%{_libdir}/%{name}/libsss_ipa.so
%attr(4750,root,sssd) %{_libexecdir}/%{servicename}/selinux_child
%{_mandir}/man5/sssd-ipa.5*

%files ad -f sssd_ad.lang
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/libsss_ad.so
%{_libexecdir}/%{servicename}/gpo_child
%{_mandir}/man5/sssd-ad.5*

%files proxy
%defattr(-,root,root,-)
%license COPYING
%attr(4750,root,sssd) %{_libexecdir}/%{servicename}/proxy_child
%{_libdir}/%{name}/libsss_proxy.so

%files dbus -f sssd_dbus.lang
%defattr(-,root,root,-)
%license COPYING
%{_libexecdir}/%{servicename}/sssd_ifp
%{_mandir}/man5/sssd-ifp.5*
%{_unitdir}/sssd-ifp.service
# InfoPipe DBus plumbing
%{_sysconfdir}/dbus-1/system.d/org.freedesktop.sssd.infopipe.conf
%{_datadir}/dbus-1/system-services/org.freedesktop.sssd.infopipe.service

%files -n libsss_simpleifp
%defattr(-,root,root,-)
%{_libdir}/libsss_simpleifp.so.*

%files -n libsss_simpleifp-devel
%defattr(-,root,root,-)
%doc sss_simpleifp_doc/html
%{_includedir}/sss_sifp.h
%{_includedir}/sss_sifp_dbus.h
%{_libdir}/libsss_simpleifp.so
%{_libdir}/pkgconfig/sss_simpleifp.pc

%files client -f sssd_client.lang
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%{_libdir}/libnss_sss.so.2
%{_libdir}/security/pam_sss.so
%{_libdir}/krb5/plugins/libkrb5/sssd_krb5_locator_plugin.so
%{_libdir}/krb5/plugins/authdata/sssd_pac_plugin.so
%if (0%{?with_cifs_utils_plugin} == 1)
%dir %{_libdir}/cifs-utils
%{_libdir}/cifs-utils/cifs_idmap_sss.so
%dir %{_sysconfdir}/cifs-utils
%ghost %{_sysconfdir}/cifs-utils/idmap-plugin
%endif
%if (0%{?with_krb5_localauth_plugin} == 1)
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/modules
%{_libdir}/%{name}/modules/sssd_krb5_localauth_plugin.so
%endif
%{_mandir}/man8/pam_sss.8*
%{_mandir}/man8/sssd_krb5_locator_plugin.8*

%files -n libsss_sudo
%defattr(-,root,root,-)
%license src/sss_client/COPYING
%{_libdir}/libsss_sudo.so*

%files -n libsss_autofs
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%dir %{_libdir}/%{name}/modules
%{_libdir}/%{name}/modules/libsss_autofs.so

%files tools -f sssd_tools.lang
%defattr(-,root,root,-)
%license COPYING
%{_sbindir}/sss_useradd
%{_sbindir}/sss_userdel
%{_sbindir}/sss_usermod
%{_sbindir}/sss_groupadd
%{_sbindir}/sss_groupdel
%{_sbindir}/sss_groupmod
%{_sbindir}/sss_groupshow
%{_sbindir}/sss_obfuscate
%{_sbindir}/sss_override
%{_sbindir}/sss_debuglevel
%{_sbindir}/sss_seed
%{_sbindir}/sssctl
%{_mandir}/man8/sss_groupadd.8*
%{_mandir}/man8/sss_groupdel.8*
%{_mandir}/man8/sss_groupmod.8*
%{_mandir}/man8/sss_groupshow.8*
%{_mandir}/man8/sss_useradd.8*
%{_mandir}/man8/sss_userdel.8*
%{_mandir}/man8/sss_usermod.8*
%{_mandir}/man8/sss_obfuscate.8*
%{_mandir}/man8/sss_override.8*
%{_mandir}/man8/sss_debuglevel.8*
%{_mandir}/man8/sss_seed.8*
%{_mandir}/man8/sssctl.8*

%files -n python-sssdconfig -f python_sssdconfig.lang
%defattr(-,root,root,-)
%dir %{python_sitelib}/SSSDConfig
%{python_sitelib}/SSSDConfig/*.py*

%files -n python-sss
%defattr(-,root,root,-)
%{python_sitearch}/pysss.so

%files -n python-sss-murmur
%defattr(-,root,root,-)
%{python_sitearch}/pysss_murmur.so

%files -n libsss_idmap
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%{_libdir}/libsss_idmap.so.*

%files -n libsss_idmap-devel
%defattr(-,root,root,-)
%doc idmap_doc/html
%{_includedir}/sss_idmap.h
%{_libdir}/libsss_idmap.so
%{_libdir}/pkgconfig/sss_idmap.pc

%files -n libipa_hbac
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%{_libdir}/libipa_hbac.so.*

%files -n libipa_hbac-devel
%defattr(-,root,root,-)
%doc hbac_doc/html
%{_includedir}/ipa_hbac.h
%{_libdir}/libipa_hbac.so
%{_libdir}/pkgconfig/ipa_hbac.pc

%files -n libsss_nss_idmap
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%{_libdir}/libsss_nss_idmap.so.*

%files -n libsss_nss_idmap-devel
%defattr(-,root,root,-)
%doc nss_idmap_doc/html
%{_includedir}/sss_nss_idmap.h
%{_libdir}/libsss_nss_idmap.so
%{_libdir}/pkgconfig/sss_nss_idmap.pc

%files -n python-libsss_nss_idmap
%defattr(-,root,root,-)
%{python_sitearch}/pysss_nss_idmap.so

%files -n python-libipa_hbac
%defattr(-,root,root,-)
%{python_sitearch}/pyhbac.so

%files libwbclient
%defattr(-,root,root,-)
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/modules
%{_libdir}/%{name}/modules/libwbclient.so.*

%files libwbclient-devel
%defattr(-,root,root,-)
%{_includedir}/wbclient_sssd.h
%{_libdir}/%{name}/modules/libwbclient.so
%{_libdir}/pkgconfig/wbclient_sssd.pc

%files winbind-idmap -f sssd_winbind_idmap.lang
%dir %{_libdir}/samba/idmap
%{_libdir}/samba/idmap/sss.so
%{_mandir}/man8/idmap_sss.8*

%files -n libsss_certmap -f libsss_certmap.lang
%defattr(-,root,root,-)
%license src/sss_client/COPYING src/sss_client/COPYING.LESSER
%{_libdir}/libsss_certmap.so.*
%{_mandir}/man5/sss-certmap.5*

%files -n libsss_certmap-devel
%defattr(-,root,root,-)
%doc certmap_doc/html
%{_includedir}/sss_certmap.h
%{_libdir}/libsss_certmap.so
%{_libdir}/pkgconfig/sss_certmap.pc

%pre ipa
getent group sssd >/dev/null || groupadd -r sssd
getent passwd sssd >/dev/null || useradd -r -g sssd -d / -s /sbin/nologin -c "User for sssd" sssd

%pre krb5-common
getent group sssd >/dev/null || groupadd -r sssd
getent passwd sssd >/dev/null || useradd -r -g sssd -d / -s /sbin/nologin -c "User for sssd" sssd

%if (0%{?with_kcm} == 1)
%files kcm -f sssd_kcm.lang
%{_libexecdir}/%{servicename}/sssd_kcm
%dir %{_sysconfdir}/krb5.conf.d
%config(noreplace) %{_sysconfdir}/krb5.conf.d/kcm_default_ccache
%{_unitdir}/sssd-kcm.socket
%{_unitdir}/sssd-kcm.service
%{_mandir}/man8/sssd-kcm.8*
%endif

%pre common
getent group sssd >/dev/null || groupadd -r sssd
getent passwd sssd >/dev/null || useradd -r -g sssd -d / -s /sbin/nologin -c "User for sssd" sssd
/bin/systemctl is-active --quiet sssd.service && touch /var/tmp/sssd_is_running || :

%post common
%systemd_post sssd.service
%systemd_post sssd-autofs.socket
%systemd_post sssd-nss.socket
%systemd_post sssd-pac.socket
%systemd_post sssd-pam.socket
%systemd_post sssd-pam-priv.socket
%systemd_post sssd-secrets.socket
%systemd_post sssd-ssh.socket
%systemd_post sssd-sudo.socket

%preun common
%systemd_preun sssd.service
%systemd_preun sssd-autofs.socket
%systemd_preun sssd-nss.socket
%systemd_preun sssd-pac.socket
%systemd_preun sssd-pam.socket
%systemd_preun sssd-pam-priv.socket
%systemd_preun sssd-secrets.socket
%systemd_preun sssd-ssh.socket
%systemd_preun sssd-sudo.socket

%postun common
%systemd_postun_with_restart sssd-autofs.socket
%systemd_postun_with_restart sssd-autofs.service
%systemd_postun_with_restart sssd-nss.socket
%systemd_postun_with_restart sssd-nss.service
%systemd_postun_with_restart sssd-pac.socket
%systemd_postun_with_restart sssd-pac.service
%systemd_postun_with_restart sssd-pam.socket
%systemd_postun_with_restart sssd-pam-priv.socket
%systemd_postun_with_restart sssd-pam.service
%systemd_postun_with_restart sssd-secrets.socket
%systemd_postun_with_restart sssd-secrets.service
%systemd_postun_with_restart sssd-ssh.socket
%systemd_postun_with_restart sssd-ssh.service
%systemd_postun_with_restart sssd-sudo.socket
%systemd_postun_with_restart sssd-sudo.service

%post dbus
%systemd_post sssd-ifp.service

%preun dbus
%systemd_preun sssd-ifp.service

%postun dbus
%systemd_postun_with_restart sssd-ifp.service

%if (0%{?with_kcm} == 1)
%post kcm
%systemd_post sssd-kcm.socket

%preun kcm
%systemd_preun sssd-kcm.socket

%postun kcm
%systemd_postun_with_restart sssd-kcm.socket
%systemd_postun_with_restart sssd-kcm.service
%endif

%if (0%{?with_cifs_utils_plugin} == 1)
%post client
/sbin/ldconfig
/usr/sbin/alternatives --install /etc/cifs-utils/idmap-plugin cifs-idmap-plugin %{_libdir}/cifs-utils/cifs_idmap_sss.so 20

%preun client
if [ $1 -eq 0 ] ; then
        /usr/sbin/alternatives --remove cifs-idmap-plugin %{_libdir}/cifs-utils/cifs_idmap_sss.so
fi
%else
%post client -p /sbin/ldconfig
%endif

%postun client -p /sbin/ldconfig

%post -n libsss_sudo -p /sbin/ldconfig

%postun -n libsss_sudo -p /sbin/ldconfig

%post -n libipa_hbac -p /sbin/ldconfig

%postun -n libipa_hbac -p /sbin/ldconfig

%post -n libsss_idmap -p /sbin/ldconfig

%postun -n libsss_idmap -p /sbin/ldconfig

%post -n libsss_nss_idmap -p /sbin/ldconfig

%postun -n libsss_nss_idmap -p /sbin/ldconfig

%post -n libsss_simpleifp -p /sbin/ldconfig

%postun -n libsss_simpleifp -p /sbin/ldconfig

%post -n libsss_certmap -p /sbin/ldconfig

%postun -n libsss_certmap -p /sbin/ldconfig

%post libwbclient
%{_sbindir}/update-alternatives \
    --install %{_libdir}/libwbclient.so.%{libwbc_alternatives_version} \
              libwbclient.so.%{libwbc_alternatives_version}%{libwbc_alternatives_suffix} \
              %{_libdir}/%{name}/modules/libwbclient.so.%{libwbc_lib_version} 20
/sbin/ldconfig

%preun libwbclient
if [ $1 -eq 0 ]; then
    %{_sbindir}/update-alternatives \
        --remove libwbclient.so.%{libwbc_alternatives_version}%{libwbc_alternatives_suffix} \
                 %{_libdir}/%{name}/modules/libwbclient.so.%{libwbc_lib_version}
fi
/sbin/ldconfig

%post libwbclient-devel
%{_sbindir}/update-alternatives --install %{_libdir}/libwbclient.so \
                                libwbclient.so%{libwbc_alternatives_suffix} \
                                %{_libdir}/%{name}/modules/libwbclient.so 20

%preun libwbclient-devel
if [ $1 -eq 0 ]; then
        %{_sbindir}/update-alternatives --remove \
                                libwbclient.so%{libwbc_alternatives_suffix} \
                                %{_libdir}/%{name}/modules/libwbclient.so
fi

%posttrans common
%systemd_postun_with_restart sssd.service
# After changing order of sssd-common and *libwbclient,
# older version of sssd will restart sssd.service in postun scriptlet
# It failed due to missing alternative to libwbclient. Start it again.
/bin/systemctl is-active --quiet sssd.service || {
    if [ -f /var/tmp/sssd_is_running ]; then
        systemctl start sssd.service >/dev/null 2>&1;
        rm -f /var/tmp/sssd_is_running;
    fi
}

%changelog
* Sun Aug  6 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-50.2
- Resolves: rhbz#1478252 - Querying the AD domain for external domain's
                           ID can mark the AD domain offline [rhel-7.4.z]

* Sun Aug  6 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-50.1
- Resolves: rhbz#1478250 - Idle nss file descriptors should be closed
                           [rhel-7.4.z]

* Wed Jun 21 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-50
- Resolves: rhbz#1457926 - Wrong search base used when SSSD is directly
                           connected to AD child domain

* Wed Jun 21 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-49
- Resolves: rhbz#1450107 - SSSD doesn't handle conflicts between users
                           from trusted domains with the same name when
                           shortname user resolution is enabled

* Fri Jun 16 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-48
- Resolves: rhbz#1459846 - krb5: properly handle 'password expired'
                           information retured by the KDC during
                           PKINIT/Smartcard authentication

* Thu Jun 15 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-47
- Resolves: rhbz#1430415 - ldap_purge_cache_timeout in RHEL7.3 invalidate
                           most of the entries once the cleanup task kicks in

* Thu Jun 15 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-46
- Resolves: rhbz#1455254 - Make domain available as user attribute

* Thu Jun  8 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-45
- Resolves: rhbz#1449731 - IPA client cannot change AD Trusted User password

* Thu Jun  8 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-44
- Resolves: rhbz#1457927 - getent failed to fetch netgroup information
                           after changing default_domain_suffix to
                           ADdomin in /etc/sssd/sssd.conf

* Mon Jun  5 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-43
- Resolves: rhbz#1440132 - fiter_users and filter_groups stop working
                           properly in v 1.15

* Mon Jun  5 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-42
- Resolves: rhbz#1449728 - LDAP to IPA migration doesn't work in master

* Mon Jun  5 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-41
- Resolves: rhbz#1445445 - Smart card login fails if same cert mapped to
                           IdM user and AD user

* Mon Jun  5 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-40
- Resolves: rhbz#1449729 - org.freedesktop.sssd.infopipe.GetUserGroups
                           does not resolve groups into names with AD

* Thu Jun  1 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-39
- Resolves: rhbz#1450094 - Properly support IPA's promptusername config
                           option

* Thu Jun  1 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-38
- Resolves: rhbz#1457644 - Segfault in access_provider = krb5 is set in
                           sssd.conf due to an off-by-one error when
                           constructing the child send buffer
- Resolves: rhbz#1456531 - Option name typos are not detected with validator
                           function of sssctl config-check command in domain
                           sections

* Fri May 26 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-37
- Resolves: rhbz#1428906 - sssd intermittently failing to resolve groups
                           for an AD user in IPA-AD trust environment.

* Fri May 26 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-36
- Resolves: rhbz#1389796 - Smartcard authentication with UPN as logon name
                           might fail
- Fix Coverity issues in patches for rhbz#1445445

* Wed May 24 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-35
- Resolves: rhbz#1445445 - Smart card login fails if same cert mapped to
                           IdM user and AD user

* Wed May 24 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-34
- Resolves: rhbz#1446302 - crash in sssd-kcm due to a race-condition
                           between two concurrent requests

* Tue May 23 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-33
- Resolves: rhbz#1389796 - Smartcard authentication with UPN as logon name might fail

* Tue May 23 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-32
- Resolves: rhbz#1306707 - Need better debug message when krb5_child
                           returns an unhandled error, leading to a
                           System Error PAM code

* Mon May 22 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-31
- Resolves: rhbz#1446535 - Group resolution does not work in subdomain
                           without ad_server option

* Wed May  17 2017 Sumit Bose <sbose@redhat.com> - 1.15.2-30
- Resolves: rhbz#1449726 - sss_nss_getlistbycert() does not return results from
                           multiple domains
- Resolves: rhbz#1447098 - sssd unable to search dbus for ipa user by
                           certificate
- Additional patch for rhbz#1440132

* Thu May  11 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-29
- Reapply patch by Lukas Slebodnik to fix upgrade issues with libwbclient
- Resolves: rhbz#1439457 - SSSD does not start after upgrade from 7.3 to 7.4 
- Resolves: rhbz#1449107 - error: %pre(sssd-common-1.15.2-26.el7.x86_64)
                           scriptlet failed, exit status 3

* Thu May 11 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-28
- Resolves: rhbz#1440132 - fiter_users and filter_groups stop working
                           properly in v 1.15
- Also apply an additional patch for rhbz#1441545

* Thu May  4 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-25
- Resolves: rhbz#1445445 - Smart card login fails if same cert mapped to
                           IdM user and AD user

* Wed May  3 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-24
- Resolves: rhbz#1434992 - Wrong pam return code for user from subdomain
                           with ad_access_filter

* Wed May  3 2017 Lukas Slebodnik <lslebodn@redhat.com> - 1.15.2-23
- Resolves: rhbz#1430494 - expect sss_ssh_authorizedkeys and
                           sss_ssh_knownhostsproxy manuals to be packaged
                           into sssd-common package

* Tue May  2 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-22
- Resolves: rhbz#1427749 - SSSD in server mode iterates over all domains
                           for group-by-GID requests, causing unnecessary
                           searches

* Tue May  2 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-21
- Resolves: rhbz#1446139 - Infopipe method ListByCertificate does not
                           return the users with overrides

* Tue May  2 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-20
- Resolves: rhbz#1441545 - With multiple subdomain sections id command
                           output for user is not displayed for both domains

* Tue May  2 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-19
- Resolves: rhbz#1428866 - Using ad_enabled_domains configuration option
                           in sssd.conf causes nameservice lookups to fail.

* Tue May  2 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-18
- Remove an unused variable from the sssd-secrets responder
- Related: rhbz#1398701 - [sssd-secrets] https proxy talks plain http
- Improve two DEBUG messages in the client trust code to aid troubleshooting
- Fix standalone application domains
- Related: rhbz#1425891 - Support delivering non-POSIX users and groups
                          through the IFP and PAM interfaces

* Wed Apr 26 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-17
- Allow completely server-side unqualified name resolution if the domain order is set,
  do not require any client-side changes
- Related: rhbz#1330196 - [RFE] Short name input format with SSSD for users from
                          all domains when domain autodiscovery is used or when
                          IPA client resolves trusted AD domain users

* Mon Apr 24 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-16
- Resolves: rhbz#1402532 - D-Bus interface of sssd is giving inappropriate
                           group information for trusted AD users

* Thu Apr 13 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-15
- Resolves: rhbz#1431858 - Wrong principal found with ad provider and long
                           host name

* Wed Apr 12 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-14
- Resolves: rhbz#1415167 - pam_acct_mgmt with pam_sss.so fails in
                           unprivileged container unless
                           selinux_provider = none is used

* Wed Apr 12 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-13
- Resolves: rhbz#1438388 - [abrt] [faf] sssd: unknown function():
                           /usr/libexec/sssd/sssd_pam killed by 6

* Tue Apr 11 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-12
- Resolves: rhbz#1432112 - sssctl config-check does not give any error
                           when default configuration file is not present

* Tue Apr 11 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-11
- Resolves: rhbz#1438374 - [abrt] [faf] sssd: vfprintf():
                           /usr/libexec/sssd/sssd_be killed by 11

* Tue Apr 11 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-10
- Resolves: rhbz#1427195 - sssd_nss consumes more memory until restarted
                           or machine swaps

* Mon Apr 10 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-9
- Resolves: rhbz#1414023 - Create troubleshooting tool to determine if a
                           failure is in SSSD or not when using layered
                           products like RH-SSO/CFME etc

* Thu Mar 30 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-8
- Resolves: rhbz#1398701 - [sssd-secrets] https proxy talks plain http

* Thu Mar 30 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-7
- Fix off-by-one error in the KCM responder
- Related: rhbz#1396012 - [RFE] KCM ccache daemon in SSSD

* Thu Mar 30 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-6
- Resolves: rhbz#1425891 - Support delivering non-POSIX users and groups
                           through the IFP and PAM interfaces

* Wed Mar 29 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-5
- Resolves: rhbz#1434991 - Issue processing ssh keys from certificates in
                           ssh respoder

* Wed Mar 29 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-4
- Resolves: rhbz#1330196 - [RFE] Short name input format with SSSD for
                           users from all domains when domain autodiscovery
                           is used or when IPA client resolves trusted AD
                           domain users
- Also backport some buildtime fixes for the KCM responder
- Related: rhbz#1396012 - [RFE] KCM ccache daemon in SSSD

* Mon Mar 27 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-3
- Resolves: rhbz#1396012 - [RFE] KCM ccache daemon in SSSD

* Thu Mar 23 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-2
- Resolves: rhbz#1340711 - [RFE] Use one smartcard and certificate for
                           authentication to distinct logon accounts

* Wed Mar 15 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.2-1
- Update to upstream 1.15.2
- https://docs.pagure.org/SSSD.sssd/users/relnotes/notes_1_15_2.html
- Resolves: rhbz#1418728 - IPA - sudo does not handle associated conflict
                           entries
- Resolves: rhbz#1386748 - sssd doesn't update PTR records if A/PTR zones
                           are configured as non-secure and secure
- Resolves: rhbz#1214491 - [RFE] Make it possible to configure AD subdomain
                           in the SSSD server mode

* Thu Mar  9 2017 Fabiano Fidêncio <fidencio@redhat.com> - 1.15.1-2
- Drop "NOUPSTREAM: Bundle http-parser" patch
  Related: rhbz#1393819 - New package: http-parser

* Sat Mar  4 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.1-1
- Update to upstream 1.15.1
- https://docs.pagure.org/SSSD.sssd/users/relnotes/notes_1_15_1.html
- Resolves: rhbz#1327085 - Don't prompt for password if there is already
                           one on the stack
- Resolves: rhbz#1378722 - [RFE] Make GETSIDBYNAME and GETORIGBYNAME
                           request aware of UPNs and aliases
- Resolves: rhbz#1405075 - [RFE] Add PKINIT support to SSSD Kerberos provider
- Resolves: rhbz#1416526 - Need correction in sssd-krb5 man page
- Resolves: rhbz#1418752 - pam_sss crashes in do_pam_conversation if no
                           conversation function is provided by the
                           client app
- Resolves: rhbz#1419356 - Fails to accept any sudo rules if there are
                           two user entries in an ldap role with the same
                           sudo user
- Resolves: rhbz#1421622 - SSSD - Users/Groups are cached as mixed-case
                           resulting in users unable to sign in

* Wed Feb  1 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.0-2
- Fix several packaging issues, notably the p11_child is no longer setuid
  and the libwbclient used a wrong version number in the symlink

* Mon Jan 30 2017 Jakub Hrozek <jhrozek@redhat.com> - 1.15.0-1
- Update to upstream 1.15.0
- Resolves: rhbz#1393824 - Rebase SSSD to version 1.15
- Resolves: rhbz#1407960 - wbcLookupSid() fails in pdomain is NULL
- Resolves: rhbz#1406437 - sssctl netgroup-show Cannot allocate memory
- Resolves: rhbz#1400422 - Use-after free in resolver in case the fd is
                           writeable and readable at the same time
- Resolves: rhbz#1393085 - bz - ldap group names don't resolve after
                           upgrading sssd to 1.14.0 if ldap_nesting_level is set to 0
- Resolves: rhbz#1392444 - sssd_be keeps crashing
- Resolves: rhbz#1392441 - sssd fails to start after upgrading to RHEL 7.3
- Resolves: rhbz#1382602 - autofs map resolution doesn't work offline
- Resolves: rhbz#1380436 - sudo: ignore case on case insensitive domains
- Resolves: rhbz#1378251 - Typo In SSSD-AD Man Page
- Resolves: rhbz#1373427 - Clock skew makes SSSD return System Error
- Resolves: rhbz#1306707 - Need better handling of "Server not found in
                           Kerberos database"
- Resolves: rhbz#1297462 - Don't include 'enable_only=sssd' in the localauth
                           plugin config

* Mon Nov  7 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-46
- Resolves: rhbz#1382598 - IPA: Uninitialized variable during subdomain check

* Mon Nov  7 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-45
- Resolves: rhbz#1378911 - No supplementary groups are resolved for users
                           in nested OUs when domain stanza differs from AD
                           domain

* Mon Nov  7 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-44
- Resolves: rhbz#1372075 - AD provider: SSSD does not retrieve a domain-local
                           group with the AD provider when following AGGUDLP
                           group structure across domains

* Tue Sep 20 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-43
- Resolves: rhbz#1376831 - sssd-common is missing dependency on sssd-sudo

* Fri Sep 16 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-42
- Resolves: rhbz#1371631 - login using gdm calls for gdm-smartcard when
                           smartcard authentication is not enabled

* Wed Sep 14 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-41
- Resolves: rhbz#1373420 - sss_override fails to export

* Wed Sep 14 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-40
- Resolves: rhbz#1375299 - sss_groupshow <user> fails with error "No such
                           group in local domain. Printing groups only
                           allowed in local domain"

* Wed Sep 14 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-39
- Resolves: rhbz#1375182 - SSSD goes offline when the LDAP server returns
                           sizelimit exceeded

* Mon Sep 12 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-38
- Resolves: rhbz#1372753 - Access denied for user when access_provider =
                           krb5 is set in sssd.conf

* Mon Sep 12 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-37
- Resolves: rhbz#1373444 - unable to create group in sssd cache
- Resolves: rhbz#1373577 - unable to add local user in sssd to a group in sssd

* Wed Sep  7 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-36
- Resolves: rhbz#1369118 - Don't enable the default shadowtils domain in RHEL

* Mon Sep  5 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-35
- Fix permissions for the private pipe directory
- Resolves: rhbz#1362716 - selinux avc denial for vsftp login as ipa user

* Fri Sep  2 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-34
- Resolves: rhbz#1371977 - resolving IPA nested user groups is broken in 1.14

* Fri Sep  2 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-33
- Resolves: rhbz#1368496 - sssd is not able to authenticate with alias

* Fri Sep  2 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-32
- Resolves: rhbz#1371152 - SSSD qualifies principal twice in IPA-AD trust
                           if the principal attribute doesn't exist on the
                           AD side

* Fri Aug 26 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-31
- Apply forgotten patch
- Resolves: rhbz#1368496 - sssd is not able to authenticate with alias
- Resolves: rhbz#1366470 - sssd: throw away the timestamp cache if
                           re-initializing the persistent cache
- Fix deleting non-existent secret
- Related: rhbz#1311056 - Add a Secrets as a Service component

* Fri Aug 26 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-30
- Resolves: rhbz#1362716 - selinux avc denial for vsftp login as ipa user

* Fri Aug 26 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-29
- Resolves: rhbz#1368496 - sssd is not able to authenticate with alias

* Fri Aug 26 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-28
- Resolves: rhbz#1364033 - sssd exits if clock is adjusted backwards
                           after boot

* Fri Aug 19 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-27
- Resolves: rhbz#1362023 - SSSD fails to start when ldap_user_extra_attrs
                           contains mail

* Fri Aug 19 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-26
- Resolves: rhbz#1368324 - libsss_autofs.so is packaged in two packages
                           sssd-common and libsss_autofs

* Fri Aug 19 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-25
- Fix RPM scriptlet plumbing for the sssd-secrets responder
- Related: rhbz#1311056 - Add a Secrets as a Service component

* Wed Aug 17 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-24
- Add socket-activation plumbing for the sssd-secrets responder
- Related: rhbz#1311056 - Add a Secrets as a Service component

* Wed Aug 17 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-23
- Own the secrets directory
- Related: rhbz#1311056 - Add a Secrets as a Service component

* Wed Aug 17 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-22
- Resolves: rhbz#1268874 - Add an option to disable checking for trusted
                           domains in the subdomains provider

* Tue Aug 16 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-21
- Resolves: rhbz#1271280 - sssd stores and returns incorrect information
                           about empty netgroup (ldap-server: 389-ds)

* Tue Aug 16 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-20
- Resolves: rhbz#1290500 - [feat] command to manually list
                           fo_add_server_to_list information

* Tue Aug 16 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-19
- Add several small fixes related to the config API
- Related: rhbz#1072458 - [RFE] SSSD configuration file test tool (sssd_check)

* Thu Aug 11 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-18
- Resolves: rhbz#1349900 - gpo search errors out and gpo_cache file is
                           never created

* Wed Aug 10 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-17
- Fix regressions in the simple access provider
- Resolves: rhbz#1360806 - sssd does not start if sub-domain user is used
                           with simple access provider
- Apply a number of specfile patches to better match the upstream spefile
- Related: rhbz#1290381 - Rebase SSSD to 1.14.x in RHEL-7.3

* Wed Aug 10 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-16
- Cherry-pick patches from upstream that fix several regressions
- Avoid checking local users in all cases
- Resolves: rhbz#1353951 - sssd_pam leaks file descriptors

* Mon Aug  8 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-15
- Resolves: rhbz#1364118 - [abrt] [faf] sssd: unknown function():
                           /usr/libexec/sssd/sssd_nss killed by 11
- Resolves: rhbz#1361563 - Wrong pam error code returned for password
                           change in offline mode

* Fri Jul 29 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-14
- Resolves: rhbz#1309745 - Support multiple principals for IPA users

* Fri Jul 29 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-13
- Resolves: rhbz#1304992 - Handle overriden name of members in the
                           memberUid attribute

* Wed Jul 27 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-12
- handle unresolvable sites more gracefully
- Resolves: rhbz#1346011 - sssd is looking at a server in the GC of a
                           subdomain, not the root domain.
- fix compilation warnings in unit tests

* Wed Jul 27 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-11
- fix capaths output
- Resolves: rhbz#1344940 - GSSAPI error causes failures for child domain
                           user logins across IPA - AD trust
- also fix Coverity issues in the secrets responder and suppress noisy
  debug messages when setting the timestamp cache

* Tue Jul 19 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-10
- Resolves: rhbz#1356577 - sssctl: Time stamps without time zone information

* Tue Jul 19 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-9
- Resolves: rhbz#1354414 - New or modified ID-View User overrides are not
                           visible unless rm -f /var/lib/sss/db/*cache*

* Mon Jul 18 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-8
- Resolves: rhbz#1211631 - [RFE] Support of UPN for IdM trusted domains

* Thu Jul 14 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-7
- Resolves: rhbz#1350520 - [abrt] sssd-common: ipa_dyndns_update_send():
                           sssd_be killed by SIGSEGV

* Wed Jul 13 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-6
- Resolves: rhbz#1349882 - sssd does not work under non-root user
- Also cherry-pick a few patches from upstream to fix config schema
- Related: rhbz#1072458 - [RFE] SSSD configuration file test tool (sssd_check)

* Wed Jul 13 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-5
- Sync a few minor patches from upstream
- Fix sssctl manpage
- Fix nss-tests unit test on big-endian machines
- Fix several issues in the config schema
- Related: rhbz#1072458 - [RFE] SSSD configuration file test tool (sssd_check)

* Wed Jul 13 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-4
- Bundle http-parser
- Resolves: rhbz#1311056 - Add a Secrets as a Service component

* Tue Jul 12 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-3
- Sync a few minor patches from upstream
- Fix a failover issue
- Resolves: rhbz#1334749 - sssd fails to mark a connection as bad on
                           searches that time out

* Mon Jul 11 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-2
- Explicitly BuildRequire newer ding-libs
- Resolves: rhbz#1072458 - [RFE] SSSD configuration file test tool (sssd_check)

* Fri Jul  8 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0-1
- New upstream release 1.14.0
- Resolves: rhbz#1290381 - Rebase SSSD to 1.14.x in RHEL-7.3
- Resolves: rhbz#835492 - [RFE] SSSD admin tool request - force reload
- Resolves: rhbz#1072458 - [RFE] SSSD configuration file test tool (sssd_check)
- Resolves: rhbz#1278691 - Please fix rfc2307 autofs schema defaults
- Resolves: rhbz#1287209 - default_domain_suffix Appended to User Name
- Resolves: rhbz#1300663 - Improve sudo protocol to support configurations
                           with default_domain_suffix
- Resolves: rhbz#1312275 - Support authentication indicators from IPA

* Thu Jun 30 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0beta1-2
- Resolves: rhbz#1290381 - Rebase SSSD to 1.14.x in RHEL-7.3
- Resolves: rhbz#790113 - [RFE] "include" directive in sssd.conf
- Resolves: rhbz#874985 - [RFE] AD provider support for automount lookups
- Resolves: rhbz#879333 - [RFE] SSSD admin tool request - status overview
- Resolves: rhbz#1140022 - [RFE]Allow sssd to add a new option that would
                           specify which server to update DNS with
- Resolves: rhbz#1290380 - RFE: Improve SSSD performance in large
                           environments
- Resolves: rhbz#883886 - sssd: incorrect checks on length values during
                          packet decoding
- Resolves: rhbz#988207 - sssd does not detail which line in configuration
                          is invalid
- Resolves: rhbz#1007969 - sssd_cache does not remove have an option to
                           remove the sssd database
- Resolves: rhbz#1103249 - PAC responder needs much time to process large
                           group lists
- Resolves: rhbz#1118257 - Users in ipa groups, added to netgroups are
                           not resovable
- Resolves: rhbz#1269018 - Too much logging from sssd_be
- Resolves: rhbz#1293695 - sssd mixup nested group from AD trusted domains
- Resolves: rhbz#1308935 - After removing certificate from user in IPA
                           and even after sss_cache, FindByCertificate
                           still finds the user
- Resolves: rhbz#1315766 - SSSD PAM module does not support multiple
                           password prompts (e.g. Password + Token) with sudo
- Resolves: rhbz#1316164 - SSSD fails to process GPO from Active Directory
- Resolves: rhbz#1322458 - sssd_be[11010]: segfault at 0 ip 00007ff889ff61bb
                           sp 00007ffc7d66a3b0 error 4 in
                           libsss_ipa.so[7ff889fcf000+5d000]

* Mon Jun 20 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.14.0alpha-1
- Resolves: rhbz#1290381 - Rebase SSSD to 1.14.x in RHEL-7.3
- The rebase includes fixes for the following bugzillas:
- Resolves: rhbz#789477 - [RFE] SUDO: Support the IPA schema
- Resolves: rhbz#1059972 - RFE: SSSD: Automatically assign new slices for
                           any AD domain
- Resolves: rhbz#1233200 - man sssd.conf should clarify details about
                           subdomain_inherit option.
- Resolves: rhbz#1238144 - Need better libhbac debuging added to sssd
- Resolves: rhbz#1265366 - sss_override segfaults when accidentally adding
                           --help flag to some commands
- Resolves: rhbz#1269512 - sss_override: memory violation
- Resolves: rhbz#1278566 - crash in sssd when non-Englsh locale is used
                           and pam_strerror prints non-ASCII characters
- Resolves: rhbz#1283686 - groups get deleted from the cache
- Resolves: rhbz#1290378 - Smart Cards: Certificate in the ID View
- Resolves: rhbz#1292238 - extreme memory usage in libnfsidmap sss.so
                           plug-in when resolving groups with many members
- Resolves: rhbz#1292456 - sssd_be AD segfaults on missing A record
- Resolves: rhbz#1294670 - Local users with local sudo rules causes
                           LDAP queries
- Resolves: rhbz#1296618 - Properly remove OriginalMemberOf attribute in
                           SSSD cache if user has no secondary groups anymore
- Resolves: rhbz#1299553 - Cannot retrieve users after upgrade from 1.12
                           to 1.13
- Resolves: rhbz#1302821 - Cannot start sssd after switching to non-root
- Resolves: rhbz#1310877 - [RFE] Support Automatic Renewing of Kerberos
                           Host Keytabs
- Resolves: rhbz#1313014 - sssd is not closing sockets properly
- Resolves: rhbz#1318996 - SSSD does not fail over to next GC
- Resolves: rhbz#1327270 - local overrides: issues with sub-domain users
                           and mixed case names
- Resolves: rhbz#1342547 - sssd-libwbclient: wbcSidsToUnixIds should not
                           fail on lookup errors

* Tue May 24 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-50
- Build the PAC plugin with krb5-1.14
- Related: rhbz#1336688 - sssd tries to resolve global catalog servers
                          from AD forest sub-domains in AD-IPA trust setup

* Tue May 24 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-49
- Resolves: rhbz#1336688 - sssd tries to resolve global catalog servers
                           from AD forest sub-domains in AD-IPA trust setup

* Tue May 24 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-48
- Resolves: rhbz#1290853 - [sssd] Trusted (AD) user's info stays in sssd
                           cache for much more than expected.

* Mon May 23 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-47
- Resolves: rhbz#1336706 - sssd_nss memory usage keeps growing when trying
                           to retrieve non-existing netgroups

* Tue May 17 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-46
- Resolves: rhbz#1296902 - In IPA-AD trust environment access is granted
                           to AD user even if the user is disabled on AD.

* Tue May 17 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-45
- Resolves: rhbz#1334159 - IPA provider crashes if a netgroup from a
                           trusted domain is requested

* Mon Apr 18 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-44
- Resolves: rhbz#1308913 - sssd be memory leak in sssd's memberof plugin
- More patches from upstream related to the memory leak

* Fri Apr  1 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-43
- Resolves: rhbz#1308913 - sssd be memory leak in sssd's memberof plugin

* Wed Feb 24 2016 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-42
- Resolves: rhbz#1300740 - [RFE] IPA: resolve external group memberships
                           of IPA groups during getgrnam and getgrgid

* Tue Nov 24 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-41
- Resolves: rhbz#1284814  - sssd: [sysdb_add_user] (0x0400): Error: 17

* Wed Oct 14 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-40
- Resolves: rhbz#1270827 - local overrides: don't contact server with
                           overridden name/id

* Wed Oct  7 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-39
- Resolves: rhbz#1267837 - sssd_be crashed in ipa_srv_ad_acct_lookup_step

* Wed Oct  7 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-38
- Resolves: rhbz#1267176 - Memory leak / possible DoS with krb auth.

* Wed Oct  7 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-37
- Resolves: rhbz#1267836 - PAM responder crashed if user was not set

* Wed Sep 30 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-36
- Resolves: rhbz#1266107 - AD: Conditional jump or move depends on
                           uninitialised value

* Wed Sep 23 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-35
- Resolves: rhbz#1250135 - Detect re-established trusts in the IPA
                           subdomain code

* Tue Sep 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-34
- Fix a Coverity warning in dyndns code
- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
                           of processing other commands
* Tue Sep 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-33
- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
                           of processing other commands

* Tue Sep 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-32
- Resolves: rhbz#1263735 - Could not resolve AD user from root domain

* Tue Sep 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-31
- Remove -d from sss_override manpage
- Related: rhbz#1259512 - sss_override : The local override user is not found

* Tue Sep 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-30
- Patches required for better handling of failover with one-way trusts
- Related: rhbz#1250135 - Detect re-established trusts in the IPA subdomain
                          code

* Fri Sep 18 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-29
- Resolves: rhbz#1263587 - sss_override --name doesn't work with RFC2307
                           and ghost users

* Fri Sep 18 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-28
- Resolves: rhbz#1259512 - sss_override : The local override user is not found

* Fri Sep 18 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-27
- Resolves: rhbz#1260027 - sssd_be memory leak with sssd-ad in GPO code

* Tue Sep  1 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-26
- Resolves: rhbz#1256398 - sssd cannot resolve user names containing
                           backslash with ldap provider

* Tue Aug 25 2015 Martin Kosek <mkosek@redhat.com> - 1.13.0-25
- Resolves: rhbz#1254189 - sss_override contains an extra parameter --debug
                           but is not listed in the man page or in
                           the arguments help

* Thu Aug 20 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-24
- Resolves: rhbz#1254518 - Fix crash in nss responder

* Thu Aug 20 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-23
- Support import/export for local overrides
- Support FQDNs for local overrides
- Resolves: rhbz#1254184 - sss_override does not work correctly when
                           'use_fully_qualified_names = True'

* Tue Aug 18 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-22
- Resolves: rhbz#1244950 - Add index for 'objectSIDString' and maybe to
                           other cache attributes

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-21
- Resolves: rhbz#1250415 - sssd: p11_child hardening

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-20
- Related: rhbz#1250135 - Detect re-established trusts in the IPA
                          subdomain code

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-19
- Resolves: rhbz#1202724 - [RFE] Add a way to lookup users based on CAC
                           identity certificates

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-18
- Resolves: rhbz#1232950 - [IPA/IdM] sudoOrder not honored as expected

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-17
- Fix wildcard_limit=0
- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-16
- Fix race condition in invalidating the memory cache
- Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

* Mon Aug 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-15
- Resolves: rhbz#1249015 - KDC proxy not working with SSSD krb5_use_kdcinfo
                           enabled

* Thu Aug  6 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-14
- Bump release number
- Related: rhbz#1246489 - sss_obfuscate fails with "ImportError: No module
                          named pysss"

* Thu Aug  6 2015 Lukas Slebodnik <lslebodn@redhat.com> - 1.13.0-13
- Fix missing dependency of sssd-tools
- Resolves: rhbz#1246489 - sss_obfuscate fails with "ImportError: No module
                           named pysss"

* Wed Aug  5 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-12
- More memory cache related fixes
- Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

* Tue Aug  4 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-11
- Remove binary blob from SC patches as patch(1) can't handle those
- Related: rhbz#854396 - [RFE] Support for smart cards

* Tue Aug  4 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-10
- Resolves: rhbz#1244949 - getgrgid for user's UID on a trust client
                           prevents getpw*

* Tue Aug  4 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-9
- Fix memory cache integration tests
- Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups
- Resolves: rhbz#854396 - [RFE] Support for smart cards

* Tue Jul 28 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-8
- Remove OTP from PAM stack correctly
- Related: rhbz#1200873 - [RFE] Allow smart multi step prompting when
                          user logs in with password and token code from IPA
- Handle sssd-owned keytabs when sssd runs as root
- Related: rhbz#1205144 - RFE: Support one-way trusts for IPA

* Mon Jul 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-7
- Resolves: rhbz#1183747 - [FEAT] UID and GID mapping on individual clients

* Fri Jul 24 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-6
- Resolves: rhbz#1206565 - [RFE] Add dualstack and multihomed support
- Resolves: rhbz#1187146 - If v4 address exists, will not create nonexistant
                           v6 in ipa domain

* Fri Jul 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-5
- Resolves: rhbz#1242942 - well-known SID check is broken for NetBIOS prefixes

* Fri Jul 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-4
- Resolves: rhbz#1234722 - sssd ad provider fails to start in rhel7.2

* Thu Jul 16 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-3
- Add support for InfoPipe wildcard requests
- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface

* Mon Jul  6 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-2
- Also package the initgr memcache
- Related: rhbz#1205554 - Rebase SSSD to 1.13.x

* Mon Jul  6 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0-1
- Rebase to 1.13.0 upstream
- Related: rhbz#1205554 - Rebase SSSD to 1.13.x
- Resolves: rhbz#910187 - [RFE] authenticate against cache in SSSD
- Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

* Wed Jul  1 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0.3alpha
- Don't default to SSSD user
- Related: rhbz#1205554 - Rebase SSSD to 1.13.x

* Tue Jun 23 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0.2alpha
- Related: rhbz#1205554 - Rebase SSSD to 1.13.x
- GPO default should be permissve

* Mon Jun 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.13.0.1alpha
- Resolves: rhbz#1205554 - Rebase SSSD to 1.13.x
- Relax the libldb requirement
- Resolves: rhbz#1221992 - sssd_be segfault at 0 ip sp error 6 in
                           libtevent.so.0.9.21
- Resolves: rhbz#1221839 - SSSD group enumeration inconsistent due to
                           binary SIDs
- Resolves: rhbz#1219285 - Unable to resolve group memberships for AD
                           users when using sssd-1.12.2-58.el7_1.6.x86_64
                           client in combination with
                           ipa-server-3.0.0-42.el6.x86_64 with AD Trust
- Resolves: rhbz#1217559 - [RFE] Support GPOs from different domain controllers
- Resolves: rhbz#1217350 - ignore_group_members doesn't work for subdomains
- Resolves: rhbz#1217127 - Override for IPA users with login does not list
                           user all groups
- Resolves: rhbz#1216285 - autofs provider fails when default_domain_suffix
                           and use_fully_qualified_names set
- Resolves: rhbz#1214719 - Group resolution is inconsistent with group
                           overrides
- Resolves: rhbz#1214718 - Overridde with --login fails trusted adusers
                           group membership resolution
- Resolves: rhbz#1214716 - idoverridegroup for ipa group with --group-name
                           does not work
- Resolves: rhbz#1214337 - Overrides with --login work in second attempt
- Resolves: rhbz#1212489 - Disable the cleanup task by default
- Resolves: rhbz#1211830 - external users do not resolve with
                           "default_domain_suffix" set in IPA server sssd.conf
- Resolves: rhbz#1210854 - Only set the selinux context if the context
                           differs from the local one
- Resolves: rhbz#1209483 - When using id_provider=proxy with
                           auth_provider=ldap, it does not work as expected
- Resolves: rhbz#1209374 - Man sssd-ad(5) lists Group Policy Management
                           Editor naming for some policies but not for all
- Resolves: rhbz#1208507 - sysdb sudo search doesn't escape special characters
- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface
- Resolves: rhbz#1206566 - SSSD does not update Dynamic DNS records if
                           the IPA domain differs from machine hostname's
                           domain
- Resolves: rhbz#1206189 - [bug] sssd always appends default_domain_suffix
                           when checking for host keys
- Resolves: rhbz#1204203 - sssd crashes intermittently
- Resolves: rhbz#1203945 - [FJ7.0 Bug]: getgrent returns error because
                           sss is written in nsswitch.conf as default
- Resolves: rhbz#1203642 - GPO access control looks for computer object
                           in user's domain only
- Resolves: rhbz#1202245 - SSSD's HBAC processing is not permissive enough
                           with broken replication entries
- Resolves: rhbz#1201271 - sssd_nss segfaults if initgroups request is by
                           UPN and doesn't find anything
- Resolves: rhbz#1200873 - [RFE] Allow smart multi step prompting when
                           user logs in with password and token code from IPA
- Resolves: rhbz#1199541 - Read and use the TTL value when resolving a
                           SRV query
- Resolves: rhbz#1199533 - [RFE] Implement background refresh for users,
                           groups or other cache objects
- Resolves: rhbz#1199445 - Does sssd-ad use the most suitable attribute
                           for group name?
- Resolves: rhbz#1198477 - ccname_file_dummy is not unlinked on error
- Resolves: rhbz#1187103 - [RFE] User's home directories are not taken
                           from AD when there is an IPA trust with AD
- Resolves: rhbz#1185536 - In ipa-ad trust, with 'default_domain_suffix' set
                           to AD domain, IPA user are not able to log unless
                           use_fully_qualified_names is set
- Resolves: rhbz#1175760 - [RFE] Have OpenLDAP lock out ssh keys when
                           account naturally expires
- Resolves: rhbz#1163806 - [RFE]ad provider dns_discovery_domain option:
                           kerberos discovery is not using this option
- Resolves: rhbz#1205160 - Complain loudly if backend doesn't start due
                           to missing or invalid keytab

* Wed Apr 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-61
- Resolves: rhbz#1226119 - Properly handle AD's binary objectGUID

* Wed Apr 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-60
- Filter out domain-local groups during AD initgroups operation
- Related: rhbz#1201840 - SSSD downloads too much information when fetching
                          information about groups

* Wed Apr 22 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-59
- Resolves: rhbz#1201840 - SSSD downloads too much information when fetching
                           information about groups

* Thu Mar 19 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.6
- Initialize variable in the views code in one success and one failure path
- Resolves: rhbz#1202170 - sssd_be segfault on IPA(when auth with AD
                           trusted domain) client at
                           src/providers/ipa/ipa_s2n_exop.c:1605

* Tue Mar 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.5
- Resolves: rhbz#1202170 - sssd_be segfault on IPA(when auth with AD
                           trusted domain) client at
                           src/providers/ipa/ipa_s2n_exop.c:1605

* Tue Mar 17 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.4
- Handle case where there is no default and no rules
- Resolves: rhbz#1192314 - With empty ipaselinuxusermapdefault security
                           context on client is staff_u

* Thu Mar  5 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.3
- Set a pointer in ldap_child to NULL to avoid warnings
- Related: rhbz#1198759 - ccname_file_dummy is not unlinked on error

* Thu Mar  5 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.2
- Resolves: rhbz#1199143 - With empty ipaselinuxusermapdefault security
                           context on client is staff_u

* Thu Mar  5 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-58.1
- Resolves: rhbz#1198759 - ccname_file_dummy is not unlinked on error

* Tue Feb  3 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-57
- Run the restart in sssd-common posttrans
- Explicitly require libwbclient
- Resolves: rhbz#1187113 - sssd deamon was not running after RHEL 7.1 upgrade

* Fri Jan 30 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-56
- Resolves: rhbz#1187113 - sssd deamon was not running after RHEL 7.1 upgrade

* Fri Jan 30 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-55
- Fix endianess bug in fill_id()
- Related: rhbz#1109331 - [RFE] Allow SSSD to be used with smbd shares

* Fri Jan 30 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-54
- Resolves: rhbz#1168904 - gid is overridden by uid in default trust view

* Fri Jan 30 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-53
- Resolves: rhbz#1187192 - IPA initgroups don't work correctly in
                           non-default view

* Tue Jan 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-52
- Resolves: rhbz#1184982 - Need to set different umask in selinux_child

* Tue Jan 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-51
- Bump the release number
- Related: rhbz#1184140 - Users saved throug extop don't have the
                          originalMemberOf attribute

* Tue Jan 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-50
- Add a patch dependency
- Related: rhbz#1184140 - Users saved throug extop don't have the
                          originalMemberOf attribute

* Tue Jan 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-49
- Process ghost members only once
- Fix processing of universal groups with members from different domains
- Related: rhbz#1168904 - gid is overridden by uid in default trust view

* Tue Jan 27 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-48
- Related: rhbz#1184140 - Users saved throug extop don't have the
                          originalMemberOf attribute

* Fri Jan 23 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-47
- Resolves: rhbz#1185188 - Uncached SIDs cannot be resolved

* Fri Jan 23 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-46
- Handle GID override in MPG domains
- Handle views with mixed-case domains
- Related: rhbz#1168904 - gid is overridden by uid in default trust view

* Wed Jan 21 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-45
- Open socket to the PAC responder in krb5_child before dropping root
- Related: rhbz#1184140 - Users saved throug extop don't have the
                          originalMemberOf attribute

* Tue Jan 20 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-44
- Resolves: rhbz#1184140 - Users saved throug extop don't have the
                           originalMemberOf attribute

* Mon Jan 19 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-43
- Resolves: rhbz#1182183 - pam_sss(sshd:auth): authentication failure with
                           user from AD

* Wed Jan 14 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-42
- Resolves: rhbz#889206 - On clock skew sssd returns system error

* Wed Jan 14 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-41
- Related: rhbz#1168904 - gid is overridden by uid in default trust view

* Tue Jan 13 2015 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-40
- Resolves: rhbz#1177140 - gpo_child fails if "log level" is enabled in smb.conf
- Related: rhbz#1168904 - gid is overridden by uid in default trust view

* Fri Dec 19 2014 Sumit Bose <sbose@redhat.com> - 1.12.2-39
- Resolves: rhbz#1175408 - SSSD should not fail authentication when only allow
                           rules are used
- Resolves: rhbz#1175705 - sssd-libwbclient conflicts with Samba's and causes
                           crash in wbinfo
                           - in addition to the patch libwbclient.so is
                             filtered out of the Provides list of the package

* Wed Dec 17 2014 Sumit Bose <sbose@redhat.com> - 1.12.2-38
- Resolves: rhbz#1171215 - Crash in function get_object_from_cache
- Resolves: rhbz#1171383 - getent fails for posix group with AD users after
                           login
- Resolves: rhbz#1171382 - getent of AD universal group fails after group users
                           login
- Resolves: rhbz#1170300 - Access is not rejected for disabled domain
- Resolves: rhbz#1162486 - Error processing external groups with
                           getgrnam/getgrgid in the server mode
- Resolves: rhbz#1168904 - gid is overridden by uid in default trust view

* Wed Dec 17 2014 Sumit Bose <sbose@redhat.com> - 1.12.2-37
- Resolves: rhbz#1169459 - sssd-ad: The man page description to enable GPO HBAC
                           Policies are unclear
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Mon Dec 15 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-35
- Rebuild to add several forgotten Patch entries
- Resolves: rhbz#1173482 - MAN: Document that only user names are checked
                           for pam_trusted_users
- Resolves: rhbz#1167324 - pam_sss domains option: User auth should fail
                           when domains=<emtpy value>

* Sun Dec 14 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-35
- Remove Coverity warnings in krb5_child code
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Sat Dec 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-34
- Resolves: rhbz#1173482 - MAN: Document that only user names are checked
                           for pam_trusted_users
- Resolves: rhbz#1167324 - pam_sss domains option: User auth should fail
                           when domains=<emtpy value>

* Sat Dec 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-33
- Don't error out on chpass with OTPs
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Mon Dec  8 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-32
- Resolves: rhbz#1124320 - [FJ7.0 Bug]: getgrent returns error because sss
                           is written in nsswitch.conf as default.

* Mon Dec  8 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-31
- Resolves: rhbz#1169739 - selinuxusermap rule does not apply to trusted
                           AD users
- Enable running unit tests without cmocka
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Wed Dec  3 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-30
- krb5_child and ldap_child do not call Kerberos calls as root
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Wed Dec  3 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-29
- Resolves: rhbz#1168735 - The Kerberos provider is not properly views-aware

* Wed Nov 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-28
- Fix typo in libwbclient-devel alternatives invocation
- Related: rhbz#1109331 - [RFE] Allow SSSD to be used with smbd shares

* Wed Nov 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-27
- Resolves: rhbz#1166727 - pam_sss domains option: Untrusted users from
                           the same domain are allowed to auth.

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-26
- Handle migrating clients between views
- Related: rhbz#891984 - [RFE] ID Views: Support migration from the sync
                         solution to the trust solution

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-25
- Use alternatives for libwbclient
- Related: rhbz#1109331 - [RFE] Allow SSSD to be used with smbd shares

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-24
- Resolves: rhbz#1165794 - sssd does not work with custom value of option
                           re_expression

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-23
- Add an option that describes where to put generated krb5 files to
- Related: rhbz#1135043 - [RFE] Implement localauth plugin for MIT krb5 1.12

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-22
- Handle IPA group names returned from the extop plugin
- Related: rhbz#891984 - [RFE] ID Views: Support migration from the sync
                         solution to the trust solution

* Tue Nov 25 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-21
- Resolves: rhbz#1165792 - automount segfaults in sss_nss_check_header

* Thu Nov 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-20
- Resolves: rhbz#1163742 - "debug_timestamps = false" and "debug_microseconds
                           = true" do not work after enabling journald
                           with sssd.

* Thu Nov 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-19
- Resolves: rhbz#1153593 - Manpage description of case_sensitive=preserving
                          is incomplete

* Thu Nov 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-18
- Support views for IPA users
- Related: rhbz#891984 - [RFE] ID Views: Support migration from the sync
                         solution to the trust solution

* Thu Nov 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-17
- Update man page to clarify TGs should be disabled with a custom search base
- Related: rhbz#1161741 - TokenGroups for LDAP provider breaks in corner cases

* Wed Nov 19 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-16
- Use upstreamed patches for the rootless sssd
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Wed Nov 19 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-15
- Resolves: rhbz#1153603 - Proxy Provider: Fails to lookup case sensitive
                           users and groups with case_sensitive=preserving

* Wed Nov 19 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-14
- Resolves: rhbz#1161741 - TokenGroups for LDAP provider breaks in corner cases

* Wed Nov 19 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-13
- Resolves: rhbz#1162480 - dereferencing failure against openldap server

* Wed Nov 12 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-12
- Move adding the user from pretrans to pre, copy adding the user to
  sssd-krb5-common and sssd-ipa as well in order to work around yum
  ordering issue
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Tue Nov 11 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-11
- Resolves: rhbz#1113783 - sssd should run under unprivileged user

* Fri Nov  7 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-10
- Fix two regressions in the new selinux_child process
- Related: rhbz#1113783 - sssd should run under unprivileged user
- Resolves: rhbz#1132365 - Remove password from the PAM stack if OTP is used

* Wed Nov  5 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-9
- Include the ldap_child and selinux_child patches for rootless sssd
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Wed Nov  5 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-8
- Support overriding SSH public keys with views
- Support extended attributes via the extop plugin
- Related: rhbz#1109756 - Rebase SSSD to 1.12
- Resolves: rhbz#1137010 - disable midpoint refresh for netgroups if ptask
                           refresh is enabled

* Thu Oct 30 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-7
- Resolves: rhbz#1153518 - service lookups returned in lowercase with
                           case_sensitive=preserving
- Resolves: rhbz#1158809 - Enumeration shows only a single group multiple
                           times

* Wed Oct 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-6
- Include the responder and packaging patches for rootless sssd
- Related: rhbz#1113783 - sssd should run under unprivileged user

* Wed Oct 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-5
- Amend the sssd-ldap man page with info about lockout setup
- Related: rhbz#1109756 - Rebase SSSD to 1.12
- Resolves: rhbz#1137014 - Shell fallback mechanism in SSSD 
- Resolves: rhbz#790854 - 4 functions with reference leaks within sssd (src/python/pyhbac.c) 

* Wed Oct 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-4
- Fix regressions caused by views patches when SSSD is connected to a
  pre-4.0 IPA server
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Wed Oct 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-3
- Add the low-level server changes for running as unprivileged user
- Package the libsss_semange library needed for SELinux label changes
- Related: rhbz#1113783 - sssd should run under unprivileged user 
- Resolves: rhbz#1113784 - sssd should audit selinux user map changes 

* Wed Oct 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-2
- Use libsemanage for SELinux label changes
- Resolves: rhbz#1113784 - sssd should audit selinux user map changes 

* Mon Oct 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.2-1
- Rebase SSSD to 1.12.2
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Thu Oct 09 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.1-2
- Sync with upstream
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Thu Sep 11 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.1-1
- Rebuild against ding-libs with fixed SONAME
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Tue Sep  9 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.1-1
- Rebase SSSD to 1.12.1
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Fri Sep 05 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.0-3
- Require ldb 2.1.17
- Related: rhbz#1133914 - Rebase libldb to version 1.1.17 or newer

* Fri Aug 08 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.0-2
- Fix fully qualified IFP lookups
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Thu Jul 24 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.12.0-1
- Rebase SSSD to 1.12.0
- Related: rhbz#1109756 - Rebase SSSD to 1.12

* Wed May 21 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-70
- Squash in upstream review comments about the PAC patch
- Related: rhbz#1097286 - Expanding home directory fails when the request
                          comes from the PAC responder

* Tue May 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-69
- Backport a patch to allow krb5-utils-test to run as root
- Related: rhbz#1097286 - Expanding home directory fails when the request
                          comes from the PAC responder

* Tue May 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-68
- Resolves: rhbz#1097286 - Expanding home directory fails when the request
                           comes from the PAC responder

* Tue May 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-67
- Fix a DEBUG message, backport two related fixes
- Related: rhbz#1090653 - segfault in sssd_be when second domain tree
                           users are queried while joined to child domain

* Tue May 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-66
- Resolves: rhbz#1090653 - segfault in sssd_be when second domain tree
                           users are queried while joined to child domain

* Wed Apr 02 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-65
- Resolves: rhbz#1082191 - RHEL7 IPA selinuxusermap hbac rule not always
                           matching

* Wed Apr 02 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-64
- Resolves: rhbz#1077328 - other subdomains are unavailable when joined
                           to a subdomain in the ad forest

* Wed Mar 26 2014 Sumit Bose <sbose@redhat.com> - 1.11.2-63
- Resolves: rhbz#1078877 - Valgrind: Invalid read of int while processing
                           netgroup

* Wed Mar 26 2014 Sumit Bose <sbose@redhat.com> - 1.11.2-62
- Resolves: rhbz#1075092 - Password change w/ OTP generates error on success

* Fri Mar 21 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-61
- Resolves: rhbz#1078840 -  Error during password change

* Thu Mar 13 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-60
- Resolves: rhbz#1075663 - SSSD should create the SELinux mapping file
                           with format expected by pam_selinux

* Wed Mar 12 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-59
- Related: rhbz#1075621 - Add another Kerberos error code to trigger IPA
                          password migration

* Tue Mar 11 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-58
- Related: rhbz#1073635 - IPA SELinux code looks for the host in the wrong
                          sysdb subdir when a trusted user logs in

* Tue Mar 11 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-57
- Related: rhbz#1066096 - not retrieving homedirs of AD users with
                          posix attributes

* Mon Mar 10 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-56
- Related: rhbz#1072995 -  AD group inconsistency when using AD provider
                           in sssd-1.11-40

* Mon Mar 10 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-55
- Resolves: rhbz#1073631 - sssd fails to handle expired passwords
                           when OTP is used

* Tue Mar 04 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-54
- Resolves: rhbz#1072067 - SSSD Does not cache SELinux map from FreeIPA
                           correctly

* Tue Mar 04 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-53
- Resolves: rhbz#1071903 - ipa-server-mode: Use lower-case user name
                           component in home dir path

* Tue Mar 04 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-52
- Resolves: rhbz#1068725 - Evaluate usage of sudo LDAP provider together
                           with the AD provider

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-51
- Fix idmap documentation
- Bump idmap version info
- Related: rhbz#1067361 - Check IPA idranges before saving them to the cache

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-50
- Pull some follow up man page fixes from upstream
- Related: rhbz#1060389 - Document that `sssd` cache needs to be cleared
                          manually, if ID mapping configuration changes
- Related: rhbz#1064908 - MAN: Remove misleading memberof example from
                          ldap_access_filter example

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-49
- Resolves: rhbz#1060389 - Document that `sssd` cache needs to be cleared
                           manually, if ID mapping configuration changes

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-48
- Resolves: rhbz#1064908 - MAN: Remove misleading memberof example from
                           ldap_access_filter example

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-47
- Resolves: rhbz#1068723 - Setting int option to 0 yields the default value

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-46
- Resolves: rhbz#1067361 - Check IPA idranges before saving them to the cache

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-45
- Resolves: rhbz#1067476 - SSSD pam module accepts usernames with leading
                           spaces

* Wed Feb 26 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-44
- Resolves: rhbz#1033069 - Configuring two different provider types might
                           start two parallel enumeration tasks

* Mon Feb 17 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-43
- Resolves: rhbz#1068640 - 'IPA: Don't call tevent_req_post outside _send'
                           should be added to RHEL7

* Mon Feb 17 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-42
- Resolves: rhbz#1063977 - SSSD needs to enable FAST by default

* Mon Feb 17 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-41
- Resolves: rhbz#1064582 - sss_cache does not reset the SYSDB_INITGR_EXPIRE
                           attribute when expiring users

* Wed Feb 12 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-40
- Resolves: rhbz#1033081 - Implement heuristics to detect if POSIX attributes
                           have been replicated to the Global Catalog or not

* Wed Feb 12 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-39
- Resolves: rhbz#872177 - [RFE] subdomain homedir template should be
                          configurable/use flatname by default

* Wed Feb 12 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-38
- Resolves: rhbz#1059753 - Warn with a user-friendly error message when
                           permissions on sssd.conf are incorrect

* Wed Jan 29 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-37
- Resolves: rhbz#1037653 - Enabling ldap_id_mapping doesn't exclude
                           uidNumber in filter

* Wed Jan 29 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-36
- Resolves: rhbz#1059253 - Man page states default_shell option supersedes
                           other shell options but in fact override_shell does.
- Use the right domain for AD site resolution
- Related: rhbz#743503 -  [RFE] sssd should support DNS sites

* Wed Jan 29 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-35
- Resolves: rhbz#1028039 - AD Enumeration reads data from LDAP while
                           regular lookups connect to GC

* Wed Jan 29 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-34
- Resolves: rhbz#877438 - sudoNotBefore/sudoNotAfter not supported by sssd
                          sudoers plugin

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 1.11.2-33
- Mass rebuild 2014-01-24

* Fri Jan 24 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-32
- Resolves: rhbz#1054639 - sssd_be aborts a request if it doesn't match
                           any configured idmap domain

* Fri Jan 24 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-31
- Resolves: rhbz#1054899 - explicitly suggest krb5_auth_timeout in a loud
                           DEBUG message in case Kerberos authentication
                           times out

* Wed Jan 22 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-30
- Resolves: rhbz#1037653 - Enabling ldap_id_mapping doesn't exclude
                           uidNumber in filter

* Mon Jan 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-29
- Resolves: rhbz#1051360 - [FJ7.0 Bug]: [REG] sssd_be crashes when
                           ldap_search_base cannot be parsed.
- Fix a typo in the man page
- Related: rhbz#1034920 - RHEL7 sssd not setting IPA AD trusted user homedir

* Mon Jan 20 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-28
- Resolves: rhbz#1054639 - sssd_be aborts a request if it doesn't match
                           any configured idmap domain
- Fix return value when searching for AD domain flat names
- Resolves: rhbz#1048102 - Access denied for users from gc domain when
                           using format DOMAIN\user

* Wed Jan 15 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-27
- Resolves: rhbz#1034920 - RHEL7 sssd not setting IPA AD trusted user homedir

* Wed Jan 15 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-26
- Resolves: rhbz#1048102 - Access denied for users from gc domain when
                           using format DOMAIN\user

* Wed Jan 15 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-25
- Resolves: rhbz#1053106 - sssd ad trusted sub domain do not inherit
                           fallbacks and overrides settings

* Thu Jan 09 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-24
- Resolves: rhbz#1051016 - FAST does not work in SSSD 1.11.2 in Fedora 20

* Thu Jan 09 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-23
- Resolves: rhbz#1033133 - "System Error" when invalid ad_access_filter
                            is used

* Thu Jan 09 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-22
- Resolves: rhbz#1032983 - sssd_be crashes when ad_access_filter uses
                           FOREST keyword.
- Fix two memory leaks in the PAC responder (Related: rhbz#991065)

* Wed Jan 08 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-21
- Resolves: rhbz#1048184 - Group lookup does not return member with multiple
                           names after user lookup

* Wed Jan 08 2014 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-20
- Resolves: rhbz#1049533 - Group membership lookup issue

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 1.11.2-19
- Mass rebuild 2013-12-27

* Thu Dec 19 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-18
- Resolves: rhbz#894068 - sss_cache doesn't support subdomains

* Thu Dec 19 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-17
- Re-initialize subdomains after provider startup
- Related: rhbz#1038637 - If SSSD starts offline, subdomains list is
                          never read

* Thu Dec 19 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-16
- The AD provider is able to resolve group memberships for groups with
  Global and Universal scope
- Related: rhbz#1033096 - tokenGroups do not work reliable with Global
                          Catalog

* Wed Dec 18 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-15
- Resolves: rhbz#1033096 - tokenGroups do not work reliable with Global
                           Catalog
- Resolves: rhbz#1030483 - Individual group search returned multiple
                           results in GC lookups

* Wed Dec 18 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-14
- Resolves: rhbz#1040969 - sssd_nss grows memory footprint when netgroups
                           are requested

* Thu Dec 12 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-13
- Resolves: rhbz#1023409 - Valgrind sssd "Syscall param
                           socketcall.sendto(msg) points to uninitialised
                           byte(s)"

* Thu Dec 12 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-12
- Resolves: rhbz#1037936 - sssd_be crashes occasionally

* Thu Dec 12 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-11
- Resolves: rhbz#1038637 - If SSSD starts offline, subdomains list is
                           never read

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-10
- Resolves: rhbz#1029631 - sssd_be crashes on manually adding a cleartext
                           password to ldap_default_authtok

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-9
- Resolves: rhbz#1036758 - SSSD: Allow for custom attributes in RDN when
                           using id_provider = proxy

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-8
- Resolves: rhbz#1034050 - Errors in domain log when saving user to sysdb

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-7
- Resolves: rhbz#1036157 - sssd can't retrieve auto.master when using the
                           "default_domain_suffix" option in

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-6
- Resolves: rhbz#1028057 - Improve detection of the right domain when
                           processing group with members from several domains

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-5
- Resolves: rhbz#1033084 - sssd_be segfaults if empty grop is resolved
                           using ad_matching_rule

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-4
- Resolves: rhbz#1031562 - Incorrect mention of access_filter in sssd-ad
                           manpage

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-3
- Resolves: rhbz#991549 - sssd fails to retrieve netgroups with multiple
                          CN attributes

* Mon Dec  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-2
- Skip netgroups that don't provide well-formed triplets
- Related: rhbz#991549 -  sssd fails to retrieve netgroups with multiple
                          CN attributes

* Wed Oct 30 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.2-1
- New upstream release 1.11.2
- Remove upstreamed patches
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.11.2
- Resolves: rhbz#991065

* Fri Sep 27 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.1-2
- Resolves: rhbz#1019882 - RHEL7 ipa ad trusted user lookups failed with
                           sssd_be crash
- Resolves: rhbz#1002597 - ad: unable to resolve membership when user is
                           from different domain than group

* Fri Sep 27 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.1-1
- New upstream release 1.11.1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.11.1
- Resolves: rhbz#991065 - Rebase SSSD to 1.11.0

* Thu Aug 29 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.0-1
- New upstream release 1.11.0
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.11.0
- Resolves: rhbz#991065

* Fri Aug 02 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.11.0.1beta2
- New upstream release 1.11 beta 2
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.11.0beta2
- Related: rhbz#991065

* Wed Jul 31 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.1-5
- Resolves: #906427 - Do not use %%{_lib} in specfile for the nss and
                      pam libraries

* Wed Jul 31 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.1-4
- Resolves: #983587 - sss_debuglevel did not increase verbosity in
                      sssd_pac.log

* Wed Jul 31 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.1-3
- Resolves: #983580 - Netgroups should ignore the 'use_fully_qualified_names'
                      setting

* Wed Jul 31 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.1-2
- Apply several important fixes from upstream 1.10 branch
- Related: #966757 - SSSD failover doesn't work if the first DNS server
                     in resolv.conf is unavailable

* Thu Jul 18 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.1-1
- New upstream release 1.10.1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.10.1

* Wed Jul 10 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-18
- Remove libcmocka dependency

* Mon Jul 08 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-17
- sssd-tools should require sssd-common, not sssd

* Tue Jul 02 2013 Stephen Gallagher <sgallagh@redhat.com> - 1.10.0-16
- Move sssd_pac to the sssd-ipa and sssd-ad subpackages
- Trim out RHEL5-specific macros since we don't build on RHEL 5
- Trim out macros for Fedora older than F18
- Update libldb requirement to 1.1.16
- Trim RPM changelog down to the last year

* Tue Jul 02 2013 Stephen Gallagher <sgallagh@redhat.com> - 1.10.0-15
- Move sssd_pac to the sssd-krb5 subpackage

* Mon Jul 01 2013 Stephen Gallagher <sgallagh@redhat.com> - 1.10.0-14
- Fix Obsoletes: to account for dist tag
- Convert post and pre scripts to run on the sssd-common subpackage
- Remove old conversion from SYSV

* Thu Jun 27 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-13
- New upstream release 1.10
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.10.0

* Mon Jun 17 2013 Dan Horák <dan[at]danny.cz> - 1.10.0-12.beta2
- the cmocka toolkit exists only on selected arches

* Sun Jun 16 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-11.beta2
- Apply a number of patches from upstream to fix issues found post-beta,
  in particular:
  -- segfault with a high DEBUG level
  -- Fix IPA password migration (upstream #1873)
  -- Fix fail over when retrying SRV resolution (upstream #1886)

* Thu Jun 13 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-10.beta2
- Only BuildRequire libcmocka on Fedora

* Thu Jun 13 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-9.beta2
- Fix typo in Requires that prevented an upgrade (#973916)
- Use a hardcoded version in Conflicts, not less-than-current

* Wed Jun 12 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-8.beta2
- New upstream release 1.10 beta2
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.10.0beta2
- BuildRequire libcmocka-devel in order to run all upstream tests during build
- BuildRequire libnl3 instead of libnl1
- No longer BuildRequire initscripts, we no longer use /sbin/service
- Remove explicit krb5-libs >= 1.10 requires; this platform doensn't carry any
  older krb5-libs version

* Thu Jun 06 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-7.beta1
- Enable hardened build for RHEL7

* Fri May 24 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-6.beta1
- Apply a couple of patches from upstream git that resolve crashes when
  ID mapping object was not initialized properly but needed later

* Tue May 14 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-5.beta1
- Resolves: rhbz#961357 - Missing dyndns_update entry in sssd.conf during
                          realm join
- Resolves: rhbz#961278 - Login failure: Enterprise Principal enabled by
                          default for AD Provider
- Resolves: rhbz#961251 - sssd does not create user's krb5 ccache dir/file
                          parent directory when logging in

* Tue May  7 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-4.beta1
- Explicitly Require libini_config >= 1.0.0.1 to work around a SONAME bug
  in ding-libs
- Fix SSH integration with fully-qualified domains
- Add the ability to dynamically discover the NetBIOS name

* Fri May  3 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-3.beta1
- New upstream release 1.10 beta1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.10.0beta1

* Wed Apr 17 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-2.alpha1
- Add a patch to fix krb5 ccache creation issue with krb5 1.11

* Tue Apr  2 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.10.0-1.alpha1
- New upstream release 1.10 alpha1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.10.0alpha1

* Fri Mar 01 2013 Stephen Gallagher <sgallagh@redhat.com> - 1.9.4-9
- Split internal helper libraries into a shared object
- Significantly reduce disk-space usage

* Thu Feb 14 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-8
- Fix the Kerberos password expiration warning (#912223)

* Thu Feb 14 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-7
- Do not write out dots in the domain-realm mapping file (#905650)

* Mon Feb 11 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-6
- Include upstream patch to build with krb5-1.11

* Thu Feb 07 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-5
- Rebuild against new libldb

* Mon Feb 04 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-4
- Fix build with new automake versions

* Wed Jan 30 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-3
- Recreate Kerberos ccache directory if it's missing
- Resolves: rhbz#853558 - [sssd[krb5_child[PID]]]: Credential cache
                          directory /run/user/UID/ccdir does not exist

* Tue Jan 29 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-2
- Fix changelog dates to make F19 rpmbuild happy

* Mon Jan 28 2013 Jakub Hrozek <jhrozek@redhat.com> - 1.9.4-1
- New upstream release 1.9.4

* Thu Dec 06 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.3-1
- New upstream release 1.9.3

* Tue Oct 30 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.2-5
- Resolve groups from AD correctly

* Tue Oct 30 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.2-4
- Check the validity of naming context

* Thu Oct 18 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.2-3
- Move the sss_cache tool to the main package

* Sun Oct 14 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.2-2
- Include the 1.9.2 tarball

* Sun Oct 14 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.2-1
- New upstream release 1.9.2

* Sun Oct 07 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.1-1
- New upstream release 1.9.1

* Wed Oct 03 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-24
- require the latest libldb

* Tue Sep 25 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-24
- Use mcpath insted of mcachepath macro to be consistent with
  upsteam spec file

* Tue Sep 25 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-23
- New upstream release 1.9.0

* Fri Sep 14 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-22.rc1
- New upstream release 1.9.0 rc1

* Thu Sep 06 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-21.beta7
- New upstream release 1.9.0 beta7
- obsoletes patches #1-#3

* Mon Sep 03 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-20.beta6
- Rebuild against libldb 1.12

* Tue Aug 28 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-19.beta6
- Rebuild against libldb 1.11

* Fri Aug 24 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-18.beta6
- Change the default ccache location to DIR:/run/user/${UID}/krb5cc
  and patch man page accordingly
- Resolves: rhbz#851304

* Mon Aug 20 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-17.beta6
- Rebuild against libldb 1.10

* Fri Aug 17 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-16.beta6
- Only create the SELinux login file if there are SELinux mappings on
  the IPA server

* Fri Aug 10 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-14.beta6
- Don't discard HBAC rule processing result if SELinux is on
  Resolves: rhbz#846792 (CVE-2012-3462)

* Thu Aug 02 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-13.beta6
- New upstream release 1.9.0 beta 6
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta6
- A new option, override_shell was added. If this option is set, all users
  managed by SSSD will have their shell set to its value.
- Fixes for the support for setting default SELinux user context from FreeIPA.
- Fixed a regression introduced in beta 5 that broke LDAP SASL binds
- The SSSD supports the concept of a Primary Server and a Back Up Server in
  failover
- A new command-line tool sss_seed is available to help prime the cache with
  a user record when deploying a new machine
- SSSD is now able to discover and save the domain-realm mappings
  between an IPA server and a trusted Active Directory server.
- Packaging changes to fix ldconfig usage in subpackages (#843995)
- Rebuild against libldb 1.1.9

* Fri Jul 27 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.9.0-13.beta5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Thu Jul 19 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-12.beta5
- New upstream release 1.9.0 beta 5
- Obsoletes the patch for missing DP_OPTION_TERMINATOR in AD provider options
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta5
- Many fixes for the support for setting default SELinux user context from
  FreeIPA, most notably fixed the specificity evaluation
- Fixed an incorrect default in the krb5_canonicalize option of the AD
  provider which was preventing password change operation
- The shadowLastChange attribute value is now correctly updated with the
  number of days since the Epoch, not seconds

* Mon Jul 16 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-11.beta4
- Fix broken ARM build
- Add missing DP_OPTION_TERMINATOR in AD provider options

* Wed Jul 11 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-10.beta4
- Own several directories create during make install (#839782)

* Wed Jul 11 2012 Jakub Hrozek <jhrozek@redhat.com> - 1.9.0-9.beta4
- New upstream release 1.9.0 beta 4
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta4
- Add a new AD provider to improve integration with Active Directory 2008 R2
  or later servers
- SUDO integration was completely rewritten. The new implementation works
  with multiple domains and uses an improved refresh mechanism to download
  only the necessary rules
- The IPA authentication provider now supports subdomains
- Fixed regression for setups that were setting default_tkt_enctypes
  manually by reverting a previous workaround.

* Mon Jun 25 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-8.beta3
- New upstream release 1.9.0 beta 3
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta3
- Add a new PAC responder for dealing with cross-realm Kerberos trusts
- Terminate idle connections to the NSS and PAM responders

* Wed Jun 20 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-7.beta2
- Switch unicode library from libunistring to Glib
- Drop unnecessary explicit Requires on keyutils
- Guarantee that versioned Requires include the correct architecture

* Mon Jun 18 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-6.beta2
- Fix accidental disabling of the DIR cache support

* Fri Jun 15 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-5.beta2
- New upstream release 1.9.0 beta 2
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta2
- Add support for the Kerberos DIR cache for storing multiple TGTs
  automatically
- Major performance enhancement when storing large groups in the cache
- Major performance enhancement when performing initgroups() against Active
  Directory
- SSSDConfig data file default locations can now be set during configure for
  easier packaging

* Tue May 29 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-4.beta1
- Fix regression in endianness patch

* Tue May 29 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-3.beta1
- Rebuild SSSD against ding-libs 0.3.0beta1
- Fix endianness bug in service map protocol

* Thu May 24 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-2.beta1
- Fix several regressions since 1.5.x
- Ensure that the RPM creates the /var/lib/sss/mc directory
- Add support for Netscape password warning expiration control
- Rebuild against libldb 1.1.6

* Fri May 11 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.9.0-1.beta1
- New upstream release 1.9.0 beta 1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.9.0beta1
- Add native support for autofs to the IPA provider
- Support for ID-mapping when connecting to Active Directory
- Support for handling very large (> 1500 users) groups in Active Directory
- Support for sub-domains (will be used for dealing with trust relationships)
- Add a new fast in-memory cache to speed up lookups of cached data on
  repeated requests

* Thu May 03 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.3-11
- New upstream release 1.8.3
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.8.3
- Numerous manpage and translation updates
- LDAP: Handle situations where the RootDSE isn't available anonymously
- LDAP: Fix regression for users using non-standard LDAP attributes for user
  information

* Mon Apr 09 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.2-10
- New upstream release 1.8.2
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.8.2
- Several fixes to case-insensitive domain functions
- Fix for GSSAPI binds when the keytab contains unrelated principals
- Fixed several segfaults
- Workarounds added for LDAP servers with unreadable RootDSE
- SSH knownhostproxy will no longer enter an infinite loop preventing login
- The provided SYSV init script now starts SSSD earlier at startup and stops
  it later during shutdown
- Assorted minor fixes for issues discovered by static analysis tools

* Mon Mar 26 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.1-9
- Don't duplicate libsss_autofs.so in two packages
- Set explicit package contents instead of globbing

* Wed Mar 21 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.1-8
- Fix uninitialized value bug causing crashes throughout the code
- Resolves: rhbz#804783 - [abrt] Segfault during LDAP 'services' lookup

* Mon Mar 12 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.1-7
- New upstream release 1.8.1
- Resolve issue where we could enter an infinite loop trying to connect to an
  auth server
- Fix serious issue with complex (3+ levels) nested groups
- Fix netgroup support for case-insensitivity and aliases
- Fix serious issue with lookup bundling resulting in requests never
  completing
- IPA provider will now check the value of nsAccountLock during pam_acct_mgmt
  in addition to pam_authenticate
- Fix several regressions in the proxy provider
- Resolves: rhbz#743133 - Performance regression with Kerberos authentication
                          against AD
- Resolves: rhbz#799031 - --debug option for sss_debuglevel doesn't work

* Tue Feb 28 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.0-6
- New upstream release 1.8.0
- Support for the service map in NSS
- Support for setting default SELinux user context from FreeIPA
- Support for retrieving SSH user and host keys from LDAP (Experimental)
- Support for caching autofs LDAP requests (Experimental)
- Support for caching SUDO rules (Experimental)
- Include the IPA AutoFS provider
- Fixed several memory-corruption bugs
- Fixed a regression in group enumeration since 1.7.0
- Fixed a regression in the proxy provider
- Resolves: rhbz#741981 - Separate Cache Timeouts for SSSD
- Resolves: rhbz#797968 - sssd_be: The requested tar get is not configured is
                          logged at each login
- Resolves: rhbz#754114 - [abrt] sssd-1.6.3-1.fc16: ping_check: Process
                          /usr/sbin/sssd was killed by signal 11 (SIGSEGV)
- Resolves: rhbz#743133 - Performance regression with Kerberos authentication
                          against AD
- Resolves: rhbz#773706 - SSSD fails during autodetection of search bases for
                          new LDAP features
- Resolves: rhbz#786957 - sssd and kerberos should change the default location for create the Credential Cashes to /run/usr/USERNAME/krb5cc

* Wed Feb 22 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.0-5.beta3
- Change default kerberos credential cache location to /run/user/<username>

* Wed Feb 15 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.0-4.beta3
- New upstream release 1.8.0 beta 3
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.8.0beta3
- Fixed a regression in group enumeration since 1.7.0
- Fixed several memory-corruption bugs
- Finalized the ABI for the autofs support
- Fixed a regression in the proxy provider

* Fri Feb 10 2012 Petr Pisar <ppisar@redhat.com> - 1.8.0-3.beta2
- Rebuild against PCRE 8.30

* Mon Feb 06 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.0-1.beta2
- New upstream release
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.8.0beta2
- Fix two minor manpage bugs
- Include the IPA AutoFS provider

* Mon Feb 06 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.8.0-1.beta1
- New upstream release
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.8.0beta1
- Support for the service map in NSS
- Support for setting default SELinux user context from FreeIPA
- Support for retrieving SSH user and host keys from LDAP (Experimental)
- Support for caching autofs LDAP requests (Experimental)
- Support for caching SUDO rules (Experimental)

* Wed Feb 01 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.7.0-5
- Resolves: rhbz#773706 - SSSD fails during autodetection of search bases for
                          new LDAP features - fix netgroups and sudo as well

* Wed Feb 01 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.7.0-4
- Fixes a serious memory hierarchy bug causing unpredictable behavior in the
  LDAP provider.

* Wed Feb 01 2012 Stephen Gallagher <sgallagh@redhat.com> - 1.7.0-3
- Resolves: rhbz#773706 - SSSD fails during autodetection of search bases for
                          new LDAP features

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Dec 22 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.7.0-1
- New upstream release 1.7.0
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.7.0
- Support for case-insensitive domains
- Support for multiple search bases in the LDAP provider
- Support for the native FreeIPA netgroup implementation
- Reliability improvements to the process monitor
- New DEBUG facility with more consistent log levels
- New tool to change debug log levels without restarting SSSD
- SSSD will now disconnect from LDAP server when idle
- FreeIPA HBAC rules can choose to ignore srchost options for significant
  performance gains
- Assorted performance improvements in the LDAP provider

* Mon Dec 19 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.4-1
- New upstream release 1.6.4
- Rolls up previous patches applied to the 1.6.3 tarball
- Fixes a rare issue causing crashes in the failover logic
- Fixes an issue where SSSD would return the wrong PAM error code for users
  that it does not recognize.

* Wed Dec 07 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.3-5
- Rebuild against libldb 1.1.4

* Tue Nov 29 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.3-4
- Resolves: rhbz#753639 - sssd_nss crashes when passed invalid UTF-8 for the
                          username in getpwnam()
- Resolves: rhbz#758425 - LDAP failover not working if server refuses
                          connections

* Thu Nov 24 2011 Jakub Hrozek <jhrozek@redhat.com> - 1.6.3-3
- Rebuild for libldb 1.1.3

* Thu Nov 10 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.3-2
- Resolves: rhbz#752495 - Crash when apply settings

* Fri Nov 04 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.3-1
- New upstream release 1.6.3
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.6.3
- Fixes a major cache performance issue introduced in 1.6.2
- Fixes a potential infinite-loop with certain LDAP layouts

* Wed Oct 26 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.6.2-5
- Rebuilt for glibc bug#747377

* Sun Oct 23 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.2-4
- Change selinux policy requirement to Conflicts: with the old version,
  rather than Requires: the supported version.

* Fri Oct 21 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.2-3
- Add explicit requirement on selinux-policy version to address new SBUS
  symlinks.

* Wed Oct 19 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.2-2
- Remove %%files reference to sss_debuglevel copied from wrong upstreeam
  spec file.

* Tue Oct 18 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.2-1
- Improved handling of users and groups with multi-valued name attributes
  (aliases)
- Performance enhancements
    Initgroups on RFC2307bis/FreeIPA
    HBAC rule processing
- Improved process-hang detection and restarting
- Enabled the midpoint cache refresh by default (fewer cache misses on
  commonly-used entries)
- Cleaned up the example configuration
- New tool to change debug level on the fly

* Mon Aug 29 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.1-1
- New upstream release 1.6.1
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.6.1
- Fixes a serious issue with LDAP connections when the communication is
  dropped (e.g. VPN disconnection, waking from sleep)
- SSSD is now less strict when dealing with users/groups with multiple names
  when a definitive primary name cannot be determined
- The LDAP provider will no longer attempt to canonicalize by default when
  using SASL. An option to re-enable this has been provided.
- Fixes for non-standard LDAP attribute names (e.g. those used by Active
  Directory)
- Three HBAC regressions have been fixed.
- Fix for an infinite loop in the deref code

* Wed Aug 03 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.0-2
- Build with _hardened_build macro

* Wed Aug 03 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.6.0-1
- New upstream release 1.6.0
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.6.0
- Add host access control support for LDAP (similar to pam_host_attr)
- Finer-grained control on principals used with Kerberos (such as for FAST or
- validation)
- Added a new tool sss_cache to allow selective expiring of cached entries
- Added support for LDAP DEREF and ASQ controls
- Added access control features for Novell Directory Server
- FreeIPA dynamic DNS update now checks first to see if an update is needed
- Complete rewrite of the HBAC library
- New libraries: libipa_hbac and libipa_hbac-python

* Tue Jul 05 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.11-2
- New upstream release 1.5.11
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.11
- Fix a serious regression that prevented SSSD from working with ldaps:// URIs
- IPA Provider: Fix a bug with dynamic DNS that resulted in the wrong IPv6
- address being saved to the AAAA record

* Fri Jul 01 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.10-1
- New upstream release 1.5.10
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.10
- Fixed a regression introduced in 1.5.9 that could result in blocking calls
- to LDAP

* Thu Jun 30 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.9-1
- New upstream release 1.5.9
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.9
- Support for overriding home directory, shell and primary GID locally
- Properly honor TTL values from SRV record lookups
- Support non-POSIX groups in nested group chains (for RFC2307bis LDAP
- servers)
- Properly escape IPv6 addresses in the failover code
- Do not crash if inotify fails (e.g. resource exhaustion)
- Don't add multiple TGT renewal callbacks (too many log messages)

* Fri May 27 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.8-1
- New upstream release 1.5.8
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.8
- Support for the LDAP paging control
- Support for multiple DNS servers for name resolution
- Fixes for several group membership bugs
- Fixes for rare crash bugs

* Mon May 23 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.7-3
- Resolves: rhbz#706740 - Orphaned links on rc0.d-rc6.d
- Make sure to properly convert to systemd if upgrading from newer
- updates for Fedora 14

* Mon May 02 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.7-2
- Fix segfault in TGT renewal

* Fri Apr 29 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.7-1
- Resolves: rhbz#700891 - CVE-2011-1758 sssd: automatic TGT renewal overwrites
-                         cached password with predicatable filename

* Wed Apr 20 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.6.1-1
- Re-add manpage translations

* Wed Apr 20 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.6-1
- New upstream release 1.5.6
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.6
- Fixed a serious memory leak in the memberOf plugin
- Fixed a regression with the negative cache that caused it to be essentially
- nonfunctional
- Fixed an issue where the user's full name would sometimes be removed from
- the cache
- Fixed an issue with password changes in the kerberos provider not working
- with kpasswd

* Wed Apr 20 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.5-5
- Resolves: rhbz#697057 - kpasswd fails when using sssd and
-                         kadmin server != kdc server
- Upgrades from SysV should now maintain enabled/disabled status

* Mon Apr 18 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.5-4
- Fix %%postun

* Thu Apr 14 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.5-3
- Fix systemd conversion. Upgrades from SysV to systemd weren't properly
- enabling the systemd service.
- Fix a serious memory leak in the memberOf plugin
- Fix an issue where the user's full name would sometimes be removed
- from the cache

* Tue Apr 12 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.5-2
- Install systemd unit file instead of sysv init script

* Tue Apr 12 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.5-1
- New upstream release 1.5.5
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.5
- Fixes for several crash bugs
- LDAP group lookups will no longer abort if there is a zero-length member
- attribute
- Add automatic fallback to 'cn' if the 'gecos' attribute does not exist

* Thu Mar 24 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.4-1
- New upstream release 1.5.4
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.4
- Fixes for Active Directory when not all users and groups have POSIX attributes
- Fixes for handling users and groups that have name aliases (aliases are ignored)
- Fix group memberships after initgroups in the IPA provider

* Thu Mar 17 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.3-2
- Resolves: rhbz#683267 - sssd 1.5.1-9 breaks AD authentication

* Fri Mar 11 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.3-1
- New upstream release 1.5.3
- Support for libldb >= 1.0.0

* Thu Mar 10 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.2-1
- New upstream release 1.5.2
- https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.2
- Fixes for support of FreeIPA v2
- Fixes for failover if DNS entries change
- Improved sss_obfuscate tool with better interactive mode
- Fix several crash bugs
- Don't attempt to use START_TLS over SSL. Some LDAP servers can't handle this
- Delete users from the local cache if initgroups calls return 'no such user'
- (previously only worked for getpwnam/getpwuid)
- Use new Transifex.net translations
- Better support for automatic TGT renewal (now survives restart)
- Netgroup fixes

* Sun Feb 27 2011 Simo Sorce <ssorce@redhat.com> - 1.5.1-9
- Rebuild sssd against libldb 1.0.2 so the memberof module loads again.
- Related: rhbz#677425

* Mon Feb 21 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-8
- Resolves: rhbz#677768 - name service caches names, so id command shows
-                         recently deleted users

* Fri Feb 11 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-7
- Ensure that SSSD builds against libldb-1.0.0 on F15 and later
- Remove .la for memberOf

* Fri Feb 11 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-6
- Fix memberOf install path

* Fri Feb 11 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-5
- Add support for libldb 1.0.0

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.5.1-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Feb 01 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-3
- Fix nested group member filter sanitization for RFC2307bis
- Put translated tool manpages into the sssd-tools subpackage

* Thu Jan 27 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-2
- Restore Requires: cyrus-sasl-gssapi as it is not auto-detected during
- rpmbuild

* Thu Jan 27 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.1-1
- New upstream release 1.5.1
- Addresses CVE-2010-4341 - DoS in sssd PAM responder can prevent logins
- Vast performance improvements when enumerate = true
- All PAM actions will now perform a forced initgroups lookup instead of just
- a user information lookup
-   This guarantees that all group information is available to other
-   providers, such as the simple provider.
- For backwards-compatibility, DNS lookups will also fall back to trying the
- SSSD domain name as a DNS discovery domain.
- Support for more password expiration policies in LDAP
-    389 Directory Server
-    FreeIPA
-    ActiveDirectory
- Support for ldap_tls_{cert,key,cipher_suite} config options
-Assorted bugfixes

* Tue Jan 11 2011 Stephen Gallagher <sgallagh@redhat.com> - 1.5.0-2
- CVE-2010-4341 - DoS in sssd PAM responder can prevent logins

* Wed Dec 22 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.5.0-1
- New upstream release 1.5.0
- Fixed issues with LDAP search filters that needed to be escaped
- Add Kerberos FAST support on platforms that support it
- Reduced verbosity of PAM_TEXT_INFO messages for cached credentials
- Added a Kerberos access provider to honor .k5login
- Addressed several thread-safety issues in the sss_client code
- Improved support for delayed online Kerberos auth
- Significantly reduced time between connecting to the network/VPN and
- acquiring a TGT
- Added feature for automatic Kerberos ticket renewal
- Provides the kerberos ticket for long-lived processes or cron jobs
- even when the user logs out
- Added several new features to the LDAP access provider
- Support for 'shadow' access control
- Support for authorizedService access control
- Ability to mix-and-match LDAP access control features
- Added an option for a separate password-change LDAP server for those
- platforms where LDAP referrals are not supported
- Added support for manpage translations


* Thu Nov 18 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.4.1-3
- Solve a shutdown race-condition that sometimes left processes running
- Resolves: rhbz#606887 - SSSD stops on upgrade

* Tue Nov 16 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.4.1-2
- Log startup errors to the syslog
- Allow cache cleanup to be disabled in sssd.conf

* Mon Nov 01 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.4.1-1
- New upstream release 1.4.1
- Add support for netgroups to the proxy provider
- Fixes a minor bug with UIDs/GIDs >= 2^31
- Fixes a segfault in the kerberos provider
- Fixes a segfault in the NSS responder if a data provider crashes
- Correctly use sdap_netgroup_search_base

* Mon Oct 18 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.4.0-2
- Fix incorrect tarball URL

* Mon Oct 18 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.4.0-1
- New upstream release 1.4.0
- Added support for netgroups to the LDAP provider
- Performance improvements made to group processing of RFC2307 LDAP servers
- Fixed nested group issues with RFC2307bis LDAP servers without a memberOf plugin
- Build-system improvements to support Gentoo
- Split out several libraries into the ding-libs tarball
- Manpage reviewed and updated

* Mon Oct 04 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-35
- Fix pre and post script requirements

* Mon Oct 04 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-34
- Resolves: rhbz#606887 - sssd stops on upgrade

* Fri Oct 01 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-33
- Resolves: rhbz#626205 - Unable to unlock screen

* Tue Sep 28 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-32
- Resolves: rhbz#637955 - libini_config-devel needs libcollection-devel but
-                         doesn't require it

* Thu Sep 16 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-31
- Resolves: rhbz#632615 - the krb5 locator plugin isn't packaged for multilib

* Tue Aug 24 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.3.0-30
- Resolves: CVE-2010-2940 - sssd allows null password entry to authenticate
-                           against LDAP

* Thu Jul 22 2010 David Malcolm <dmalcolm@redhat.com> - 1.2.91-21
- Rebuilt for https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild

* Fri Jul 09 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.2.91-20
- New upstream version 1.2.91 (1.3.0rc1)
- Improved LDAP failover
- Synchronous sysdb API (provides performance enhancements)
- Better online reconnection detection

* Mon Jun 21 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.2.1-15
- New stable upstream version 1.2.1
- Resolves: rhbz#595529 - spec file should eschew %%define in favor of
-                         %%global
- Resolves: rhbz#593644 - Empty list of simple_allow_users causes sssd service
-                         to fail while restart.
- Resolves: rhbz#599026 - Makefile typo causes SSSD not to use the kernel
-                         keyring
- Resolves: rhbz#599724 - sssd is broken on Rawhide

* Mon May 24 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.2.0-12
- New stable upstream version 1.2.0
- Support ServiceGroups for FreeIPA v2 HBAC rules
- Fix long-standing issue with auth_provider = proxy
- Better logging for TLS issues in LDAP

* Tue May 18 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.1.92-11
- New LDAP access provider allows for filtering user access by LDAP attribute
- Reduced default timeout for detecting offline status with LDAP
- GSSAPI ticket lifetime made configurable
- Better offline->online transition support in Kerberos

* Fri May 07 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.1.91-10
- Release new upstream version 1.1.91
- Enhancements when using SSSD with FreeIPA v2
- Support for deferred kinit
- Support for DNS SRV records for failover

* Fri Apr 02 2010 Simo Sorce <ssorce@redhat.com> - 1.1.1-3
- Bump up release number to avoid library sub-packages version issues with
  previous releases.

* Thu Apr 01 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.1.1-1
- New upstream release 1.1.1
- Fixed the IPA provider (which was segfaulting at start)
- Fixed a bug in the SSSDConfig API causing some options to revert to
- their defaults
- This impacted the Authconfig UI
- Ensure that SASL binds to LDAP auto-retry when interrupted by a signal

* Tue Mar 23 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.1.0-2
- Release SSSD 1.1.0 final
- Fix two potential segfaults
- Fix memory leak in monitor
- Better error message for unusable confdb

* Wed Mar 17 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.1.0-1.pre20100317git0ea7f19
- Release candidate for SSSD 1.1
- Add simple access provider
- Create subpackages for libcollection, libini_config, libdhash and librefarray
- Support IPv6
- Support LDAP referrals
- Fix cache issues
- Better feedback from PAM when offline

* Wed Feb 24 2010 Stephen Gallagehr <sgallagh@redhat.com> - 1.0.5-2
- Rebuild against new libtevent

* Fri Feb 19 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.0.5-1
- Fix licenses in sources and on RPMs

* Mon Jan 25 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.0.4-1
- Fix regression on 64-bit platforms

* Fri Jan 22 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.0.3-1
- Fixes link error on platforms that do not do implicit linking
- Fixes double-free segfault in PAM
- Fixes double-free error in async resolver
- Fixes support for TCP-based DNS lookups in async resolver
- Fixes memory alignment issues on ARM processors
- Manpage fixes

* Thu Jan 14 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.0.2-1
- Fixes a bug in the failover code that prevented the SSSD from detecting when it went back online
- Fixes a bug causing long (sometimes multiple-minute) waits for NSS requests
- Several segfault bugfixes

* Mon Jan 11 2010 Stephen Gallagher <sgallagh@redhat.com> - 1.0.1-1
- Fix CVE-2010-0014

* Mon Dec 21 2009 Stephen Gallagher <sgallagh@redhat.com> - 1.0.0-2
- Patch SSSDConfig API to address
- https://bugzilla.redhat.com/show_bug.cgi?id=549482

* Fri Dec 18 2009 Stephen Gallagher <sgallagh@redhat.com> - 1.0.0-1
- New upstream stable release 1.0.0

* Fri Dec 11 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.99.1-1
- New upstream bugfix release 0.99.1

* Mon Nov 30 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.99.0-1
- New upstream release 0.99.0

* Tue Oct 27 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.7.1-1
- Fix segfault in sssd_pam when cache_credentials was enabled
- Update the sample configuration
- Fix upgrade issues caused by data provider service removal

* Mon Oct 26 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.7.0-2
- Fix upgrade issues from old (pre-0.5.0) releases of SSSD

* Fri Oct 23 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.7.0-1
- New upstream release 0.7.0

* Thu Oct 15 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.6.1-2
- Fix missing file permissions for sssd-clients

* Tue Oct 13 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.6.1-1
- Add SSSDConfig API
- Update polish translation for 0.6.0
- Fix long timeout on ldap operation
- Make dp requests more robust

* Tue Sep 29 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.6.0-1
- Ensure that the configuration upgrade script always writes the config
  file with 0600 permissions
- Eliminate an infinite loop in group enumerations

* Mon Sep 28 2009 Sumit Bose <sbose@redhat.com> - 0.6.0-0
- New upstream release 0.6.0

* Mon Aug 24 2009 Simo Sorce <ssorce@redhat.com> - 0.5.0-0
- New upstream release 0.5.0

* Wed Jul 29 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.4.1-4
- Fix for CVE-2009-2410 - Native SSSD users with no password set could log in
  without a password. (Patch by Stephen Gallagher)

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Jun 22 2009 Simo Sorce <ssorce@redhat.com> - 0.4.1-2
- Fix a couple of segfaults that may happen on reload

* Thu Jun 11 2009 Simo Sorce <ssorce@redhat.com> - 0.4.1-1
- add missing configure check that broke stopping the daemon
- also fix default config to add a missing required option

* Mon Jun  8 2009 Simo Sorce <ssorce@redhat.com> - 0.4.1-0
- latest upstream release.
- also add a patch that fixes debugging output (potential segfault)

* Mon Apr 20 2009 Simo Sorce <ssorce@redhat.com> - 0.3.2-2
- release out of the official 0.3.2 tarball

* Mon Apr 20 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.3.2-1
- bugfix release 0.3.2
- includes previous release patches
- change permissions of the /etc/sssd/sssd.conf to 0600

* Tue Apr 14 2009 Simo Sorce <ssorce@redhat.com> - 0.3.1-2
- Add last minute bug fixes, found in testing the package

* Mon Apr 13 2009 Simo Sorce <ssorce@redhat.com> - 0.3.1-1
- Version 0.3.1
- includes previous release patches

* Mon Apr 13 2009 Simo Sorce <ssorce@redhat.com> - 0.3.0-2
- Try to fix build adding automake as an explicit BuildRequire
- Add also a couple of last minute patches from upstream

* Mon Apr 13 2009 Simo Sorce <ssorce@redhat.com> - 0.3.0-1
- Version 0.3.0
- Provides file based configuration and lots of improvements

* Tue Mar 10 2009 Simo Sorce <ssorce@redhat.com> - 0.2.1-1
- Version 0.2.1

* Tue Mar 10 2009 Simo Sorce <ssorce@redhat.com> - 0.2.0-1
- Version 0.2.0

* Sun Mar 08 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-5.20090309git691c9b3
- package git snapshot

* Fri Mar 06 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-4
- fixed items found during review
- added initscript

* Thu Mar 05 2009 Sumit Bose <sbose@redhat.com> - 0.1.0-3
- added sss_client

* Mon Feb 23 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-2
- Small cleanup and fixes in the spec file

* Thu Feb 12 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.1.0-1
- Initial release (based on version 0.1.0 upstream code)
