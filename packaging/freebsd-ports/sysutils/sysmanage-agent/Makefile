# Phase 11.8 stub.  ``DISTVERSION`` is sed-replaced from ``0.0.0`` to the
# release tag value by the ``freebsd-ports`` job in
# build-and-release.yml.  Do not hand-edit on release.

PORTNAME=	sysmanage-agent
DISTVERSION=	0.0.0
CATEGORIES=	sysutils python
# No MASTER_SITES / DISTFILES / DIST_SUBDIR here on purpose: USE_GITHUB below
# derives all three from GH_ACCOUNT/GH_PROJECT/GH_TAGNAME.  Setting both is
# redundant, portlint flags it, and the two can disagree about what is actually
# fetched.

MAINTAINER=	bryan@theeverlys.com
COMMENT=	Cross-platform system management agent for SysManage
WWW=		https://github.com/bceverly/sysmanage-agent

LICENSE=	AGPLv3+
LICENSE_FILE=	${WRKSRC}/LICENSE

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}websockets>0:devel/py-websockets@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}pyyaml>0:devel/py-pyyaml@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}aiohttp>0:www/py-aiohttp@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}cryptography>0:security/py-cryptography@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}psutil>0:sysutils/py-psutil@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}bcrypt>0:security/py-bcrypt@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}aiofiles>0:devel/py-aiofiles@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}sqlalchemy20>0:databases/py-sqlalchemy20@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}alembic>0:databases/py-alembic@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}defusedxml>0:devel/py-defusedxml@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}netifaces>0:net/py-netifaces@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}packaging>0:devel/py-packaging@${PY_FLAVOR} \
		sudo:security/sudo

# python:...,run — NO_BUILD means python is only needed at RUN time.
# Deliberately NO ``USE_PYTHON=autoplist``: autoplist generates the packing
# list for setuptools-installed modules, and this port has no setup.py at all —
# it stages a source tree by hand below.  The two mechanisms together produce
# an empty or wrong plist.
USES=		python:3.9+,run shebangfix
USE_GITHUB=	yes
GH_ACCOUNT=	bceverly
GH_PROJECT=	sysmanage-agent
GH_TAGNAME=	v${DISTVERSION}

# The agent runs unprivileged and escalates through the sudoers policy
# installed below.  Its account is DISTINCT from the sysmanage server port's
# ``sysmanage`` account on purpose: that one runs a network-facing web
# application, and the policy here is root-equivalent (it grants install(1),
# chmod(1), chown(8), sed(1) and sysrc(8) with unrestricted arguments).  Giving
# both services one account would mean a web-application compromise yields
# root, so the two ports must not share a user.
#
# 255 was free in ports/UIDs and ports/GIDs alongside the server's 253 as of
# 2026-08-10; portmgr may reassign either, which is routine.
USERS=		sysmanage-agent
GROUPS=		sysmanage-agent

USE_RC_SUBR=	sysmanage-agent

# pkg-message documents the optional unprivileged deployment.  It needs
# substitution (%%PREFIX%%, %%EXAMPLESDIR%%), which SUB_FILES performs from
# SUB_LIST; both of those are default SUB_LIST members.
SUB_FILES=	pkg-message

# PYTHON_CMD is NOT in the default SUB_LIST — USES=python contributes
# PYTHON_VERSION, PYTHON_VER, PYTHON_SUFFIX and friends, but not the
# interpreter path.  Without this line USE_RC_SUBR leaves the literal
# string %%PYTHON_CMD%% in the installed rc.d script, and the service
# fails at exec with no useful message.  Nothing catches it: the port
# builds, packages, passes check-plist and stage-qa, and installs — the
# placeholder only bites when the service is STARTED.  Found 2026-08-10
# via `sh -x` on the installed rc script.
SUB_LIST+=	PYTHON_CMD=${PYTHON_CMD}

NO_ARCH=	yes
NO_BUILD=	yes

SHEBANG_FILES=	main.py

PLIST_SUB+=	PORTNAME=${PORTNAME} VERSION=${DISTVERSION}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}
	${INSTALL_SCRIPT} ${WRKSRC}/main.py ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}/
	${INSTALL_DATA} ${WRKSRC}/alembic.ini ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}/
	cd ${WRKSRC} && ${COPYTREE_SHARE} src ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}
	${MKDIR} ${STAGEDIR}${PREFIX}/etc
	${INSTALL_DATA} ${WRKSRC}/sysmanage-agent-system.yaml \
		${STAGEDIR}${PREFIX}/etc/sysmanage-agent.yaml.sample
# The sudoers policy for the OPTIONAL non-root deployment.  Installed to
# EXAMPLESDIR, deliberately NOT to ${PREFIX}/etc/sudoers.d and deliberately NOT
# as @sample: pkg materialises @sample files at install time, which would make
# a plain ``pkg install`` silently grant a service account root-equivalent
# privileges.  Nothing here takes effect until an admin copies it, which is the
# only honest default — see pkg-message.
# The sudoers policy for the unprivileged deployment.  Mode and ownership come
# from the @(root,wheel,0440) line in pkg-plist: sudo REFUSES to read a policy
# file writable by anyone but its owner, and a refused file invalidates the
# whole @includedir, so the agent would lose every grant at once.
#
# NOTE: pkg-plist has NO comment syntax — every line there is an entry, so this
# rationale lives here.  Six explanatory lines in pkg-plist were turned into
# six bogus file paths by check-plist and pkg-create on 2026-08-10.
#
# The ${SED} rewrites the account name for releases up to and including
# 3.5.1.9, whose shipped policy grants the bare ``sysmanage`` account — the
# same account the sysmanage SERVER port creates for its web application.  On a
# host running both ports that would hand a network-facing service
# root-equivalent sudo, which is the exact outcome this deployment exists to
# avoid.  The expression anchors on "sysmanage " WITH the trailing space, so it
# is a no-op against a corrected policy and needs no removal later.
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/sudoers.d
	${SED} -e 's|^sysmanage ALL=|sysmanage-agent ALL=|' \
		${WRKSRC}/installer/freebsd/sysmanage-agent.sudoers \
		> ${STAGEDIR}${PREFIX}/etc/sudoers.d/sysmanage-agent
# Writable state.  get_database_path_from_config() falls back to
# ``os.getcwd()/agent.db`` and daemon(8) -c makes the cwd /, so an unprivileged
# agent cannot create its SQLite database at all — and a root one silently
# writes /agent.db.  The rc script points SYSMANAGE_DB_PATH and
# SYSMANAGE_LOG_DIR at these directories.
	${MKDIR} ${STAGEDIR}/var/db/${PORTNAME} ${STAGEDIR}/var/log/${PORTNAME}

# ``src`` is ~290 files that change every release, so they cannot be enumerated
# by hand in pkg-plist — an unlisted staged file fails stage-qa, which is what
# the hand-written 3-line plist would have done on the first real build.
# Appending the staged tree to ${TMPPLIST} is the in-tree idiom for a generated
# file set.  pkg-plist keeps the fixed entries (main.py, alembic.ini, @sample).
post-install:
	@${FIND} -s ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}/src -type f \
		| ${SED} -e 's,^${STAGEDIR}${PREFIX}/,,' >> ${TMPPLIST}

.include <bsd.port.mk>
