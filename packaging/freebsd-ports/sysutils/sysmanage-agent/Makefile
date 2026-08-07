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

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}websockets>=15.0.1:www/py-websockets@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}yaml>0:devel/py-yaml@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}aiohttp>=3.13.5:www/py-aiohttp@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}cryptography>=48.0.0:security/py-cryptography@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}psutil>0:sysutils/py-psutil@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}bcrypt>=4.0.0:security/py-bcrypt@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}aiofiles>0:devel/py-aiofiles@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}sqlalchemy20>=2.0.43:databases/py-sqlalchemy20@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}alembic>=1.16.5:databases/py-alembic@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}defusedxml>0:devel/py-defusedxml@${PY_FLAVOR}

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

USE_RC_SUBR=	sysmanage-agent

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

# ``src`` is ~290 files that change every release, so they cannot be enumerated
# by hand in pkg-plist — an unlisted staged file fails stage-qa, which is what
# the hand-written 3-line plist would have done on the first real build.
# Appending the staged tree to ${TMPPLIST} is the in-tree idiom for a generated
# file set.  pkg-plist keeps the fixed entries (main.py, alembic.ini, @sample).
post-install:
	@${FIND} -s ${STAGEDIR}${PREFIX}/libexec/${PORTNAME}/src -type f \
		| ${SED} -e 's,^${STAGEDIR}${PREFIX}/,,' >> ${TMPPLIST}

.include <bsd.port.mk>
