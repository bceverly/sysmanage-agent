# Created by: Bryan Everly <bryan@theeverlys.com>
# $FreeBSD$
#
# Phase 11.8 stub.  ``DISTVERSION`` is sed-replaced from ``0.0.0`` to the
# release tag value by the ``freebsd-ports`` job in
# build-and-release.yml.  Do not hand-edit on release.

PORTNAME=	sysmanage-agent
DISTVERSION=	0.0.0
CATEGORIES=	sysutils python
MASTER_SITES=	https://github.com/bceverly/sysmanage-agent/archive/refs/tags/
DISTFILES=	v${DISTVERSION}${EXTRACT_SUFX}
DIST_SUBDIR=	sysmanage-agent

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

USES=		python:3.9+ shebangfix
USE_PYTHON=	autoplist
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

.include <bsd.port.mk>
